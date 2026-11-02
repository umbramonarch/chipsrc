use crate::error::{ChipsrcError, Result};
use crate::model::{
    ArchLayer, BundleIndexes, CacheManifest, CacheShardEntry, ConvertConfig, ExtractedType,
    FileScope, GraphStateFile, GraphSymbolRef, IncrementalAstCache, RankedSymbol, RepoMetadata,
    SanityReport, SectionShard, SymbolGraphState, SymbolKind, TypeKind, VendorMode, Visibility,
    CACHE_SCHEMA_VERSION, GRAPH_STATE_FILE,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Advisory lock staleness threshold (`10 s`). Locks older than this are reclaimed automatically.
pub const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);

/// Maximum lock wait budget for background callers (`auto_refresh_bundles`, `hook post-edit`).
pub const LOCK_WAIT_AUTO_SYNC: Duration = Duration::from_millis(150);

/// Maximum lock wait budget for explicit CLI commands (`convert`, `ensure`).
pub const LOCK_WAIT_EXPLICIT: Duration = Duration::from_secs(5);

/// Stale temporary file threshold (`60 s`). Pruners delete `*.tmp` files older than this.
const STALE_TMP_MAX_AGE: Duration = Duration::from_secs(60);

static NEXT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Advisory exclusive bundle lock on `<out>/cache/.lock`. Removes the lock file on `Drop`.
#[derive(Debug)]
pub struct BundleLock {
    path: PathBuf,
}

impl BundleLock {
    /// Attempts to acquire an exclusive advisory lock at `<out_dir>/cache/.lock`, waiting up to
    /// `wait` if another live process holds the lock.
    ///
    /// - Writes `<pid>:<unix_ms>\n` using `File::options().write(true).create_new(true)`.
    /// - Reclaims stale locks (`> 10 s` old by mtime or timestamp) immediately.
    /// - Tolerates arbitrary/garbage lock contents by falling back to file mtime.
    /// - Returns `Ok(None)` if the lock is still held after `wait`.
    pub fn acquire(out_dir: &Path, wait: Duration) -> Result<Option<Self>> {
        let cache_dir = out_dir.join("cache");
        fs::create_dir_all(&cache_dir).map_err(|source| ChipsrcError::io(&cache_dir, source))?;
        let lock_path = cache_dir.join(".lock");
        let start = Instant::now();

        loop {
            match fs::File::options()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    let payload = format!("{}:{now_ms}\n", std::process::id());
                    let _ = std::io::Write::write_all(&mut file, payload.as_bytes());
                    return Ok(Some(Self { path: lock_path }));
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::AlreadyExists
                        || err.kind() == std::io::ErrorKind::PermissionDenied
                        || matches!(err.raw_os_error(), Some(5 | 32 | 80 | 183)) =>
                {
                    let stale = fs::metadata(&lock_path).is_ok_and(|meta| {
                        let old_mtime = meta.modified().is_ok_and(|modified| {
                            SystemTime::now()
                                .duration_since(modified)
                                .is_ok_and(|age| age > LOCK_STALE_AFTER)
                        });
                        if old_mtime {
                            return true;
                        }
                        if meta.len() <= 128 {
                            if let Ok(bytes) = fs::read(&lock_path) {
                                if let Ok(text) = std::str::from_utf8(&bytes) {
                                    if let Some((_, ts_str)) = text.trim().split_once(':') {
                                        if let Ok(lock_ms) = ts_str.trim().parse::<u128>() {
                                            if lock_ms >= 1_000_000_000_000 {
                                                let now_ms = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .map(|d| d.as_millis())
                                                    .unwrap_or(0);
                                                return now_ms.saturating_sub(lock_ms)
                                                    > LOCK_STALE_AFTER.as_millis();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        false
                    });
                    if stale {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    let elapsed = start.elapsed();
                    if elapsed >= wait {
                        return Ok(None);
                    }
                    let remaining = wait.saturating_sub(elapsed);
                    std::thread::sleep(remaining.min(Duration::from_millis(15)));
                }
                Err(err) => return Err(ChipsrcError::io(&lock_path, err)),
            }
        }
    }
}

/// Acquires an exclusive advisory bundle lock on `<out_dir>/cache/.lock`, waiting up to `wait`.
pub fn acquire_bundle_lock(out_dir: &Path, wait: Duration) -> Result<Option<BundleLock>> {
    BundleLock::acquire(out_dir, wait)
}

impl Drop for BundleLock {
    fn drop(&mut self) {
        for attempt in 0..4 {
            if fs::remove_file(&self.path).is_ok() || !self.path.exists() {
                return;
            }
            if attempt < 3 {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

/// Returns `true` when `output_root` resides inside `repo_path`.
pub fn is_output_inside_repo(repo_path: &Path, output_root: &Path) -> bool {
    let canon_repo = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    let canon_out = output_root
        .canonicalize()
        .unwrap_or_else(|_| output_root.to_path_buf());

    let Ok(rel_out) = canon_out.strip_prefix(&canon_repo) else {
        return false;
    };
    let Some(first_comp) = rel_out
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
    else {
        return false;
    };
    !first_comp.is_empty() && first_comp != "." && first_comp != ".."
}

/// Writes `bytes` to `path` atomically:
/// 1. Skips the write when `path` already exists with identical bytes.
/// 2. Writes a sibling `.tmp` file (`<dir>/.<name>.<pid>.<seq>.tmp`).
/// 3. Atomically renames the temp file over `path` with up to 5 attempts (`5/10/20/40 ms` backoff
///    on Windows `PermissionDenied` or sharing violations).
/// 4. Removes the `.tmp` file on failure before returning the error.
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_file() && meta.len() == bytes.len() as u64 {
            if let Ok(existing) = fs::read(path) {
                if existing == bytes {
                    return Ok(());
                }
            }
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bundle");
    let pid = std::process::id();
    let seq = NEXT_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{file_name}.{pid}.{seq}.tmp"));

    if let Err(source) = fs::write(&tmp_path, bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ChipsrcError::io(path, source));
    }

    const BACKOFF_MS: [u64; 4] = [5, 10, 20, 40];
    let mut last_err = None;
    for attempt in 0..5 {
        match fs::rename(&tmp_path, path) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let retryable = !path.is_dir()
                    && (err.kind() == std::io::ErrorKind::PermissionDenied
                        || matches!(err.raw_os_error(), Some(5 | 32 | 33)));
                last_err = Some(err);
                if let (true, Some(&delay_ms)) = (retryable, BACKOFF_MS.get(attempt)) {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                } else {
                    break;
                }
            }
        }
    }

    let _ = fs::remove_file(&tmp_path);
    Err(ChipsrcError::io(
        path,
        last_err.unwrap_or_else(|| std::io::Error::other("atomic rename failed")),
    ))
}

fn is_stale_tmp_file(path: &Path) -> bool {
    if path.extension().and_then(|s| s.to_str()) != Some("tmp") {
        return false;
    }
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    meta.modified().is_ok_and(|modified| {
        SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age > STALE_TMP_MAX_AGE)
    })
}

/// Deletes stale `*.tmp` files (older than 60 s) inside `dir`.
pub fn prune_stale_tmp_files_in_dir(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if is_stale_tmp_file(&p) {
            let _ = fs::remove_file(p);
        }
    }
}

/// Returns `true` when `value` contains no control characters, no non-space whitespace,
/// no leading or trailing spaces, and no consecutive spaces, allowing `sanitize_tsv` to
/// return `Cow::Borrowed(value)` without allocating.
#[inline]
fn is_clean_tsv_str(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return true;
    }
    if bytes[0] <= b' ' || bytes[bytes.len() - 1] <= b' ' {
        return false;
    }
    let mut prev_space = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b' ' {
            if prev_space {
                return false;
            }
            prev_space = true;
            i += 1;
        } else if b > b' ' && b < 0x7F {
            prev_space = false;
            i += 1;
        } else if b < b' ' || b == 0x7F {
            return false;
        } else {
            for c in value[i..].chars() {
                if c == ' ' {
                    if prev_space {
                        return false;
                    }
                    prev_space = true;
                } else if c.is_control() || c.is_whitespace() {
                    return false;
                } else {
                    prev_space = false;
                }
            }
            return !prev_space;
        }
    }
    true
}

#[inline]
fn push_usize(buf: &mut String, mut n: usize) {
    if n == 0 {
        buf.push('0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut i = 20;
    while n > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    if let Ok(s) = std::str::from_utf8(&digits[i..]) {
        buf.push_str(s);
    }
}

/// Sanitizes a string for TSV emission by replacing tabs, newlines, and control characters
/// with spaces and collapsing consecutive whitespace into a single space.
///
/// Uses a zero-allocation byte-scan fast path (`Cow::Borrowed`) when the input is already
/// clean, and a single-pass `String::with_capacity` builder otherwise.
pub fn sanitize_tsv(value: &str) -> Cow<'_, str> {
    if is_clean_tsv_str(value) {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for c in value.chars() {
        if c == '\t' || c == '\r' || c == '\n' || c.is_control() || c.is_whitespace() {
            if !out.is_empty() {
                pending_space = true;
            }
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Ensures `.claudeignore` in `repo_path` contains the bundle output directory ONLY when
/// `output_root` resides inside `repo_path`, preventing out-of-tree conversions from mutating
/// external directories.
pub fn ensure_claudeignore_entry(repo_path: &Path, output_root: &Path) -> Result<bool> {
    let canon_repo = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    let canon_out = output_root
        .canonicalize()
        .unwrap_or_else(|_| output_root.to_path_buf());

    let Ok(rel_out) = canon_out.strip_prefix(&canon_repo) else {
        // Output directory is outside the repository tree; never mutate `.claudeignore`.
        return Ok(false);
    };
    let Some(first_comp) = rel_out
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
    else {
        return Ok(false);
    };
    if first_comp.is_empty() || first_comp == "." || first_comp == ".." {
        return Ok(false);
    }

    let dir_name = first_comp;
    let entry = format!("{dir_name}/");
    let claudeignore_path = canon_repo.join(".claudeignore");

    let existing = fs::read_to_string(&claudeignore_path).unwrap_or_default();
    if existing
        .lines()
        .any(|l| l.trim() == entry || l.trim() == dir_name)
    {
        return Ok(false);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("# chipsrc generated bundles (prevents prompt cache invalidation)\n");
    updated.push_str(&entry);
    updated.push('\n');
    write_file(&claudeignore_path, &updated)?;
    Ok(true)
}

/// Emits the Hierarchical Agent Codebase Bundle (`INDEX.md`, `sections/*.md`,
/// `index/*.tsv`, `cache/manifest.json` + `cache/<shard>.json`, optional `<repo_name>.md`,
/// and `.claudeignore`). `meta.json` is written once by `convert_repo` after final timings
/// are recorded.
pub fn emit_bundle(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    sanity: &SanityReport,
    sections: &[SectionShard],
    indexes: &BundleIndexes,
    cache: &IncrementalAstCache,
) -> Result<bool> {
    let output_dir = &config.output_dir;
    let sections_dir = output_dir.join("sections");
    let index_dir = output_dir.join("index");

    create_dir(output_dir)?;
    create_dir(&sections_dir)?;
    create_dir(&index_dir)?;

    // Clean stale .md files in output_dir/sections/ that are no longer part of `sections`,
    // and prune any stale *.tmp files (>60s) across bundle directories.
    prune_stale_tmp_files_in_dir(output_dir);
    let expected_md: FxHashSet<&str> = sections
        .iter()
        .map(|s| {
            s.summary
                .md_file
                .strip_prefix("sections/")
                .unwrap_or(s.summary.md_file.as_str())
        })
        .collect();
    if let Ok(entries) = fs::read_dir(&sections_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|s| s.to_str());
            if ext == Some("md") {
                let keep = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| expected_md.contains(name));
                if !keep {
                    let _ = fs::remove_file(p);
                }
            } else if ext == Some("tmp") && is_stale_tmp_file(&p) {
                let _ = fs::remove_file(p);
            }
        }
    }

    // 1. Format INDEX.md and all 6 index/*.tsv buffers in parallel in memory, then write
    //    changed artifacts sequentially to avoid Windows NTFS / filter-driver contention.
    let build_index_md =
        || -> String { build_master_index_markdown(metadata, sanity, sections, indexes) };

    let build_small_and_sym_tsvs = || -> (String, String, String, String) {
        // index/sections.tsv
        let mut sec_tsv = String::with_capacity(128 + indexes.sections.len() * 128);
        sec_tsv.push_str(
            "section_id\ttitle\tmodule_path\tarch_layer\tscope\tfile_count\tsymbol_count\ttype_count\tmacro_count\ttoken_estimate\tmd_file\n",
        );
        for s in &indexes.sections {
            let _ = writeln!(
                sec_tsv,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                sanitize_tsv(&s.section_id),
                sanitize_tsv(&s.title),
                sanitize_tsv(&s.module_path),
                sanitize_tsv(&s.arch_layer),
                sanitize_tsv(&s.scope),
                s.file_count,
                s.symbol_count,
                s.type_count,
                s.macro_count,
                s.token_estimate,
                sanitize_tsv(&s.md_file),
            );
        }

        // index/symbols.tsv
        let mut sym_tsv = String::with_capacity(180 + indexes.symbols.len() * 160);
        sym_tsv.push_str(
            "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\tdoc_summary\thub_score\tauthority_score\n",
        );
        for rs in &indexes.symbols {
            let s = &rs.symbol;
            let _ = writeln!(
                sym_tsv,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.6}\t{:.6}",
                sanitize_tsv(&s.symbol_id),
                sanitize_tsv(&s.name),
                s.kind.as_str(),
                s.visibility.as_str(),
                sanitize_tsv(&s.file),
                s.start_line,
                s.end_line,
                sanitize_tsv(&s.signature),
                rs.pagerank,
                rs.in_degree,
                rs.out_degree,
                s.arch_layer.as_str(),
                s.scope.as_str(),
                sanitize_tsv(&s.section_id),
                sanitize_tsv(&s.doc_summary),
                rs.hub_score,
                rs.authority_score,
            );
        }

        // index/types.tsv
        let mut typ_tsv = String::with_capacity(140 + indexes.types.len() * 160);
        typ_tsv.push_str(
            "type_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tfields_summary\tarch_layer\tscope\tsection_id\tdoc_summary\n",
        );
        for t in &indexes.types {
            let _ = writeln!(
                typ_tsv,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                sanitize_tsv(&t.type_id),
                sanitize_tsv(&t.name),
                t.kind.as_str(),
                t.visibility.as_str(),
                sanitize_tsv(&t.file),
                t.start_line,
                t.end_line,
                sanitize_tsv(&t.fields_summary),
                t.arch_layer.as_str(),
                t.scope.as_str(),
                sanitize_tsv(&t.section_id),
                sanitize_tsv(&t.doc_summary),
            );
        }

        // index/macros.tsv
        let mut mac_tsv = String::with_capacity(128 + indexes.macros.len() * 128);
        mac_tsv.push_str(
            "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription\n",
        );
        for m in &indexes.macros {
            let _ = writeln!(
                mac_tsv,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                sanitize_tsv(&m.name),
                m.kind.as_str(),
                sanitize_tsv(&m.value_or_args),
                sanitize_tsv(m.hex_addr.as_deref().unwrap_or("-")),
                sanitize_tsv(&m.file),
                m.line,
                m.arch_layer.as_str(),
                m.scope.as_str(),
                sanitize_tsv(&m.section_id),
                sanitize_tsv(&m.description),
            );
        }
        (sec_tsv, sym_tsv, typ_tsv, mac_tsv)
    };

    let build_calls_tsv = || -> String {
        let mut calls_tsv = String::with_capacity(96 + indexes.calls.len() * 96);
        calls_tsv.push_str(
            "caller_id\tcaller_name\tcallee_name\tcallee_id\tfile\tline\ttier\tsection_id\n",
        );
        for c in &indexes.calls {
            calls_tsv.push_str(&sanitize_tsv(&c.caller_id));
            calls_tsv.push('\t');
            calls_tsv.push_str(&sanitize_tsv(&c.caller_name));
            calls_tsv.push('\t');
            calls_tsv.push_str(&sanitize_tsv(&c.callee_name));
            calls_tsv.push('\t');
            calls_tsv.push_str(&sanitize_tsv(&c.callee_id));
            calls_tsv.push('\t');
            calls_tsv.push_str(&sanitize_tsv(&c.file));
            calls_tsv.push('\t');
            push_usize(&mut calls_tsv, c.line);
            calls_tsv.push('\t');
            calls_tsv.push_str(c.tier.as_str());
            calls_tsv.push('\t');
            calls_tsv.push_str(&sanitize_tsv(&c.section_id));
            calls_tsv.push('\n');
        }
        calls_tsv
    };

    let build_xref_tsv = || -> String {
        let mut xref_tsv = String::with_capacity(96 + indexes.xrefs.len() * 110);
        xref_tsv.push_str("symbol\tcategory\trelation\ttarget\tfile\tline\tsection_id\tcontext\n");
        for x in &indexes.xrefs {
            xref_tsv.push_str(&sanitize_tsv(&x.symbol));
            xref_tsv.push('\t');
            xref_tsv.push_str(&sanitize_tsv(&x.category));
            xref_tsv.push('\t');
            xref_tsv.push_str(&sanitize_tsv(&x.relation));
            xref_tsv.push('\t');
            xref_tsv.push_str(&sanitize_tsv(&x.target));
            xref_tsv.push('\t');
            xref_tsv.push_str(&sanitize_tsv(&x.file));
            xref_tsv.push('\t');
            push_usize(&mut xref_tsv, x.line);
            xref_tsv.push('\t');
            xref_tsv.push_str(&sanitize_tsv(&x.section_id));
            xref_tsv.push('\t');
            xref_tsv.push_str(&sanitize_tsv(&x.context));
            xref_tsv.push('\n');
        }
        xref_tsv
    };

    let ((index_md, (sec_tsv, sym_tsv, typ_tsv, mac_tsv)), (calls_tsv, xref_tsv)) = rayon::join(
        || rayon::join(build_index_md, build_small_and_sym_tsvs),
        || rayon::join(build_calls_tsv, build_xref_tsv),
    );

    let write_md_and_sections = || -> Result<()> {
        write_file(&output_dir.join("INDEX.md"), &index_md)?;
        let sync_sections = config.force && (50..=1000).contains(&cache.files.len());
        if sync_sections {
            for shard in sections {
                let rel_md = shard
                    .summary
                    .md_file
                    .strip_prefix("sections/")
                    .unwrap_or(&shard.summary.md_file);
                let sec_path = sections_dir.join(rel_md);
                let tmp_path =
                    sections_dir.join(format!(".{rel_md}.{}.sync.tmp", std::process::id()));
                let _ = fs::write(&tmp_path, shard.markdown_body.as_bytes());
                if let Ok(file) = fs::File::options().write(true).open(&tmp_path) {
                    let _ = fs::File::sync_data(&file);
                }
                let _ = fs::remove_file(&tmp_path);
                write_file(&sec_path, &shard.markdown_body)?;
            }
        } else {
            let mid = sections.len() / 2;
            let (left, right) = sections.split_at(mid);
            let (rl, rr) = rayon::join(
                || -> Result<()> {
                    for shard in left {
                        let rel_md = shard
                            .summary
                            .md_file
                            .strip_prefix("sections/")
                            .unwrap_or(&shard.summary.md_file);
                        write_file(&sections_dir.join(rel_md), &shard.markdown_body)?;
                    }
                    Ok(())
                },
                || -> Result<()> {
                    for shard in right {
                        let rel_md = shard
                            .summary
                            .md_file
                            .strip_prefix("sections/")
                            .unwrap_or(&shard.summary.md_file);
                        write_file(&sections_dir.join(rel_md), &shard.markdown_body)?;
                    }
                    Ok(())
                },
            );
            rl?;
            rr?;
        }
        Ok(())
    };
    let write_small_tsvs = || -> Result<()> {
        write_file(&index_dir.join("sections.tsv"), &sec_tsv)?;
        write_file(&index_dir.join("symbols.tsv"), &sym_tsv)?;
        write_file(&index_dir.join("types.tsv"), &typ_tsv)?;
        write_file(&index_dir.join("macros.tsv"), &mac_tsv)
    };
    let write_calls_and_cache = || -> Result<()> {
        write_file(&index_dir.join("calls.tsv"), &calls_tsv)?;
        emit_cache_shards(output_dir, cache)
    };
    let write_xref = || -> Result<()> { write_file(&index_dir.join("xref.tsv"), &xref_tsv) };

    let ((r1a, r1b), (r2, r3)) = rayon::join(
        || rayon::join(write_md_and_sections, write_small_tsvs),
        || rayon::join(write_calls_and_cache, write_xref),
    );
    r1a?;
    r1b?;
    r2?;
    r3?;

    // Optional <repo_name>.md if config.single_file is true
    if config.single_file {
        let mut combined = String::with_capacity(index_md.len() + sections.len() * 2048);
        combined.push_str(&index_md);
        combined.push_str("\n---\n\n");
        for shard in sections {
            combined.push_str(&shard.markdown_body);
            combined.push_str("\n\n---\n\n");
        }
        let single_path = output_dir.join(format!("{}.md", metadata.repo_name));
        write_file(&single_path, &combined)?;
    }

    // Persist the compact linked-graph state used by the coordinate-shift tier. Written last so
    // it always describes the bundle that is on disk; a missing/corrupt file only disables the
    // fast path (callers fall back to a full rebuild).
    let graph_state = build_graph_state(indexes, &metadata.fingerprint, metadata.vendor_mode);
    emit_graph_state(output_dir, &graph_state)?;

    // Ensure .claudeignore entry (only when output_dir is inside repo_path)
    let claudeignore_updated = ensure_claudeignore_entry(&config.repo_path, output_dir)?;
    Ok(claudeignore_updated)
}

/// Builds the compact linked-graph state persisted at `cache/graph_state.json`.
///
/// The per-symbol annotations (PageRank/HITS/degree/SCC/god/entrypoint flags) are the only
/// analysis output that cannot be re-derived from the AST tables, so they are stored compactly
/// keyed by `(symbol_id, start_line)`; calls and xrefs are reconstructed from `index/*.tsv`.
pub fn build_graph_state(
    indexes: &BundleIndexes,
    fingerprint: &str,
    vendor_mode: VendorMode,
) -> GraphStateFile {
    GraphStateFile {
        schema_version: CACHE_SCHEMA_VERSION.to_string(),
        fingerprint: fingerprint.to_string(),
        vendor_mode,
        symbols: indexes
            .symbols
            .iter()
            .map(|rs| SymbolGraphState {
                symbol_id: rs.symbol.symbol_id.clone(),
                start_line: rs.symbol.start_line,
                pagerank: rs.pagerank,
                hub_score: rs.hub_score,
                authority_score: rs.authority_score,
                in_degree: rs.in_degree,
                out_degree: rs.out_degree,
                is_god_node: rs.is_god_node,
                is_entrypoint: rs.is_entrypoint,
                scc_id: rs.scc_id,
            })
            .collect(),
        god_nodes: indexes
            .god_nodes
            .iter()
            .map(|rs| GraphSymbolRef {
                symbol_id: rs.symbol.symbol_id.clone(),
                start_line: rs.symbol.start_line,
            })
            .collect(),
        entrypoints: indexes
            .entrypoints
            .iter()
            .map(|rs| GraphSymbolRef {
                symbol_id: rs.symbol.symbol_id.clone(),
                start_line: rs.symbol.start_line,
            })
            .collect(),
        layer_edges: indexes.layer_edges.clone(),
        cycles: indexes.cycles.clone(),
        vendor_surface: indexes.vendor_surface.clone(),
    }
}

/// Atomically writes the linked-graph state to `<out_dir>/cache/graph_state.json`.
pub fn emit_graph_state(output_dir: &Path, state: &GraphStateFile) -> Result<()> {
    let cache_dir = output_dir.join("cache");
    create_dir(&cache_dir)?;
    let json = serde_json::to_string(state)?;
    write_bytes_atomic(&cache_dir.join(GRAPH_STATE_FILE), json.as_bytes())
}

/// Loads `cache/graph_state.json` if present and well-formed (any schema version is accepted
/// here; callers validate the version before using it).
pub fn load_graph_state(bundle_dir: &Path) -> Option<GraphStateFile> {
    let bytes = fs::read(bundle_dir.join("cache").join(GRAPH_STATE_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn build_master_index_markdown(
    metadata: &RepoMetadata,
    sanity: &SanityReport,
    sections: &[SectionShard],
    indexes: &BundleIndexes,
) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(256);

    lines.push(format!(
        "# {} — Codebase Intelligence Bundle",
        metadata.repo_name
    ));
    lines.push(String::new());

    // Agent Navigation Guide
    lines.push("> **Agent Navigation Guide**:".to_string());
    lines.push(
        "> - **1-Turn CLI Queries**: `chipsrc sym <name> [--show]`, `chipsrc callers <fn> [--show]`, `chipsrc callees <fn> [--show]`, `chipsrc type <name> [--show]`, `chipsrc macro <name|hex> [--show]`, `chipsrc section <query> [--show]`, `chipsrc xref <symbol>`, `chipsrc search <pattern>`."
            .to_string(),
    );
    lines.push(
        "> - **Direct Flat TSV Indexes**: Grep `index/symbols.tsv`, `index/types.tsv`, `index/calls.tsv`, `index/macros.tsv`, `index/xref.tsv`, and `index/sections.tsv`."
            .to_string(),
    );
    lines.push(
        "> - **Module Signature Skeletons**: Read `sections/*.md` for compact module signatures and exact `file:start_line-end_line` coordinates before opening raw source files."
            .to_string(),
    );
    lines.push(String::new());

    // Repository Summary
    lines.push("## Repository Summary".to_string());
    lines.push(String::new());
    lines.push(format!("- **Source Root**: `{}`", metadata.source_root));
    lines.push(format!(
        "- **Repository Fingerprint**: `{}` (vendor mode: `{}`)",
        metadata.fingerprint,
        metadata.vendor_mode.as_str()
    ));
    lines.push(format!(
        "- **Source Files**: {} total ({} first-party, {} vendor SDK, {} test) | **Total Lines**: {}",
        metadata.total_files,
        metadata.first_party_files,
        metadata.vendor_files,
        metadata.test_files,
        metadata.total_lines
    ));
    if !metadata.languages.is_empty() {
        let lang_summary: Vec<String> = metadata
            .languages
            .iter()
            .map(|l| format!("`{}` ({} files, {} lines)", l.language, l.files, l.lines))
            .collect();
        lines.push(format!("- **Languages**: {}", lang_summary.join(", ")));
    }
    lines.push(format!(
        "- **Indexed Entities**: {} symbols ({} hubs, {} entrypoints/ISRs) | {} types | {} call edges ({:.1}% resolved) | {} macros/MMIO | {} xrefs",
        metadata.symbol_count,
        metadata.god_node_count,
        metadata.entrypoint_count,
        metadata.type_count,
        metadata.call_edge_count,
        sanity.call_resolution_ratio * 100.0,
        metadata.macro_count,
        metadata.xref_count
    ));
    lines.push(format!(
        "- **Sanity & Token Compression**: **{}/100** ({:.1}% clean parse) | ~{} raw source tokens -> ~{} bundle index tokens (**{:.1}x compression**)",
        sanity.score,
        sanity.parse_clean_ratio * 100.0,
        sanity.raw_source_tokens_est,
        sanity.bundle_index_tokens_est,
        sanity.token_compression_ratio
    ));
    lines.push(String::new());

    // Architectural Layer Topology
    lines.push("## Architectural Layer Topology".to_string());
    lines.push(String::new());
    if indexes.layer_edges.is_empty() {
        lines.push("_No cross-layer call or import edges detected._".to_string());
    } else {
        lines.push("| From Layer -> To Layer | Calls | Imports | Status |".to_string());
        lines.push("| --- | ---: | ---: | --- |".to_string());
        for edge in &indexes.layer_edges {
            let status = if edge.is_upward_violation {
                "UPWARD VIOLATION"
            } else {
                "OK"
            };
            lines.push(format!(
                "| `{}` -> `{}` | {} | {} | {} |",
                edge.from_layer, edge.to_layer, edge.call_count, edge.import_count, status
            ));
        }
    }
    if !indexes.cycles.is_empty() {
        lines.push(String::new());
        lines.push("### Strongly Connected Cyclic Clusters (SCCs)".to_string());
        for c in &indexes.cycles {
            lines.push(format!(
                "- **SCC #{}** ({} symbols in `{}`): {}",
                c.scc_id,
                c.symbols.len(),
                c.files.join(", "),
                c.symbols
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(" <-> ")
            ));
        }
    }
    lines.push(String::new());

    // Entrypoints & Interrupt Service Routines (ISRs)
    lines.push("## Entrypoints & Interrupt Service Routines (ISRs)".to_string());
    lines.push(String::new());
    let (entrypoints_list, isrs_list) = select_entrypoints(indexes);
    if entrypoints_list.is_empty() && isrs_list.is_empty() {
        lines.push("_No explicit entrypoints or ISRs detected._".to_string());
    } else {
        lines.push("| Symbol | Kind | Layer | Location | Out-Calls | Signature |".to_string());
        lines.push("| --- | --- | --- | --- | ---: | --- |".to_string());
        let ep_quota = if isrs_list.len() > 17 {
            8.min(entrypoints_list.len())
        } else {
            (25usize.saturating_sub(isrs_list.len())).min(entrypoints_list.len())
        };
        let isr_quota = 25usize.saturating_sub(ep_quota).min(isrs_list.len());
        for rs in entrypoints_list
            .iter()
            .take(ep_quota)
            .chain(isrs_list.iter().take(isr_quota))
        {
            let s = &rs.symbol;
            lines.push(format!(
                "| `{}` | `{}` | `{}` | `{}:{}-{}` | {} | `{}` |",
                escape_table(&s.name),
                s.kind.as_str(),
                s.arch_layer.as_str(),
                s.file,
                s.start_line,
                s.end_line,
                rs.out_degree,
                escape_table(&s.signature)
            ));
        }
        if isrs_list.len() > isr_quota {
            lines.push(format!(
                "_… +{} more ISRs indexed in `index/symbols.tsv`_",
                isrs_list.len() - isr_quota
            ));
        }
    }
    lines.push(String::new());

    // Central Architectural Hubs (God Nodes)
    lines.push("## Central Architectural Hubs (God Nodes)".to_string());
    lines.push(String::new());
    let god_nodes_list = select_god_nodes(indexes);
    if god_nodes_list.is_empty() {
        lines.push("_No central architectural hubs ranked._".to_string());
    } else {
        lines.push(
            "| Rank | Symbol | Kind | Layer | PageRank | In/Out | Location | Signature |"
                .to_string(),
        );
        lines.push("| ---: | --- | --- | --- | ---: | --- | --- | --- |".to_string());
        for (idx, rs) in god_nodes_list.iter().take(15).enumerate() {
            let s = &rs.symbol;
            lines.push(format!(
                "| {} | `{}` | `{}` | `{}` | {:.4} | {}/{} | `{}:{}-{}` | `{}` |",
                idx + 1,
                escape_table(&s.name),
                s.kind.as_str(),
                s.arch_layer.as_str(),
                rs.pagerank,
                rs.in_degree,
                rs.out_degree,
                s.file,
                s.start_line,
                s.end_line,
                escape_table(&s.signature)
            ));
        }
    }
    lines.push(String::new());

    // Core Domain Types & Data Structures (Issue #45)
    let top_types = select_core_domain_types(indexes);
    if !top_types.is_empty() {
        lines.push("## Core Domain Types & Data Structures".to_string());
        lines.push(String::new());
        lines.push("| Type | Kind | Layer | Refs | Location | Fields / Variants |".to_string());
        lines.push("| --- | --- | --- | ---: | --- | --- |".to_string());
        for (t, refs) in top_types.into_iter().take(15) {
            let fields = if t.fields_summary.is_empty() {
                Cow::Borrowed("-")
            } else {
                escape_table(&t.fields_summary)
            };
            lines.push(format!(
                "| `{}` | `{}` | `{}` | {} | `{}:{}-{}` | `{}` |",
                escape_table(&t.name),
                t.kind.as_str(),
                t.arch_layer.as_str(),
                refs,
                t.file,
                t.start_line,
                t.end_line,
                fields
            ));
        }
        lines.push(String::new());
    }

    // Active Hardware / MMIO & Vendor SDK Surface
    lines.push("## Active Hardware / MMIO & Vendor SDK Surface".to_string());
    lines.push(String::new());
    let vs = &indexes.vendor_surface;
    lines.push(format!(
        "- **Vendor SDK Footprint**: {} vendor files, {} vendor symbols ({} actively referenced by first-party code)",
        vs.total_vendor_files,
        vs.total_vendor_symbols,
        vs.active_vendor_symbols.len()
    ));
    if !vs.active_mmio_registers.is_empty() {
        let mmio_list: Vec<String> = vs
            .active_mmio_registers
            .iter()
            .take(40)
            .map(|r| format!("`{r}`"))
            .collect();
        lines.push(format!(
            "- **Active MMIO Registers & Bitmasks ({})**: {}",
            vs.active_mmio_registers.len(),
            mmio_list.join(", ")
        ));
    } else {
        lines.push("- **Active MMIO Registers & Bitmasks**: none".to_string());
    }
    if !vs.active_vendor_symbols.is_empty() {
        let vsym_list: Vec<String> = vs
            .active_vendor_symbols
            .iter()
            .take(40)
            .map(|s| format!("`{s}`"))
            .collect();
        lines.push(format!(
            "- **Active Vendor SDK Symbols ({})**: {}",
            vs.active_vendor_symbols.len(),
            vsym_list.join(", ")
        ));
    }
    if !vs.active_vendor_headers.is_empty() {
        let vhdr_list: Vec<String> = vs
            .active_vendor_headers
            .iter()
            .take(25)
            .map(|h| format!("`{h}`"))
            .collect();
        lines.push(format!(
            "- **Active Vendor Headers ({})**: {}",
            vs.active_vendor_headers.len(),
            vhdr_list.join(", ")
        ));
    }
    lines.push(String::new());

    // Architectural Module Shards (sections/*.md)
    lines.push("## Architectural Module Shards (`sections/*.md`)".to_string());
    lines.push(String::new());
    lines.push(
        "| ID | Module Path | Layer | Scope | Files | Symbols | Types | Est. Tokens | File |"
            .to_string(),
    );
    lines.push("| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |".to_string());
    for sec in sections {
        let s = &sec.summary;
        let rel_link = if s.md_file.starts_with("sections/") {
            s.md_file.clone()
        } else {
            format!("sections/{}", s.md_file)
        };
        lines.push(format!(
            "| `{}` | `{}` | `{}` | `{}` | {} | {} | {} | ~{} | [{}]({}) |",
            s.section_id,
            escape_table(&s.module_path),
            s.arch_layer,
            s.scope,
            s.file_count,
            s.symbol_count,
            s.type_count,
            s.token_estimate,
            rel_link,
            rel_link
        ));
    }
    lines.push(String::new());

    lines.join("\n")
}

/// Writes `cache/manifest.json` and per-file `cache/<shard_key>.json` shards, deleting
/// orphaned shards and any legacy `cache.json` file.
///
/// Performs a single `fs::read_dir` pass over `cache/` to detect existing shard files,
/// reuses `structural_digest` from the previous manifest when `blake3_hash` and `shard`
/// match, writes only missing or changed shards, and prunes orphaned `.json` shards.
pub fn emit_cache_shards(output_dir: &Path, cache: &IncrementalAstCache) -> Result<()> {
    let cache_dir = output_dir.join("cache");
    create_dir(&cache_dir)?;

    let mut existing_json_files: FxHashSet<String> = FxHashSet::default();
    if let Ok(entries) = fs::read_dir(&cache_dir) {
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|ft| ft.is_file()) {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if name.ends_with(".json") {
                existing_json_files.insert(name);
            } else if name.ends_with(".tmp") {
                let p = entry.path();
                if is_stale_tmp_file(&p) {
                    let _ = fs::remove_file(p);
                }
            }
        }
    }

    let prev_manifest = if existing_json_files.contains("manifest.json") {
        fs::read(cache_dir.join("manifest.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<CacheManifest>(&b).ok())
    } else {
        None
    };
    let schema_current = prev_manifest.as_ref().is_some_and(|m| {
        m.schema_version == cache.schema_version
            && m.blueprint_hash == cache.blueprint_hash
            && m.vendor_mode == cache.vendor_mode
    });

    let mut manifest_files: BTreeMap<String, CacheShardEntry> = BTreeMap::new();
    let mut expected_shard_names: FxHashSet<String> =
        FxHashSet::with_capacity_and_hasher(cache.files.len(), Default::default());

    for (rel_path, unit) in &cache.files {
        let hash = &unit.scanned.blake3_hash;
        let shard_key = CacheShardEntry::shard_key(rel_path, hash);
        let shard_fname = format!("{shard_key}.json");
        let shard_rel = format!("cache/{shard_fname}");

        let matched_prev = if schema_current {
            prev_manifest
                .as_ref()
                .and_then(|m| m.files.get(rel_path))
                .filter(|prev| {
                    prev.blake3_hash == *hash
                        && prev.shard == shard_rel
                        && !prev.structural_digest.is_empty()
                })
        } else {
            None
        };

        let structural_digest = match matched_prev {
            Some(prev) => prev.structural_digest.clone(),
            None => unit.structural_digest(),
        };

        let reuse_existing_shard =
            matched_prev.is_some() && existing_json_files.contains(&shard_fname);

        if !reuse_existing_shard {
            let shard_path = cache_dir.join(&shard_fname);
            let unit_json = serde_json::to_string(unit)?;
            write_file(&shard_path, &unit_json)?;
        }

        expected_shard_names.insert(shard_fname);
        manifest_files.insert(
            rel_path.clone(),
            CacheShardEntry {
                blake3_hash: hash.clone(),
                shard: shard_rel,
                structural_digest,
            },
        );
    }

    for existing_name in &existing_json_files {
        if existing_name != "manifest.json"
            && existing_name != GRAPH_STATE_FILE
            && !expected_shard_names.contains(existing_name)
        {
            let _ = fs::remove_file(cache_dir.join(existing_name));
        }
    }

    let manifest = CacheManifest {
        schema_version: cache.schema_version.clone(),
        repo_root: cache.repo_root.clone(),
        vendor_mode: cache.vendor_mode,
        fingerprint: cache.fingerprint.clone(),
        blueprint_hash: cache.blueprint_hash.clone(),
        files: manifest_files,
    };
    let manifest_json = serde_json::to_string(&manifest)?;
    write_file(&cache_dir.join("manifest.json"), &manifest_json)?;

    let legacy_cache = output_dir.join("cache.json");
    if legacy_cache.is_file() {
        let _ = fs::remove_file(legacy_cache);
    }

    Ok(())
}

fn select_entrypoints(indexes: &BundleIndexes) -> (Vec<&RankedSymbol>, Vec<&RankedSymbol>) {
    let source: Vec<&RankedSymbol> =
        if !indexes.entrypoints.is_empty() && indexes.entrypoints.iter().any(|r| r.is_entrypoint) {
            indexes.entrypoints.iter().collect()
        } else {
            indexes.symbols.iter().filter(|r| r.is_entrypoint).collect()
        };

    let mut entrypoints = Vec::new();
    let mut isrs = Vec::new();
    for rs in source {
        if rs.symbol.kind == SymbolKind::Isr {
            isrs.push(rs);
        } else {
            entrypoints.push(rs);
        }
    }

    let sort_fn = |a: &&RankedSymbol, b: &&RankedSymbol| {
        let fp_a = a.symbol.scope != FileScope::FirstParty;
        let fp_b = b.symbol.scope != FileScope::FirstParty;
        fp_a.cmp(&fp_b)
            .then_with(|| b.pagerank.total_cmp(&a.pagerank))
            .then_with(|| a.symbol.file.cmp(&b.symbol.file))
            .then_with(|| a.symbol.start_line.cmp(&b.symbol.start_line))
            .then_with(|| a.symbol.symbol_id.cmp(&b.symbol.symbol_id))
    };
    entrypoints.sort_by(sort_fn);
    isrs.sort_by(sort_fn);

    (entrypoints, isrs)
}

fn select_god_nodes(indexes: &BundleIndexes) -> Vec<&RankedSymbol> {
    if !indexes.god_nodes.is_empty() && indexes.god_nodes.iter().any(|r| r.is_god_node) {
        return indexes.god_nodes.iter().collect();
    }
    let mut nodes: Vec<&RankedSymbol> = indexes.symbols.iter().filter(|r| r.is_god_node).collect();
    nodes.sort_by(|a, b| b.pagerank.total_cmp(&a.pagerank));
    nodes
}

fn is_excluded_std_type_alias(t: &ExtractedType, total_types: usize) -> bool {
    if total_types <= 5 || t.kind != TypeKind::TypeAlias {
        return false;
    }
    matches!(
        t.name.as_str(),
        "Result" | "Error" | "Option" | "Box" | "Rc" | "Arc"
    ) || t.fields_summary.starts_with("std::")
        || t.fields_summary.starts_with("core::")
}

fn select_core_domain_types(indexes: &BundleIndexes) -> Vec<(&ExtractedType, usize)> {
    if indexes.types.is_empty() {
        return Vec::new();
    }
    let total_types = indexes.types.len();
    let has_first_party = indexes
        .types
        .iter()
        .any(|t| t.scope == FileScope::FirstParty);

    let candidate_types: Vec<&ExtractedType> = indexes
        .types
        .iter()
        .filter(|t| {
            (!has_first_party || t.scope == FileScope::FirstParty)
                && !is_excluded_std_type_alias(t, total_types)
        })
        .collect();

    if candidate_types.is_empty() {
        return Vec::new();
    }

    let mut type_files: FxHashMap<&str, &str> = FxHashMap::default();
    let mut ref_files_by_type: FxHashMap<&str, FxHashSet<&str>> = FxHashMap::default();
    let mut pub_fn_files_by_type: FxHashMap<&str, FxHashSet<&str>> = FxHashMap::default();
    let mut facade_pub_fn_counts: FxHashMap<&str, usize> = FxHashMap::default();
    let mut enclosing_counts: FxHashMap<&str, usize> = FxHashMap::default();

    for t in &candidate_types {
        type_files.insert(t.name.as_str(), t.file.as_str());
        ref_files_by_type.insert(t.name.as_str(), FxHashSet::default());
        pub_fn_files_by_type.insert(t.name.as_str(), FxHashSet::default());
        facade_pub_fn_counts.insert(t.name.as_str(), 0);
        enclosing_counts.insert(t.name.as_str(), 0);
    }

    // Map excluded TypeAliases (e.g. `type Result<T> = std::result::Result<T, ChipsrcError>`)
    // to any domain candidate types referenced in their definition so `Result<...>` in signatures
    // credits the underlying domain error/type (`ChipsrcError`).
    let mut alias_forwards: FxHashMap<&str, Vec<&str>> = FxHashMap::default();
    for t in &indexes.types {
        if is_excluded_std_type_alias(t, total_types) {
            let mut targets = Vec::new();
            for tok in t
                .fields_summary
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .filter(|s| !s.is_empty() && *s != t.name)
            {
                if let Some(&canon_name) = type_files.keys().find(|&&k| k == tok) {
                    targets.push(canon_name);
                }
            }
            if !targets.is_empty() {
                alias_forwards.insert(t.name.as_str(), targets);
            }
        }
    }

    for rs in &indexes.symbols {
        if has_first_party && rs.symbol.scope == FileScope::Test {
            continue;
        }
        let sym_file = rs.symbol.file.as_str();
        let is_pub_free_fn =
            rs.symbol.visibility == Visibility::Public && rs.symbol.enclosing_type.is_none();
        if let Some(et) = rs.symbol.enclosing_type.as_deref() {
            if let Some(cnt) = enclosing_counts.get_mut(et) {
                if rs.symbol.name != "as_str" {
                    *cnt += 1;
                }
            }
            if let Some(fset) = ref_files_by_type.get_mut(et) {
                fset.insert(sym_file);
            }
        }
        for tok in rs
            .symbol
            .signature
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty())
        {
            if let Some(fset) = ref_files_by_type.get_mut(tok) {
                fset.insert(sym_file);
            }
            if is_pub_free_fn {
                if let Some(pfset) = pub_fn_files_by_type.get_mut(tok) {
                    pfset.insert(sym_file);
                }
                if sym_file.ends_with("/lib.rs") || sym_file == "src/lib.rs" || sym_file == "lib.rs"
                {
                    if let Some(c) = facade_pub_fn_counts.get_mut(tok) {
                        *c += 1;
                    }
                }
            }
            if let Some(forwarded) = alias_forwards.get(tok) {
                for &target_ty in forwarded {
                    if let Some(fset) = ref_files_by_type.get_mut(target_ty) {
                        fset.insert(sym_file);
                    }
                    if is_pub_free_fn {
                        if let Some(pfset) = pub_fn_files_by_type.get_mut(target_ty) {
                            pfset.insert(sym_file);
                        }
                    }
                }
            }
        }
    }

    for t in &indexes.types {
        let t_file = t.file.as_str();
        for tok in t
            .fields_summary
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| !s.is_empty() && *s != t.name)
        {
            if let Some(fset) = ref_files_by_type.get_mut(tok) {
                fset.insert(t_file);
            }
        }
    }

    for x in &indexes.xrefs {
        if has_first_party && (x.file.contains("/tests/") || x.file.starts_with("tests/")) {
            continue;
        }
        if matches!(
            x.category.as_str(),
            "import" | "type_ref" | "field_read" | "field_write"
        ) {
            let sym_head = x
                .symbol
                .split_once("::")
                .map(|(h, _)| h)
                .unwrap_or(x.symbol.as_str());
            if let Some(fset) = ref_files_by_type.get_mut(sym_head) {
                fset.insert(x.file.as_str());
            }
        }
    }

    let mut ranked: Vec<(&ExtractedType, usize, usize, bool)> = candidate_types
        .into_iter()
        .map(|t| {
            let t_name = t.name.as_str();
            let fset = ref_files_by_type.get(t_name);
            let distinct_files = fset.map_or(0, |s| s.len());
            let mut raw_weighted = enclosing_counts.get(t_name).copied().unwrap_or(0);
            if let Some(files) = fset {
                for &f in files {
                    if f != t.file.as_str() {
                        raw_weighted += 2;
                    } else {
                        raw_weighted += 1;
                    }
                }
            }
            if let Some(pfiles) = pub_fn_files_by_type.get(t_name) {
                for &f in pfiles {
                    if f != t.file.as_str() {
                        raw_weighted += 2;
                    } else {
                        raw_weighted += 1;
                    }
                }
            }
            raw_weighted += facade_pub_fn_counts.get(t_name).copied().unwrap_or(0) * 4;
            if t.kind == TypeKind::Struct && !t.fields_summary.is_empty() {
                raw_weighted += 2;
            }
            let weighted_refs = if t.arch_layer == ArchLayer::Domain {
                (raw_weighted * 5).div_ceil(4)
            } else {
                raw_weighted
            };
            let is_public_aggregate = t.visibility == Visibility::Public
                && matches!(
                    t.kind,
                    TypeKind::Struct
                        | TypeKind::Enum
                        | TypeKind::Trait
                        | TypeKind::Interface
                        | TypeKind::Class
                );
            (t, weighted_refs, distinct_files, is_public_aggregate)
        })
        .collect();

    ranked.sort_by(|(ta, wa, da, pub_a), (tb, wb, db, pub_b)| {
        pub_b
            .cmp(pub_a)
            .then_with(|| wb.cmp(wa))
            .then_with(|| db.cmp(da))
            .then_with(|| ta.name.cmp(&tb.name))
    });

    ranked
        .into_iter()
        .map(|(t, weighted_refs, _, _)| (t, weighted_refs))
        .collect()
}

fn escape_table(s: &str) -> Cow<'_, str> {
    match sanitize_tsv(s) {
        Cow::Borrowed(clean) => {
            if clean.contains('|') {
                Cow::Owned(clean.replace('|', "\\|"))
            } else {
                Cow::Borrowed(clean)
            }
        }
        Cow::Owned(owned) => {
            if owned.contains('|') {
                Cow::Owned(owned.replace('|', "\\|"))
            } else {
                Cow::Owned(owned)
            }
        }
    }
}

fn create_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| ChipsrcError::io(path, source))
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    write_bytes_atomic(path, content.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ExtractedSymbol, LanguageKind, ParsedFileUnit, ScannedFile, VendorMode,
        CACHE_SCHEMA_VERSION,
    };
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("chipsrc_emitter_{label}_{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sanitize_tsv_reference(value: &str) -> String {
        value
            .chars()
            .map(|c| {
                if c == '\t' || c == '\r' || c == '\n' || c.is_control() {
                    ' '
                } else {
                    c
                }
            })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn test_sanitize_tsv_strips_tabs_and_newlines() {
        let raw = "fn foo(\n\tint a,\r\n\tint   b\n) -> i32";
        assert_eq!(sanitize_tsv(raw), "fn foo( int a, int b ) -> i32");
    }

    #[test]
    fn sanitize_tsv_fast_path_matches_slow_path() {
        let cases: &[(&str, bool)] = &[
            ("", true),
            ("a", true),
            ("-", true),
            ("0", true),
            ("0.004215", true),
            ("external::malloc", true),
            ("smart_locker/domain/identifiers.py::pm_match_key", true),
            (
                "pub fn emit_bundle(config: &ConvertConfig) -> Result<bool>",
                true,
            ),
            ("def pm_match_key(raw: str) -> str", true),
            ("Single spaces between words are clean.", true),
            ("01-domain", true),
            ("sections/01-domain.md", true),
            ("first_party", true),
            ("same_file", true),
            ("Returns Cow<str> — fast path", true),
            ("αβγ → δεζ", true),
            ("Unicode identifier café_name", true),
            ("Symbols: [a, b, c] {x: 1}", true),
            ("a ~ b ! c @ d # e $ f % g ^ h & i * j", true),
            ("1234567890_abcdef", true),
            // Dirty inputs that must take Cow::Owned and match reference
            (" ", false),
            ("   ", false),
            (" leading", false),
            ("trailing ", false),
            (" both ", false),
            ("a  b", false),
            ("a   b    c", false),
            ("a\tb", false),
            ("\tleading_tab", false),
            ("trailing_tab\t", false),
            ("line1\nline2", false),
            ("line1\r\nline2", false),
            ("only\r\n\t ", false),
            ("fn foo(\n\tint a,\r\n\tint   b\n) -> i32", false),
            ("null\0byte", false),
            ("\x01bell\x07and\x1besc", false),
            ("del\x7fchar", false),
            ("vtab\x0band\x0cff", false),
            ("c1\u{0080}control", false),
            ("next\u{0085}line", false),
            ("c1_end\u{009f}ctrl", false),
            ("nbsp\u{00a0}sep", false),
            ("em\u{2003}space", false),
            ("ideo\u{3000}space", false),
            ("\u{2000}leading_unicode_ws", false),
            ("trailing_unicode_ws\u{200a}", false),
            ("αβγ  δεζ", false),
            ("αβγ\tδεζ\nηθι", false),
        ];

        assert!(cases.len() >= 40);
        for &(input, expect_borrowed) in cases {
            let result = sanitize_tsv(input);
            let expected = sanitize_tsv_reference(input);
            assert_eq!(
                result.as_ref(),
                expected.as_str(),
                "mismatch for input {:?}",
                input
            );
            assert_eq!(
                matches!(result, Cow::Borrowed(_)),
                expect_borrowed,
                "Cow variant mismatch for input {:?}",
                input
            );
        }
    }

    #[test]
    fn write_file_skips_identical_large_content() {
        let tmp = TestTempDir::new("write_skip_large");
        let path = tmp.0.join("large_xref.tsv");

        // Build > 1 MB payload (exceeds the legacy 256 KB cap)
        let row = "symbol_alpha\tcall\tsame_file\tmod::caller\tsrc/mod.rs\t42\t01-mod\tcaller -> symbol_alpha\n";
        let content = row.repeat(14_000);
        assert!(content.len() > 1024 * 1024);

        write_file(&path, &content).expect("initial write");
        let past = SystemTime::now() - Duration::from_secs(60);
        {
            let f = fs::File::options()
                .write(true)
                .open(&path)
                .expect("open for set_modified");
            f.set_modified(past).expect("set past mtime");
        }
        let mtime_before = fs::metadata(&path)
            .expect("meta before")
            .modified()
            .expect("mtime before");

        // Second write with identical >1 MB content must be skipped
        write_file(&path, &content).expect("second identical write");
        let mtime_after_skip = fs::metadata(&path)
            .expect("meta after skip")
            .modified()
            .expect("mtime after skip");
        assert_eq!(mtime_before, mtime_after_skip);

        // Mutating 1 byte (same length) must write through and update mtime
        let mut modified_content = content.into_bytes();
        modified_content[0] = b'Z';
        let modified_str = String::from_utf8(modified_content).expect("valid utf8");
        write_file(&path, &modified_str).expect("write modified content");
        let mtime_after_change = fs::metadata(&path)
            .expect("meta after change")
            .modified()
            .expect("mtime after change");
        assert_ne!(mtime_before, mtime_after_change);
        assert_eq!(
            fs::read_to_string(&path).expect("read updated").as_bytes()[0],
            b'Z'
        );
    }

    #[test]
    fn emit_cache_shards_reuses_manifest_digest() {
        let tmp = TestTempDir::new("cache_shards_reuse");
        let out_dir = tmp.0.join("bundle");

        let make_unit = |rel_path: &str, hash: &str, sym_name: &str| ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: rel_path.to_string(),
                abs_path: PathBuf::from(rel_path),
                language: LanguageKind::Python,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Domain,
                size_bytes: 100,
                mtime_secs: 1_700_000_000,
                mtime_nanos: 0,
                blake3_hash: hash.to_string(),
                line_count: 10,
            },
            symbols: vec![ExtractedSymbol {
                symbol_id: format!("{rel_path}::{sym_name}"),
                name: sym_name.to_string(),
                qualified_name: sym_name.to_string(),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                file: rel_path.to_string(),
                start_line: 1,
                end_line: 5,
                signature: format!("def {sym_name}():"),
                doc_summary: String::new(),
                enclosing_type: None,
                arch_layer: ArchLayer::Domain,
                scope: FileScope::FirstParty,
                section_id: "01-domain".to_string(),
            }],
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        };

        let mut files = BTreeMap::new();
        files.insert(
            "a.py".to_string(),
            make_unit("a.py", "1111111111111111", "fn_a"),
        );
        files.insert(
            "b.py".to_string(),
            make_unit("b.py", "2222222222222222", "fn_b"),
        );

        let mut cache = IncrementalAstCache {
            schema_version: CACHE_SCHEMA_VERSION.to_string(),
            repo_root: "/repo".to_string(),
            vendor_mode: VendorMode::Active,
            fingerprint: "fp1".to_string(),
            blueprint_hash: String::new(),
            files,
        };

        emit_cache_shards(&out_dir, &cache).expect("first emit_cache_shards");

        let shard_a_key = CacheShardEntry::shard_key("a.py", "1111111111111111");
        let shard_a_path = out_dir.join("cache").join(format!("{shard_a_key}.json"));
        let shard_b_old_key = CacheShardEntry::shard_key("b.py", "2222222222222222");
        let shard_b_old_path = out_dir
            .join("cache")
            .join(format!("{shard_b_old_key}.json"));

        // Backdate shard_a and inject a sentinel structural_digest into manifest.json
        let past = SystemTime::now() - Duration::from_secs(60);
        {
            let f = fs::File::options()
                .write(true)
                .open(&shard_a_path)
                .expect("open shard_a");
            f.set_modified(past).expect("set shard_a mtime");
        }
        let shard_a_mtime_before = fs::metadata(&shard_a_path)
            .expect("shard_a meta")
            .modified()
            .expect("shard_a mtime");

        let manifest_path = out_dir.join("cache").join("manifest.json");
        let mut manifest: CacheManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest
            .files
            .get_mut("a.py")
            .expect("a.py entry")
            .structural_digest = "sentinel_digest0".to_string();
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");

        // Update b.py hash while keeping a.py unchanged
        cache.files.insert(
            "b.py".to_string(),
            make_unit("b.py", "3333333333333333", "fn_b_v2"),
        );
        cache.fingerprint = "fp2".to_string();

        emit_cache_shards(&out_dir, &cache).expect("second emit_cache_shards");

        let shard_a_mtime_after = fs::metadata(&shard_a_path)
            .expect("shard_a meta after")
            .modified()
            .expect("shard_a mtime after");
        assert_eq!(
            shard_a_mtime_before, shard_a_mtime_after,
            "unchanged shard must not be rewritten"
        );
        assert!(
            !shard_b_old_path.exists(),
            "orphaned shard for old b.py must be pruned"
        );

        let updated_manifest: CacheManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read updated manifest"))
                .expect("parse updated manifest");
        assert_eq!(
            updated_manifest.files["a.py"].structural_digest, "sentinel_digest0",
            "structural_digest must be reused from previous manifest when blake3_hash matches"
        );
    }

    #[test]
    fn test_ensure_claudeignore_entry_idempotent_and_scoped_to_repo() {
        let tmp = TestTempDir::new("claudeignore");
        let out_dir = tmp.0.join("output").join("demo_repo");
        fs::create_dir_all(&out_dir).expect("create out_dir");

        let first = ensure_claudeignore_entry(&tmp.0, &out_dir).expect("first ensure");
        assert!(first);

        let claudeignore = fs::read_to_string(tmp.0.join(".claudeignore")).expect("read ignore");
        assert!(claudeignore.contains("# chipsrc generated bundles"));
        assert!(claudeignore.contains("output/"));

        let second = ensure_claudeignore_entry(&tmp.0, &out_dir).expect("second ensure");
        assert!(!second);

        // Out-of-tree output directory must NOT write `.claudeignore`
        let external = TestTempDir::new("external_out");
        let ext_out = external.0.join("qa_bundles").join("demo");
        fs::create_dir_all(&ext_out).expect("create ext_out");
        let ext_updated = ensure_claudeignore_entry(&tmp.0, &ext_out).expect("external ensure");
        assert!(!ext_updated);
        assert!(!external.0.join(".claudeignore").exists());
        assert!(is_output_inside_repo(&tmp.0, &out_dir));
        assert!(!is_output_inside_repo(&tmp.0, &ext_out));
    }

    #[test]
    fn write_bytes_atomic_leaves_no_tmp_on_success_or_failure_and_prunes_stale_tmp() {
        let tmp = TestTempDir::new("atomic_write");
        let target = tmp.0.join("meta.json");

        write_bytes_atomic(&target, b"{\"v\":1}\n").expect("atomic write 1");
        assert_eq!(fs::read(&target).expect("read 1"), b"{\"v\":1}\n");

        // Identical write must skip and preserve mtime
        let past = SystemTime::now() - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&target)
            .unwrap()
            .set_modified(past)
            .unwrap();
        let mtime_before = fs::metadata(&target).unwrap().modified().unwrap();
        write_bytes_atomic(&target, b"{\"v\":1}\n").expect("identical atomic write");
        let mtime_after_skip = fs::metadata(&target).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after_skip);

        // Changed content must replace atomically and leave zero *.tmp files
        write_bytes_atomic(&target, b"{\"v\":2}\n").expect("atomic write 2");
        assert_eq!(fs::read(&target).expect("read 2"), b"{\"v\":2}\n");

        // Failure case: target path is an existing directory -> rename fails, .tmp must be cleaned up
        let dir_target = tmp.0.join("dir_collision");
        fs::create_dir_all(&dir_target).expect("create collision dir");
        assert!(write_bytes_atomic(&dir_target, b"should fail").is_err());

        let tmp_leftovers: Vec<_> = fs::read_dir(&tmp.0)
            .expect("read tmp dir")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("tmp"))
            .collect();
        assert!(
            tmp_leftovers.is_empty(),
            "Expected zero .tmp files after success and failure, found: {:?}",
            tmp_leftovers
        );

        // Stale .tmp (>60s) is deleted by pruner while fresh .tmp is kept
        let stale_tmp = tmp.0.join(".meta.json.9999.0.tmp");
        let fresh_tmp = tmp.0.join(".meta.json.9999.1.tmp");
        fs::write(&stale_tmp, b"stale").expect("write stale tmp");
        fs::write(&fresh_tmp, b"fresh").expect("write fresh tmp");
        std::fs::File::options()
            .write(true)
            .open(&stale_tmp)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(120))
            .unwrap();
        prune_stale_tmp_files_in_dir(&tmp.0);
        assert!(!stale_tmp.exists(), "Stale .tmp (>60s) must be pruned");
        assert!(fresh_tmp.exists(), "Fresh .tmp (<60s) must not be pruned");
        let _ = fs::remove_file(&fresh_tmp);
    }

    #[test]
    fn bundle_lock_acquire_contention_stale_garbage_and_drop() {
        let tmp = TestTempDir::new("bundle_lock");
        let out_dir = tmp.0.join("bundle");
        let lock_path = out_dir.join("cache").join(".lock");

        // 1. Acquire lock on fresh bundle dir
        let lock1 = BundleLock::acquire(&out_dir, Duration::from_millis(100))
            .expect("acquire 1")
            .expect("lock1 should be Some");
        assert!(lock_path.is_file(), "cache/.lock must exist while held");
        let lock_text = fs::read_to_string(&lock_path).expect("read lock file");
        assert!(
            lock_text.trim().contains(':'),
            "Expected pid:unix_ms in lock file, got: {lock_text:?}"
        );

        // 2. Contention while held: waits ~80ms and returns Ok(None)
        let t0 = Instant::now();
        let contended =
            BundleLock::acquire(&out_dir, Duration::from_millis(80)).expect("contended acquire");
        assert!(
            contended.is_none(),
            "Second acquire while held must return None"
        );
        assert!(t0.elapsed() >= Duration::from_millis(65));

        // 3. Drop deletes cache/.lock
        drop(lock1);
        assert!(!lock_path.exists(), "Drop must remove cache/.lock");

        // 4. Stale lock (>10s old) is reclaimed immediately
        fs::write(&lock_path, "999999:1000\n").expect("write stale lock");
        std::fs::File::options()
            .write(true)
            .open(&lock_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(30))
            .unwrap();
        let t_stale = Instant::now();
        let lock2 = BundleLock::acquire(&out_dir, Duration::from_millis(500))
            .expect("acquire over stale")
            .expect("stale lock must be reclaimed");
        assert!(t_stale.elapsed() < Duration::from_millis(200));
        drop(lock2);
        assert!(!lock_path.exists());

        // 5. Garbage lock contents: treated by mtime (fresh = live, old = stale)
        fs::write(&lock_path, b"garbage\xff\x00not_pid_ms").expect("write fresh garbage lock");
        let garbage_live = BundleLock::acquire(&out_dir, Duration::from_millis(60))
            .expect("acquire on fresh garbage");
        assert!(
            garbage_live.is_none(),
            "Fresh garbage lock must be treated as live by mtime"
        );
        std::fs::File::options()
            .write(true)
            .open(&lock_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(60))
            .unwrap();
        let lock3 = BundleLock::acquire(&out_dir, Duration::from_millis(100))
            .expect("acquire on stale garbage")
            .expect("Stale garbage lock must be reclaimed by mtime");
        drop(lock3);
        assert!(!lock_path.exists());
    }
}
