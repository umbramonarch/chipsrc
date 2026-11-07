use crate::error::{ChipsrcError, Result};
use crate::model::{
    ArchLayer, BundleIndexes, CacheManifest, CacheShardEntry, ConvertConfig, ExtractedMacro,
    ExtractedType, FileScope, GraphStateFile, GraphSymbolRef, IncrementalAstCache, ParsedFileUnit,
    RankedSymbol, RepoMetadata, ResolvedCallEdge, SanityReport, SectionShard, SectionSummary,
    SymbolGraphState, SymbolKind, TypeKind, VendorMode, Visibility, XrefEntry,
    CACHE_SCHEMA_VERSION, GRAPH_STATE_FILE,
};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Advisory lock staleness threshold.
pub const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);

/// Maximum lock wait budget for automatic synchronization callers.
pub const LOCK_WAIT_AUTO_SYNC: Duration = Duration::from_millis(150);

/// Maximum lock wait budget for explicit commands.
pub const LOCK_WAIT_EXPLICIT: Duration = Duration::from_secs(5);

/// Interval at which a held lock refreshes its heartbeat.
pub const LOCK_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Poll interval while waiting for a contended lock.
pub const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(15);

const STALE_TMP_MAX_AGE: Duration = Duration::from_secs(60);

static NEXT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
static NEXT_LOCK_SEQ: AtomicU64 = AtomicU64::new(0);

type LockHeartbeatSignal = Arc<(Mutex<bool>, Condvar)>;

fn new_lock_owner_token() -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = NEXT_LOCK_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{}:{now_ms}:{seq}\n", std::process::id())
}

fn is_lock_contention_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists
        || err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(5 | 32 | 80 | 183))
}

fn is_lock_stale(lock_path: &Path) -> bool {
    let Ok(meta) = fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    age > LOCK_STALE_AFTER
}

fn refresh_lock_file(lock_path: &Path, owner_token: &str) -> bool {
    match fs::read(lock_path) {
        Ok(contents) if contents == owner_token.as_bytes() => {
            let _ = fs::write(lock_path, owner_token.as_bytes());
            true
        }
        _ => false,
    }
}

fn spawn_lock_heartbeat(
    lock_path: PathBuf,
    owner_token: String,
    interval: Duration,
) -> (LockHeartbeatSignal, Option<JoinHandle<()>>) {
    let signal = Arc::new((Mutex::new(false), Condvar::new()));
    let thread_signal = Arc::clone(&signal);
    let handle = std::thread::Builder::new()
        .name("chipsrc-bundle-lock-heartbeat".to_string())
        .spawn(move || {
            let (mutex, cvar) = &*thread_signal;
            let mut stop = match mutex.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            loop {
                if *stop {
                    break;
                }
                let (guard, _) = match cvar.wait_timeout(stop, interval) {
                    Ok(pair) => pair,
                    Err(poisoned) => poisoned.into_inner(),
                };
                stop = guard;
                if *stop {
                    break;
                }
                drop(stop);
                if !refresh_lock_file(&lock_path, &owner_token) {
                    break;
                }
                stop = match mutex.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
            }
        })
        .ok();
    (signal, handle)
}

static LOCK_ACQUIRE_SERIAL: Mutex<()> = Mutex::new(());

#[cfg(windows)]
const LOCK_FILE_SHARE_MODE: u32 = 0x1 | 0x2;

fn open_new_lock_file(lock_path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::File::options();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(LOCK_FILE_SHARE_MODE);
    }
    options.open(lock_path)
}

enum LockAttempt {
    Acquired(fs::File),
    Reclaimed(fs::File),
    Contended,
}

fn attempt_lock(lock_path: &Path) -> std::io::Result<LockAttempt> {
    match open_new_lock_file(lock_path) {
        Ok(file) => Ok(LockAttempt::Acquired(file)),
        Err(err) if is_lock_contention_error(&err) => {
            if !is_lock_stale(lock_path) {
                return Ok(LockAttempt::Contended);
            }
            if fs::remove_file(lock_path).is_err() {
                return Ok(LockAttempt::Contended);
            }
            match open_new_lock_file(lock_path) {
                Ok(file) => Ok(LockAttempt::Reclaimed(file)),
                Err(err) if is_lock_contention_error(&err) => Ok(LockAttempt::Contended),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

/// Advisory exclusive bundle lock guard.
#[derive(Debug)]
pub struct BundleLock {
    path: PathBuf,
    owner_token: String,
    handle: Option<fs::File>,
    stop_heartbeat: LockHeartbeatSignal,
    heartbeat: Option<JoinHandle<()>>,
}

impl BundleLock {
    /// Attempts to acquire an exclusive advisory bundle lock.
    pub fn acquire(out_dir: &Path, wait: Duration) -> Result<Option<Self>> {
        let cache_dir = out_dir.join("cache");
        fs::create_dir_all(&cache_dir).map_err(|source| ChipsrcError::io(&cache_dir, source))?;
        let lock_path = cache_dir.join(".lock");
        let start = Instant::now();

        loop {
            let attempt = {
                let _serial = match LOCK_ACQUIRE_SERIAL.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                attempt_lock(&lock_path).map_err(|err| ChipsrcError::io(&lock_path, err))?
            };

            match attempt {
                LockAttempt::Acquired(mut file) | LockAttempt::Reclaimed(mut file) => {
                    let owner_token = new_lock_owner_token();
                    if let Err(source) =
                        std::io::Write::write_all(&mut file, owner_token.as_bytes())
                    {
                        drop(file);
                        let _ = fs::remove_file(&lock_path);
                        return Err(ChipsrcError::io(&lock_path, source));
                    }
                    let (stop_heartbeat, heartbeat) = spawn_lock_heartbeat(
                        lock_path.clone(),
                        owner_token.clone(),
                        LOCK_HEARTBEAT_INTERVAL,
                    );
                    return Ok(Some(Self {
                        path: lock_path,
                        owner_token,
                        handle: Some(file),
                        stop_heartbeat,
                        heartbeat,
                    }));
                }
                LockAttempt::Contended => {
                    let elapsed = start.elapsed();
                    if elapsed >= wait {
                        return Ok(None);
                    }
                    let remaining = wait.saturating_sub(elapsed);
                    std::thread::sleep(LOCK_POLL_INTERVAL.min(remaining));
                }
            }
        }
    }
}

/// Acquires an exclusive advisory bundle lock with a timeout.
pub fn acquire_bundle_lock(out_dir: &Path, wait: Duration) -> Result<Option<BundleLock>> {
    BundleLock::acquire(out_dir, wait)
}

impl Drop for BundleLock {
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat.take() {
            {
                let (mutex, cvar) = &*self.stop_heartbeat;
                let mut stop = match mutex.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *stop = true;
                cvar.notify_all();
            }
            let _ = handle.join();
        }
        drop(self.handle.take());
        let owns_lock =
            fs::read(&self.path).is_ok_and(|contents| contents == self.owner_token.as_bytes());
        if !owns_lock {
            return;
        }
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

/// Returns whether the output directory resides inside the repository.
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

/// Atomically writes bytes to a file using a temporary replacement file.
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
    let tmp_path = temp_sibling_path(path);

    if let Err(source) = fs::write(&tmp_path, bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ChipsrcError::io(path, source));
    }

    rename_with_retry(&tmp_path, path)
}

fn temp_sibling_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bundle");
    let pid = std::process::id();
    let seq = NEXT_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(".{file_name}.{pid}.{seq}.tmp"))
}

fn rename_with_retry(tmp_path: &Path, path: &Path) -> Result<()> {
    const BACKOFF_MS: [u64; 4] = [5, 10, 20, 40];
    let mut last_err = None;
    for attempt in 0..5 {
        match fs::rename(tmp_path, path) {
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

    let _ = fs::remove_file(tmp_path);
    Err(ChipsrcError::io(
        path,
        last_err.unwrap_or_else(|| std::io::Error::other("atomic rename failed")),
    ))
}

const STREAM_ROW_BUFFER_BYTES: usize = 1 << 20;

const IN_MEMORY_STREAM_MAX_BYTES: u64 = 8 * 1024 * 1024;

enum RowTarget<'a> {
    File {
        out: &'a mut HashingWriter<std::io::BufWriter<fs::File>>,
        path: &'a Path,
    },
    Memory {
        bytes: &'a mut Vec<u8>,
    },
}

struct RowSink<'a> {
    target: RowTarget<'a>,
    buf: String,
    path: &'a Path,
}

fn sink_write(
    out: &mut HashingWriter<std::io::BufWriter<fs::File>>,
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    out.inner
        .write_all(bytes)
        .map_err(|e| ChipsrcError::io(path, e))?;
    if let Some(hasher) = out.hasher.as_mut() {
        hasher.update(bytes);
    }
    out.len += bytes.len() as u64;
    Ok(())
}

fn target_write(target: &mut RowTarget<'_>, bytes: &[u8]) -> Result<()> {
    match target {
        RowTarget::File { out, path } => sink_write(out, path, bytes),
        RowTarget::Memory { bytes: buf } => {
            buf.extend_from_slice(bytes);
            Ok(())
        }
    }
}

impl<'a> RowSink<'a> {
    fn rows(&mut self) -> &mut String {
        &mut self.buf
    }

    fn flush_if_full(&mut self) -> Result<()> {
        if self.buf.len() >= STREAM_ROW_BUFFER_BYTES {
            target_write(&mut self.target, self.buf.as_bytes())?;
            self.buf.clear();
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        target_write(&mut self.target, self.buf.as_bytes())?;
        self.buf.clear();
        match &mut self.target {
            RowTarget::File { out, .. } => out
                .inner
                .flush()
                .map_err(|e| ChipsrcError::io(self.path, e)),
            RowTarget::Memory { .. } => Ok(()),
        }
    }
}

struct HashingWriter<W: std::io::Write> {
    inner: W,
    hasher: Option<blake3::Hasher>,
    len: u64,
}

fn write_streamed_file<F>(path: &Path, build: F) -> Result<()>
where
    F: FnOnce(&mut RowSink<'_>) -> Result<()>,
{
    let existing_len = fs::metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.len());

    if let Some(len) = existing_len.filter(|len| *len <= IN_MEMORY_STREAM_MAX_BYTES) {
        let mut bytes: Vec<u8> = Vec::with_capacity(len as usize + 4096);
        {
            let mut sink = RowSink {
                target: RowTarget::Memory { bytes: &mut bytes },
                buf: String::with_capacity(STREAM_ROW_BUFFER_BYTES + 4096),
                path,
            };
            build(&mut sink).and_then(|()| sink.finish())?;
        }
        return write_bytes_atomic(path, &bytes);
    }

    let tmp_path = temp_sibling_path(path);
    let hashing = match fs::File::create(&tmp_path) {
        Ok(file) => HashingWriter {
            inner: std::io::BufWriter::with_capacity(1 << 20, file),
            hasher: existing_len.map(|_| blake3::Hasher::new()),
            len: 0,
        },
        Err(source) => return Err(ChipsrcError::io(&tmp_path, source)),
    };
    let mut hashing = hashing;
    let rendered = {
        let mut sink = RowSink {
            target: RowTarget::File {
                out: &mut hashing,
                path,
            },
            buf: String::with_capacity(STREAM_ROW_BUFFER_BYTES + 4096),
            path,
        };
        build(&mut sink).and_then(|()| sink.finish())
    };
    if let Err(err) = rendered {
        drop(hashing);
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    let HashingWriter {
        hasher,
        len,
        mut inner,
    } = hashing;
    if let (Some(existing_len), Some(hasher)) = (existing_len, hasher) {
        if existing_len == len && file_hash(path).is_some_and(|hash| hash == hasher.finalize()) {
            let _ = fs::remove_file(&tmp_path);
            return Ok(());
        }
    }
    if let Err(source) = inner.flush() {
        drop(inner);
        let _ = fs::remove_file(&tmp_path);
        return Err(ChipsrcError::io(path, source));
    }
    drop(inner);
    rename_with_retry(&tmp_path, path)
}

fn file_hash(path: &Path) -> Option<blake3::Hash> {
    use std::io::Read as _;
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize())
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

/// Deletes stale temporary files in the specified directory.
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

fn write_new_or_existing_file(path: &Path, bytes: &[u8], known_absent: bool) -> Result<()> {
    if known_absent {
        return match fs::write(path, bytes) {
            Ok(()) => Ok(()),
            Err(_) => write_bytes_atomic(path, bytes),
        };
    }
    write_bytes_atomic(path, bytes)
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

/// Sanitizes a string for TSV emission by normalizing whitespace.
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

/// Ensures the bundle directory is ignored in .claudeignore when inside the repo.
pub fn ensure_claudeignore_entry(repo_path: &Path, output_root: &Path) -> Result<bool> {
    let canon_repo = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());
    let canon_out = output_root
        .canonicalize()
        .unwrap_or_else(|_| output_root.to_path_buf());

    let Ok(rel_out) = canon_out.strip_prefix(&canon_repo) else {
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

fn index_tables_parallelizable(index_dir: &Path) -> bool {
    const TABLES: [&str; 6] = [
        "xref.tsv",
        "calls.tsv",
        "symbols.tsv",
        "types.tsv",
        "macros.tsv",
        "sections.tsv",
    ];
    TABLES.iter().all(|name| {
        fs::metadata(index_dir.join(name))
            .is_ok_and(|meta| meta.is_file() && meta.len() <= IN_MEMORY_STREAM_MAX_BYTES)
    })
}

fn join_emit_worker(
    joined: std::thread::Result<Result<()>>,
    index_dir: &Path,
) -> Result<Result<()>> {
    joined.map_err(|_| {
        ChipsrcError::io(
            index_dir,
            std::io::Error::other("bundle emitter worker thread panicked"),
        )
    })
}

/// Source of cache shards for bundle emission.
pub enum CacheShardSource<'a> {
    Prewritten(&'a PrewrittenCache),
    Units(&'a [ParsedFileUnit]),
}

/// Emits the complete codebase bundle.
#[allow(clippy::too_many_arguments)]
pub fn emit_bundle(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    sanity: &SanityReport,
    sections: &[SectionShard],
    indexes: &BundleIndexes,
    cache_source: CacheShardSource<'_>,
    blueprint_hash: &str,
) -> Result<bool> {
    let output_dir = &config.output_dir;
    let sections_dir = output_dir.join("sections");
    let index_dir = output_dir.join("index");

    let fresh_bundle = !sections_dir.is_dir();
    create_dir(output_dir)?;
    create_dir(&sections_dir)?;
    create_dir(&index_dir)?;
    prune_stale_tmp_files_in_dir(&index_dir);

    let mut existing_md: FxHashSet<String> = FxHashSet::default();
    if !fresh_bundle {
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
                    let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if expected_md.contains(name) {
                        existing_md.insert(name.to_string());
                    } else {
                        let _ = fs::remove_file(p);
                    }
                } else if ext == Some("tmp") && is_stale_tmp_file(&p) {
                    let _ = fs::remove_file(p);
                }
            }
        }
    }

    let parallel_tables = index_tables_parallelizable(&index_dir);
    if parallel_tables {
        let mut tail: Option<Result<bool>> = None;
        std::thread::scope(|scope| -> Result<()> {
            let xref = scope.spawn(|| write_xref_tsv_in_memory(&index_dir, indexes));
            let calls = scope.spawn(|| write_calls_tsv_in_memory(&index_dir, indexes));
            let symbols = scope.spawn(|| write_symbols_tsv_in_memory(&index_dir, indexes));
            let small = scope.spawn(|| write_other_small_tsv_files(&index_dir, indexes));
            let docs = scope.spawn(|| {
                write_index_and_sections(
                    config,
                    metadata,
                    sanity,
                    sections,
                    indexes,
                    &sections_dir,
                    &existing_md,
                )
            });
            let graph = scope.spawn(|| {
                let graph_state =
                    build_graph_state(indexes, &metadata.fingerprint, metadata.vendor_mode);
                emit_graph_state(output_dir, &graph_state)
            });
            let parallel_tail = !config.single_file;
            let cache = parallel_tail.then(|| {
                scope.spawn(|| emit_cache_source(config, metadata, blueprint_hash, &cache_source))
            });
            let ignore = parallel_tail
                .then(|| scope.spawn(|| ensure_claudeignore_entry(&config.repo_path, output_dir)));
            join_emit_worker(xref.join(), &index_dir)??;
            join_emit_worker(calls.join(), &index_dir)??;
            join_emit_worker(symbols.join(), &index_dir)??;
            join_emit_worker(small.join(), &index_dir)??;
            join_emit_worker(docs.join(), &index_dir)??;
            join_emit_worker(graph.join(), &index_dir)??;
            if let (Some(cache), Some(ignore)) = (cache, ignore) {
                join_emit_worker(cache.join(), output_dir)??;
                let updated = ignore.join().map_err(|_| {
                    ChipsrcError::io(
                        output_dir,
                        std::io::Error::other("bundle emitter worker thread panicked"),
                    )
                })??;
                tail = Some(Ok(updated));
            }
            Ok(())
        })?;
        if let Some(updated) = tail {
            return updated;
        }
    } else {
        std::thread::scope(|scope| -> Result<()> {
            let docs = scope.spawn(|| {
                write_index_and_sections(
                    config,
                    metadata,
                    sanity,
                    sections,
                    indexes,
                    &sections_dir,
                    &existing_md,
                )
            });
            let tables = (|| -> Result<()> {
                write_xref_tsv_file(&index_dir, indexes)?;
                write_small_tsv_files(&index_dir, indexes)?;
                write_calls_tsv_file(&index_dir, indexes)
            })();
            let docs = join_emit_worker(docs.join(), &sections_dir)?;
            tables?;
            docs?;
            Ok(())
        })?;
        let graph_state = build_graph_state(indexes, &metadata.fingerprint, metadata.vendor_mode);
        emit_graph_state(output_dir, &graph_state)?;
    }

    if config.single_file {
        let index_md = build_master_index_markdown(metadata, sanity, sections, indexes);
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

    emit_cache_source(config, metadata, blueprint_hash, &cache_source)?;

    let claudeignore_updated = ensure_claudeignore_entry(&config.repo_path, output_dir)?;
    Ok(claudeignore_updated)
}

/// Builds the linked graph state structure.
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

/// Atomically writes the linked graph state file.
pub fn emit_graph_state(output_dir: &Path, state: &GraphStateFile) -> Result<()> {
    let cache_dir = output_dir.join("cache");
    create_dir(&cache_dir)?;
    let json = serde_json::to_string(state)?;
    write_bytes_atomic(&cache_dir.join(GRAPH_STATE_FILE), json.as_bytes())
}

/// Loads the linked graph state file if present and valid.
pub fn load_graph_state(bundle_dir: &Path) -> Option<GraphStateFile> {
    let bytes = fs::read(bundle_dir.join("cache").join(GRAPH_STATE_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

const CALLS_TSV_HEADER: &str =
    "caller_id\tcaller_name\tcallee_name\tcallee_id\tfile\tline\ttier\tsection_id\n";
const XREF_TSV_HEADER: &str =
    "symbol\tcategory\trelation\ttarget\tfile\tline\tsection_id\tcontext\n";

fn append_calls_row(buf: &mut String, c: &ResolvedCallEdge) {
    buf.push_str(&sanitize_tsv(&c.caller_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&c.caller_name));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&c.callee_name));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&c.callee_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&c.file));
    buf.push('\t');
    push_usize(buf, c.line);
    buf.push('\t');
    buf.push_str(c.tier.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&c.section_id));
    buf.push('\n');
}

fn append_xref_row(buf: &mut String, x: &XrefEntry) {
    buf.push_str(&sanitize_tsv(&x.symbol));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&x.category));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&x.relation));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&x.target));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&x.file));
    buf.push('\t');
    push_usize(buf, x.line);
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&x.section_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&x.context));
    buf.push('\n');
}

fn build_table_bytes<T, F>(header: &str, rows: &[T], append_row: F) -> Vec<u8>
where
    T: Sync,
    F: Fn(&mut String, &T) + Sync + Send,
{
    const TABLE_BUILD_CHUNKS: usize = 4;
    let chunk_len = rows.len().div_ceil(TABLE_BUILD_CHUNKS);
    let parts: Vec<String> = if chunk_len == 0 {
        Vec::new()
    } else {
        rows.par_chunks(chunk_len)
            .map(|chunk| {
                let mut buf = String::with_capacity(chunk.len() * 128);
                for row in chunk {
                    append_row(&mut buf, row);
                }
                buf
            })
            .collect()
    };
    let body_len: usize = parts.iter().map(|part| part.len()).sum();
    let mut bytes = Vec::with_capacity(header.len() + body_len);
    bytes.extend_from_slice(header.as_bytes());
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
    }
    bytes
}

fn write_calls_tsv_file(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_index_table(
        &index_dir.join("calls.tsv"),
        CALLS_TSV_HEADER,
        &indexes.calls,
        append_calls_row,
        true,
    )
}

fn write_calls_tsv_in_memory(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    let bytes = build_table_bytes(CALLS_TSV_HEADER, &indexes.calls, append_calls_row);
    write_bytes_atomic(&index_dir.join("calls.tsv"), &bytes)
}

fn write_xref_tsv_file(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_index_table(
        &index_dir.join("xref.tsv"),
        XREF_TSV_HEADER,
        &indexes.xrefs,
        append_xref_row,
        true,
    )
}

fn write_xref_tsv_in_memory(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    let bytes = build_table_bytes(XREF_TSV_HEADER, &indexes.xrefs, append_xref_row);
    write_bytes_atomic(&index_dir.join("xref.tsv"), &bytes)
}

const SECTIONS_TSV_HEADER: &str =
    "section_id\ttitle\tmodule_path\tarch_layer\tscope\tfile_count\tsymbol_count\ttype_count\tmacro_count\ttoken_estimate\tmd_file\n";
const SYMBOLS_TSV_HEADER: &str =
    "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\tdoc_summary\thub_score\tauthority_score\n";
const TYPES_TSV_HEADER: &str =
    "type_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tfields_summary\tarch_layer\tscope\tsection_id\tdoc_summary\n";
const MACROS_TSV_HEADER: &str =
    "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription\n";

fn fixed6_scaled(value: f64) -> Option<u64> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return None;
    }
    let bits = value.to_bits();
    let exponent_bits = ((bits >> 52) & 0x7FF) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, exponent) = if exponent_bits == 0 {
        (fraction, -1074i32)
    } else {
        (fraction | (1u64 << 52), exponent_bits - 1075)
    };
    let scaled_exact = (mantissa as u128) * 1_000_000u128;
    if exponent >= 0 {
        if exponent > 74 {
            return Some(u64::MAX);
        }
        return Some((scaled_exact << exponent).min(u128::from(u64::MAX)) as u64);
    }
    let shift = u32::try_from(-exponent).ok()?;
    if shift >= 128 {
        return Some(0);
    }
    if shift > 74 {
        return Some(u64::from(scaled_exact > (1u128 << (shift - 1))));
    }
    let quotient = scaled_exact >> shift;
    let remainder = scaled_exact & ((1u128 << shift) - 1);
    let half = 1u128 << (shift - 1);
    let rounded = if remainder > half {
        quotient + 1
    } else if remainder < half {
        quotient
    } else if quotient & 1 == 1 {
        quotient + 1
    } else {
        quotient
    };
    Some(rounded.min(u128::from(u64::MAX)) as u64)
}

#[inline]
fn push_fixed6(buf: &mut String, value: f64) {
    let Some(scaled) = fixed6_scaled(value) else {
        let _ = write!(buf, "{value:.6}");
        return;
    };
    if scaled == u64::MAX {
        let _ = write!(buf, "{value:.6}");
        return;
    }
    push_usize(buf, (scaled / 1_000_000) as usize);
    buf.push('.');
    let mut frac = scaled % 1_000_000;
    let mut divisor = 100_000u64;
    while divisor > 0 {
        buf.push(char::from(b'0' + ((frac / divisor) % 10) as u8));
        frac %= divisor;
        divisor /= 10;
    }
}

fn append_section_row(buf: &mut String, s: &SectionSummary) {
    buf.push_str(&sanitize_tsv(&s.section_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.title));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.module_path));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.arch_layer));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.scope));
    buf.push('\t');
    push_usize(buf, s.file_count);
    buf.push('\t');
    push_usize(buf, s.symbol_count);
    buf.push('\t');
    push_usize(buf, s.type_count);
    buf.push('\t');
    push_usize(buf, s.macro_count);
    buf.push('\t');
    push_usize(buf, s.token_estimate);
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.md_file));
    buf.push('\n');
}

fn append_symbol_row(buf: &mut String, rs: &RankedSymbol) {
    let s = &rs.symbol;
    buf.push_str(&sanitize_tsv(&s.symbol_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.name));
    buf.push('\t');
    buf.push_str(s.kind.as_str());
    buf.push('\t');
    buf.push_str(s.visibility.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.file));
    buf.push('\t');
    push_usize(buf, s.start_line);
    buf.push('\t');
    push_usize(buf, s.end_line);
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.signature));
    buf.push('\t');
    push_fixed6(buf, rs.pagerank);
    buf.push('\t');
    push_usize(buf, rs.in_degree);
    buf.push('\t');
    push_usize(buf, rs.out_degree);
    buf.push('\t');
    buf.push_str(s.arch_layer.as_str());
    buf.push('\t');
    buf.push_str(s.scope.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.section_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&s.doc_summary));
    buf.push('\t');
    push_fixed6(buf, rs.hub_score);
    buf.push('\t');
    push_fixed6(buf, rs.authority_score);
    buf.push('\n');
}

fn append_type_row(buf: &mut String, t: &ExtractedType) {
    buf.push_str(&sanitize_tsv(&t.type_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&t.name));
    buf.push('\t');
    buf.push_str(t.kind.as_str());
    buf.push('\t');
    buf.push_str(t.visibility.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&t.file));
    buf.push('\t');
    push_usize(buf, t.start_line);
    buf.push('\t');
    push_usize(buf, t.end_line);
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&t.fields_summary));
    buf.push('\t');
    buf.push_str(t.arch_layer.as_str());
    buf.push('\t');
    buf.push_str(t.scope.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&t.section_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&t.doc_summary));
    buf.push('\n');
}

fn append_macro_row(buf: &mut String, m: &ExtractedMacro) {
    buf.push_str(&sanitize_tsv(&m.name));
    buf.push('\t');
    buf.push_str(m.kind.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&m.value_or_args));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(m.hex_addr.as_deref().unwrap_or("-")));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&m.file));
    buf.push('\t');
    push_usize(buf, m.line);
    buf.push('\t');
    buf.push_str(m.arch_layer.as_str());
    buf.push('\t');
    buf.push_str(m.scope.as_str());
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&m.section_id));
    buf.push('\t');
    buf.push_str(&sanitize_tsv(&m.description));
    buf.push('\n');
}

fn write_index_table<T, F>(
    path: &Path,
    header: &str,
    rows: &[T],
    append_row: F,
    parallel_cold: bool,
) -> Result<()>
where
    T: Sync,
    F: Fn(&mut String, &T) + Sync + Send,
{
    let existing_len = fs::metadata(path)
        .ok()
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len());
    if parallel_cold && existing_len.is_none() {
        return write_parallel_table_cold(path, header, rows, append_row);
    }
    write_streamed_file(path, |sink| {
        sink.rows().push_str(header);
        for row in rows {
            append_row(sink.rows(), row);
            sink.flush_if_full()?;
        }
        Ok(())
    })
}

const COLD_TABLE_BATCH_ROWS: usize = 2 * 1024;

const COLD_TABLE_BUFFER_BYTES: usize = 2 * 1024 * 1024;

fn write_parallel_table_cold<T, F>(
    path: &Path,
    header: &str,
    rows: &[T],
    append_row: F,
) -> Result<()>
where
    T: Sync,
    F: Fn(&mut String, &T) + Sync + Send,
{
    let tmp_path = temp_sibling_path(path);
    let file = match fs::File::create(&tmp_path) {
        Ok(file) => file,
        Err(source) => return Err(ChipsrcError::io(&tmp_path, source)),
    };
    let mut hashing = HashingWriter {
        inner: std::io::BufWriter::with_capacity(COLD_TABLE_BUFFER_BYTES, file),
        hasher: None,
        len: 0,
    };

    let rendered = (|| -> Result<()> {
        sink_write(&mut hashing, path, header.as_bytes())?;
        if rows.is_empty() {
            return Ok(());
        }
        let batch_count = rows.len().div_ceil(COLD_TABLE_BATCH_ROWS);
        let window = rayon::current_num_threads().clamp(1, 4);
        let mut start = 0usize;
        while start < batch_count {
            let end = (start + window).min(batch_count);
            let parts: Vec<String> = (start..end)
                .into_par_iter()
                .map(|batch| {
                    let from = batch * COLD_TABLE_BATCH_ROWS;
                    let to = ((batch + 1) * COLD_TABLE_BATCH_ROWS).min(rows.len());
                    let mut buf = String::with_capacity((to - from) * 96 + 256);
                    for row in &rows[from..to] {
                        append_row(&mut buf, row);
                    }
                    buf
                })
                .collect();
            for part in parts {
                sink_write(&mut hashing, path, part.as_bytes())?;
            }
            start = end;
        }
        Ok(())
    })();

    if let Err(err) = rendered {
        drop(hashing);
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    let HashingWriter { mut inner, .. } = hashing;
    if let Err(source) = inner.flush() {
        drop(inner);
        let _ = fs::remove_file(&tmp_path);
        return Err(ChipsrcError::io(path, source));
    }
    drop(inner);
    rename_with_retry(&tmp_path, path)
}

fn write_small_tsv_files(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_index_table(
        &index_dir.join("sections.tsv"),
        SECTIONS_TSV_HEADER,
        &indexes.sections,
        append_section_row,
        false,
    )?;
    write_symbols_tsv(index_dir, indexes)?;
    write_other_small_tsv_files(index_dir, indexes)
}

fn write_symbols_tsv_in_memory(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    let bytes = build_table_bytes(SYMBOLS_TSV_HEADER, &indexes.symbols, append_symbol_row);
    write_bytes_atomic(&index_dir.join("symbols.tsv"), &bytes)
}

fn write_symbols_tsv(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_index_table(
        &index_dir.join("symbols.tsv"),
        SYMBOLS_TSV_HEADER,
        &indexes.symbols,
        append_symbol_row,
        true,
    )
}

fn write_other_small_tsv_files(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_index_table(
        &index_dir.join("sections.tsv"),
        SECTIONS_TSV_HEADER,
        &indexes.sections,
        append_section_row,
        false,
    )?;
    write_index_table(
        &index_dir.join("types.tsv"),
        TYPES_TSV_HEADER,
        &indexes.types,
        append_type_row,
        false,
    )?;
    write_index_table(
        &index_dir.join("macros.tsv"),
        MACROS_TSV_HEADER,
        &indexes.macros,
        append_macro_row,
        true,
    )
}

fn write_index_and_sections(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    sanity: &SanityReport,
    sections: &[SectionShard],
    indexes: &BundleIndexes,
    sections_dir: &Path,
    existing_md: &FxHashSet<String>,
) -> Result<()> {
    let index_md = build_master_index_markdown(metadata, sanity, sections, indexes);
    write_file(&config.output_dir.join("INDEX.md"), &index_md)?;

    let write_shard = |shard: &SectionShard| -> Result<()> {
        let rel_md = shard
            .summary
            .md_file
            .strip_prefix("sections/")
            .unwrap_or(&shard.summary.md_file);
        write_new_or_existing_file(
            &sections_dir.join(rel_md),
            shard.markdown_body.as_bytes(),
            !existing_md.contains(rel_md),
        )
    };
    if !existing_md.is_empty() && sections.len() <= 128 {
        sections.par_iter().try_for_each(write_shard)?;
    } else {
        for shard in sections {
            write_shard(shard)?;
        }
    }
    Ok(())
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

/// Snapshot of existing cache directory entries and previous manifest.
#[derive(Debug, Default)]
pub struct CacheDirState {
    existing_json_files: FxHashSet<String>,
    prev_manifest: Option<CacheManifest>,
}

impl CacheDirState {
    fn scan(cache_dir: &Path) -> Self {
        let mut existing_json_files: FxHashSet<String> = FxHashSet::default();
        if let Ok(entries) = fs::read_dir(cache_dir) {
            for entry in entries.flatten() {
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                if name.ends_with(".json") {
                    existing_json_files.insert(name);
                } else if name.ends_with(".tmp") {
                    let path = entry.path();
                    if is_stale_tmp_file(&path) {
                        let _ = fs::remove_file(path);
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
        Self {
            existing_json_files,
            prev_manifest,
        }
    }
}

/// Prewritten shard identities and cache directory state.
pub struct PrewrittenCache {
    shards: FxHashMap<String, PrewrittenShard>,
    state: CacheDirState,
}

impl PrewrittenCache {
    /// Returns the number of prewritten shards.
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Returns true when no prewritten shards are present.
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// Returns the prewritten shard map.
    pub fn shards(&self) -> &FxHashMap<String, PrewrittenShard> {
        &self.shards
    }
}

/// Emits cache manifest and shard files for an incremental cache.
pub fn emit_cache_shards(output_dir: &Path, cache: &IncrementalAstCache) -> Result<()> {
    emit_cache_shards_with_prewritten(output_dir, cache, &FxHashMap::default())
}

/// Identity and digests of a prewritten cache shard.
#[derive(Debug, Clone)]
pub struct PrewrittenShard {
    pub blake3_hash: String,
    pub shard_name: String,
    pub structural_digest: String,
}

/// Serialized AST cache shard packet prepared for writing.
#[derive(Debug)]
pub struct CacheShardPacket {
    pub rel_path: String,
    pub blake3_hash: String,
    pub shard_name: String,
    pub structural_digest: String,
    pub json: String,
}

/// Serializes a parsed file unit into a cache shard packet.
pub fn prepare_cache_shard(unit: &ParsedFileUnit) -> Option<CacheShardPacket> {
    let rel_path = unit.scanned.rel_path.as_str();
    let hash = unit.scanned.blake3_hash.as_str();
    let json = serde_json::to_string(unit).ok()?;
    Some(CacheShardPacket {
        rel_path: rel_path.to_string(),
        blake3_hash: hash.to_string(),
        shard_name: format!("{}.json", CacheShardEntry::shard_key(rel_path, hash)),
        structural_digest: unit.structural_digest(),
        json,
    })
}

/// Policy controlling cache shard reuse and worker parallelism.
#[derive(Debug, Clone, Default)]
pub struct CacheShardWritePolicy {
    pub reuse_previous: bool,
    pub rewrite: FxHashSet<String>,
    pub background_writer: bool,
}

const CACHE_WRITER_PARALLELISM: usize = 2;

/// Streaming per-file AST cache shard writer.
pub struct CacheShardWriter {
    cache_dir: PathBuf,
    state: CacheDirState,
    policy: CacheShardWritePolicy,
    parallel_pool: Option<rayon::ThreadPool>,
    written: usize,
    reused: usize,
    bytes: usize,
    elapsed: Duration,
}

impl CacheShardWriter {
    /// Opens the cache directory for streaming writes with default reuse policy.
    pub fn new(
        output_dir: &Path,
        schema_version: &str,
        blueprint_hash: &str,
        vendor_mode: VendorMode,
    ) -> Result<Self> {
        Self::new_with_policy(
            output_dir,
            schema_version,
            blueprint_hash,
            vendor_mode,
            &CacheShardWritePolicy {
                reuse_previous: true,
                rewrite: FxHashSet::default(),
                background_writer: false,
            },
        )
    }

    /// Opens the cache directory with an explicit shard write policy.
    pub fn new_with_policy(
        output_dir: &Path,
        schema_version: &str,
        blueprint_hash: &str,
        vendor_mode: VendorMode,
        policy: &CacheShardWritePolicy,
    ) -> Result<Self> {
        let cache_dir = output_dir.join("cache");
        create_dir(&cache_dir)?;

        let mut state = CacheDirState::scan(&cache_dir);
        state.prev_manifest = state.prev_manifest.filter(|m| {
            m.schema_version == schema_version
                && m.blueprint_hash == blueprint_hash
                && m.vendor_mode == vendor_mode
        });

        let parallel_pool = if policy.background_writer {
            let threads = CACHE_WRITER_PARALLELISM
                .min(std::thread::available_parallelism().map_or(1, |n| n.get()))
                .max(1);
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .thread_name(|idx| format!("chipsrc-cache-writer-{idx}"))
                .build()
                .ok()
        } else {
            None
        };

        Ok(Self {
            cache_dir,
            state,
            policy: policy.clone(),
            parallel_pool,
            written: 0,
            reused: 0,
            bytes: 0,
            elapsed: Duration::ZERO,
        })
    }

    fn reusable_digest(&self, rel_path: &str, hash: &str, expected_shard: &str) -> Option<String> {
        if !self.policy.reuse_previous || self.policy.rewrite.contains(rel_path) {
            return None;
        }
        let prev = self.state.prev_manifest.as_ref()?.files.get(rel_path)?;
        if prev.blake3_hash == hash
            && prev.shard == expected_shard
            && !prev.structural_digest.is_empty()
        {
            Some(prev.structural_digest.clone())
        } else {
            None
        }
    }

    /// Serializes and writes cache shards for a batch of parsed units.
    pub fn write_units(
        &mut self,
        units: &[ParsedFileUnit],
    ) -> Result<Vec<(String, PrewrittenShard)>> {
        let started = Instant::now();
        let mut out = Vec::with_capacity(units.len());
        let mut pending: Vec<&ParsedFileUnit> = Vec::new();
        for unit in units {
            let rel_path = unit.scanned.rel_path.as_str();
            let hash = unit.scanned.blake3_hash.as_str();
            let shard_name = format!("{}.json", CacheShardEntry::shard_key(rel_path, hash));
            let expected_shard = format!("cache/{shard_name}");
            let reusable = self.state.existing_json_files.contains(&shard_name);
            match self
                .reusable_digest(rel_path, hash, &expected_shard)
                .filter(|_| reusable)
            {
                Some(structural_digest) => {
                    self.reused += 1;
                    out.push((
                        rel_path.to_string(),
                        PrewrittenShard {
                            blake3_hash: hash.to_string(),
                            shard_name,
                            structural_digest,
                        },
                    ));
                }
                None => pending.push(unit),
            }
        }
        const SERIAL_SERIALIZE_LIMIT: usize = 8;
        let mut packets: Vec<CacheShardPacket> = if pending.len() <= SERIAL_SERIALIZE_LIMIT {
            pending
                .iter()
                .filter_map(|unit| prepare_cache_shard(unit))
                .collect()
        } else {
            pending
                .par_iter()
                .filter_map(|unit| prepare_cache_shard(unit))
                .collect()
        };
        if packets.len() != pending.len() {
            return Err(ChipsrcError::io(
                &self.cache_dir,
                std::io::Error::other("failed to serialize a parsed unit into its AST cache shard"),
            ));
        }
        packets.sort_by(|a, b| a.shard_name.cmp(&b.shard_name));
        for packet in packets {
            let exists = self.state.existing_json_files.contains(&packet.shard_name);
            write_new_or_existing_file(
                &self.cache_dir.join(&packet.shard_name),
                packet.json.as_bytes(),
                !exists,
            )?;
            self.written += 1;
            self.bytes += packet.json.len();
            out.push((
                packet.rel_path,
                PrewrittenShard {
                    blake3_hash: packet.blake3_hash,
                    shard_name: packet.shard_name,
                    structural_digest: packet.structural_digest,
                },
            ));
        }
        self.elapsed += started.elapsed();
        Ok(out)
    }

    fn write_pack(&mut self, units: &[&ParsedFileUnit]) -> Result<Vec<(String, PrewrittenShard)>> {
        let started = Instant::now();
        let parallel_pool = self.parallel_pool.as_ref();
        let shard_name = crate::model::cache_pack_shard_name(units);
        let shard_rel = format!("cache/{shard_name}");
        let exists = self.state.existing_json_files.contains(&shard_name);
        let mut fully_reusable = exists;
        let mut digests: Vec<Option<String>> = Vec::with_capacity(units.len());
        for unit in units {
            let digest = self.reusable_digest(
                &unit.scanned.rel_path,
                &unit.scanned.blake3_hash,
                &shard_rel,
            );
            fully_reusable &= digest.is_some();
            digests.push(digest);
        }
        if fully_reusable {
            self.reused += 1;
        } else {
            let json = serialize_pack_json(units, &self.cache_dir, parallel_pool)?;
            write_new_or_existing_file(
                &self.cache_dir.join(&shard_name),
                json.as_bytes(),
                !exists,
            )?;
            self.written += 1;
            self.bytes += json.len();
        }
        fill_missing_digests(units, &mut digests, parallel_pool);
        let mut out = Vec::with_capacity(units.len());
        for (unit, digest) in units.iter().zip(digests) {
            out.push((
                unit.scanned.rel_path.clone(),
                PrewrittenShard {
                    blake3_hash: unit.scanned.blake3_hash.clone(),
                    shard_name: shard_name.clone(),
                    structural_digest: digest.unwrap_or_default(),
                },
            ));
        }
        self.elapsed += started.elapsed();
        Ok(out)
    }

    /// Returns shard counts, bytes written, and elapsed write duration.
    pub fn stats(&self) -> (usize, usize, usize, Duration) {
        (self.written, self.reused, self.bytes, self.elapsed)
    }
}

/// Serializes and writes cache shards for parsed units.
pub fn write_cache_shards_for_units(
    output_dir: &Path,
    units: &[ParsedFileUnit],
    schema_version: &str,
    blueprint_hash: &str,
    vendor_mode: VendorMode,
) -> Result<PrewrittenCache> {
    write_cache_shards_for_units_with_policy(
        output_dir,
        units,
        schema_version,
        blueprint_hash,
        vendor_mode,
        &CacheShardWritePolicy {
            reuse_previous: true,
            rewrite: FxHashSet::default(),
            background_writer: false,
        },
    )
}

/// Writes cache shards for parsed units using a specified policy.
pub fn write_cache_shards_for_units_with_policy(
    output_dir: &Path,
    units: &[ParsedFileUnit],
    schema_version: &str,
    blueprint_hash: &str,
    vendor_mode: VendorMode,
    policy: &CacheShardWritePolicy,
) -> Result<PrewrittenCache> {
    let mut effective_policy = policy.clone();
    if effective_policy.background_writer && units.len() <= crate::model::CACHE_PACK_FILE_THRESHOLD
    {
        effective_policy.background_writer = false;
    }
    let mut writer = CacheShardWriter::new_with_policy(
        output_dir,
        schema_version,
        blueprint_hash,
        vendor_mode,
        &effective_policy,
    )?;
    let mut available: FxHashMap<String, PrewrittenShard> =
        FxHashMap::with_capacity_and_hasher(units.len(), Default::default());
    if units.len() > crate::model::CACHE_PACK_FILE_THRESHOLD {
        let mut sorted: Vec<&ParsedFileUnit> = units.iter().collect();
        sorted.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));
        let mut start = 0usize;
        while start < sorted.len() {
            let end = (start + crate::model::CACHE_PACK_UNITS).min(sorted.len());
            for (rel_path, shard) in writer.write_pack(&sorted[start..end])? {
                available.insert(rel_path, shard);
            }
            start = end;
        }
    } else {
        let mut start = 0usize;
        while start < units.len() {
            let end = (start + CACHE_SHARD_WRITE_CHUNK).min(units.len());
            for (rel_path, shard) in writer.write_units(&units[start..end])? {
                available.insert(rel_path, shard);
            }
            start = end;
        }
    }
    Ok(PrewrittenCache {
        shards: available,
        state: writer.state,
    })
}

const CACHE_SHARD_WRITE_CHUNK: usize = 256;

const PACK_SERIALIZE_BATCH_UNITS: usize = 16;

fn serialize_pack_json(
    units: &[&ParsedFileUnit],
    cache_dir: &Path,
    pool: Option<&rayon::ThreadPool>,
) -> Result<String> {
    let mut json = String::with_capacity(units.len() * 16 * 1024 + 2);
    json.push('[');
    let mut start = 0usize;
    while start < units.len() {
        let end = (start + PACK_SERIALIZE_BATCH_UNITS).min(units.len());
        let batch = &units[start..end];
        let encode = || -> Vec<Option<String>> {
            batch
                .par_iter()
                .map(|unit| serde_json::to_string(unit).ok())
                .collect()
        };
        let parts = match pool {
            Some(pool) => pool.install(encode),
            None => encode(),
        };
        for (idx, part) in parts.into_iter().enumerate() {
            let Some(text) = part else {
                return Err(ChipsrcError::io(
                    cache_dir,
                    std::io::Error::other(
                        "failed to serialize a parsed unit into its packed AST cache shard",
                    ),
                ));
            };
            if start + idx > 0 {
                json.push(',');
            }
            json.push_str(&text);
        }
        start = end;
    }
    json.push(']');
    Ok(json)
}

fn fill_missing_digests(
    units: &[&ParsedFileUnit],
    digests: &mut [Option<String>],
    pool: Option<&rayon::ThreadPool>,
) {
    let missing: Vec<usize> = digests
        .iter()
        .enumerate()
        .filter_map(|(idx, digest)| digest.is_none().then_some(idx))
        .collect();
    if missing.is_empty() {
        return;
    }
    let compute = || -> Vec<String> {
        missing
            .par_iter()
            .map(|&idx| units[idx].structural_digest())
            .collect()
    };
    let computed = match pool {
        Some(pool) => pool.install(compute),
        None => compute(),
    };
    for (idx, digest) in missing.into_iter().zip(computed) {
        digests[idx] = Some(digest);
    }
}

struct CacheIdentity<'a> {
    schema_version: &'a str,
    repo_root: &'a str,
    vendor_mode: VendorMode,
    fingerprint: &'a str,
    blueprint_hash: &'a str,
}

/// Emits cache shards, reusing prewritten shards where available.
pub fn emit_cache_shards_with_prewritten(
    output_dir: &Path,
    cache: &IncrementalAstCache,
    prewritten: &FxHashMap<String, PrewrittenShard>,
) -> Result<()> {
    let identity = CacheIdentity {
        schema_version: &cache.schema_version,
        repo_root: &cache.repo_root,
        vendor_mode: cache.vendor_mode,
        fingerprint: &cache.fingerprint,
        blueprint_hash: &cache.blueprint_hash,
    };
    let cache_dir = output_dir.join("cache");
    create_dir(&cache_dir)?;
    let state = CacheDirState::scan(&cache_dir);
    emit_cache_manifest(
        output_dir,
        &identity,
        cache.files.iter().map(|(k, v)| (k.as_str(), v)),
        prewritten,
        &state,
    )
}

/// Emits cache shards and manifest for parsed file units.
pub fn emit_cache_shards_for_units(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    units: &[ParsedFileUnit],
    blueprint_hash: &str,
    prewritten: &FxHashMap<String, PrewrittenShard>,
) -> Result<()> {
    let identity = CacheIdentity {
        schema_version: CACHE_SCHEMA_VERSION,
        repo_root: &metadata.source_root,
        vendor_mode: metadata.vendor_mode,
        fingerprint: &metadata.fingerprint,
        blueprint_hash,
    };
    let cache_dir = config.output_dir.join("cache");
    create_dir(&cache_dir)?;
    let state = CacheDirState::scan(&cache_dir);
    emit_cache_manifest(
        &config.output_dir,
        &identity,
        units.iter().map(|u| (u.scanned.rel_path.as_str(), u)),
        prewritten,
        &state,
    )
}

fn emit_cache_source(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    blueprint_hash: &str,
    cache_source: &CacheShardSource<'_>,
) -> Result<()> {
    match cache_source {
        CacheShardSource::Prewritten(cache) => {
            emit_cache_manifest_for_prewritten(config, metadata, blueprint_hash, cache)
        }
        CacheShardSource::Units(units) => emit_cache_shards_for_units(
            config,
            metadata,
            units,
            blueprint_hash,
            &FxHashMap::default(),
        ),
    }
}

/// Emits cache manifest for prewritten shards.
pub fn emit_cache_manifest_for_prewritten(
    config: &ConvertConfig,
    metadata: &RepoMetadata,
    blueprint_hash: &str,
    prewritten: &PrewrittenCache,
) -> Result<()> {
    let identity = CacheIdentity {
        schema_version: CACHE_SCHEMA_VERSION,
        repo_root: &metadata.source_root,
        vendor_mode: metadata.vendor_mode,
        fingerprint: &metadata.fingerprint,
        blueprint_hash,
    };
    let cache_dir = config.output_dir.join("cache");
    create_dir(&cache_dir)?;

    let mut manifest_files: BTreeMap<String, CacheShardEntry> = BTreeMap::new();
    let mut expected_shard_names: FxHashSet<String> =
        FxHashSet::with_capacity_and_hasher(prewritten.shards.len(), Default::default());
    for (rel_path, shard) in &prewritten.shards {
        expected_shard_names.insert(shard.shard_name.clone());
        manifest_files.insert(
            rel_path.clone(),
            CacheShardEntry {
                blake3_hash: shard.blake3_hash.clone(),
                shard: format!("cache/{}", shard.shard_name),
                structural_digest: shard.structural_digest.clone(),
            },
        );
    }

    write_cache_manifest(
        &config.output_dir,
        &cache_dir,
        &identity,
        &prewritten.state,
        manifest_files,
        &expected_shard_names,
    )
}

fn emit_cache_manifest<'a, I>(
    output_dir: &Path,
    identity: &CacheIdentity<'_>,
    units: I,
    prewritten: &FxHashMap<String, PrewrittenShard>,
    state: &CacheDirState,
) -> Result<()>
where
    I: Iterator<Item = (&'a str, &'a ParsedFileUnit)> + ExactSizeIterator,
{
    let cache_dir = output_dir.join("cache");
    create_dir(&cache_dir)?;

    let existing_json_files = &state.existing_json_files;
    let prev_manifest = state.prev_manifest.as_ref();
    let schema_current = prev_manifest.is_some_and(|m| {
        m.schema_version == identity.schema_version
            && m.blueprint_hash == identity.blueprint_hash
            && m.vendor_mode == identity.vendor_mode
    });

    let mut manifest_files: BTreeMap<String, CacheShardEntry> = BTreeMap::new();
    let mut expected_shard_names: FxHashSet<String> =
        FxHashSet::with_capacity_and_hasher(units.len(), Default::default());

    let mut collected: Vec<(&str, &ParsedFileUnit)> = units.collect();
    if collected.len() > crate::model::CACHE_PACK_FILE_THRESHOLD {
        collected.sort_by(|a, b| a.0.cmp(b.0));
        let mut start = 0usize;
        while start < collected.len() {
            let end = (start + crate::model::CACHE_PACK_UNITS).min(collected.len());
            emit_packed_cache_chunk(
                &cache_dir,
                existing_json_files,
                prev_manifest,
                schema_current,
                prewritten,
                &collected[start..end],
                &mut manifest_files,
                &mut expected_shard_names,
            )?;
            start = end;
        }
    } else {
        for (rel_path, unit) in collected {
            let hash = &unit.scanned.blake3_hash;
            let shard_key = CacheShardEntry::shard_key(rel_path, hash);
            let shard_fname = format!("{shard_key}.json");
            let shard_rel = format!("cache/{shard_fname}");

            let pre = prewritten
                .get(rel_path)
                .filter(|p| p.blake3_hash == *hash && p.shard_name == shard_fname);

            let matched_prev = if pre.is_some() {
                None
            } else if schema_current {
                prev_manifest
                    .and_then(|m| m.files.get(rel_path))
                    .filter(|prev| {
                        prev.blake3_hash == *hash
                            && prev.shard == shard_rel
                            && !prev.structural_digest.is_empty()
                    })
            } else {
                None
            };

            let structural_digest = match (pre, matched_prev) {
                (Some(pre), _) => pre.structural_digest.clone(),
                (None, Some(prev)) => prev.structural_digest.clone(),
                (None, None) => unit.structural_digest(),
            };

            let reuse_existing_shard = pre.is_some()
                || (matched_prev.is_some() && existing_json_files.contains(&shard_fname));

            if !reuse_existing_shard {
                let shard_path = cache_dir.join(&shard_fname);
                let unit_json = serde_json::to_string(unit)?;
                write_file(&shard_path, &unit_json)?;
            }

            expected_shard_names.insert(shard_fname);
            manifest_files.insert(
                rel_path.to_string(),
                CacheShardEntry {
                    blake3_hash: hash.clone(),
                    shard: shard_rel,
                    structural_digest,
                },
            );
        }
    }

    write_cache_manifest(
        output_dir,
        &cache_dir,
        identity,
        state,
        manifest_files,
        &expected_shard_names,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_packed_cache_chunk(
    cache_dir: &Path,
    existing_json_files: &FxHashSet<String>,
    prev_manifest: Option<&CacheManifest>,
    schema_current: bool,
    prewritten: &FxHashMap<String, PrewrittenShard>,
    chunk: &[(&str, &ParsedFileUnit)],
    manifest_files: &mut BTreeMap<String, CacheShardEntry>,
    expected_shard_names: &mut FxHashSet<String>,
) -> Result<()> {
    let units: Vec<&ParsedFileUnit> = chunk.iter().map(|(_, unit)| *unit).collect();
    let shard_name = crate::model::cache_pack_shard_name(&units);
    let shard_rel = format!("cache/{shard_name}");
    let exists = existing_json_files.contains(&shard_name);

    let mut digests: Vec<Option<String>> = Vec::with_capacity(chunk.len());
    let mut all_prewritten = true;
    let mut all_previous = schema_current && exists;
    for (rel_path, unit) in chunk {
        let hash = unit.scanned.blake3_hash.as_str();
        let pre = prewritten
            .get(*rel_path)
            .filter(|p| p.blake3_hash == hash && p.shard_name == shard_name);
        all_prewritten &= pre.is_some();
        let prev = prev_manifest
            .and_then(|manifest| manifest.files.get(*rel_path))
            .filter(|p| {
                p.blake3_hash == hash && p.shard == shard_rel && !p.structural_digest.is_empty()
            });
        all_previous &= prev.is_some();
        digests.push(
            pre.map(|p| p.structural_digest.clone())
                .or_else(|| prev.map(|p| p.structural_digest.clone())),
        );
    }

    if !all_prewritten && !all_previous {
        let json = serialize_pack_json(&units, cache_dir, None)?;
        write_file(&cache_dir.join(&shard_name), &json)?;
    }

    fill_missing_digests(&units, &mut digests, None);
    expected_shard_names.insert(shard_name.clone());
    for (idx, (rel_path, unit)) in chunk.iter().enumerate() {
        manifest_files.insert(
            (*rel_path).to_string(),
            CacheShardEntry {
                blake3_hash: unit.scanned.blake3_hash.clone(),
                shard: shard_rel.clone(),
                structural_digest: digests[idx].clone().unwrap_or_default(),
            },
        );
    }
    Ok(())
}

fn write_cache_manifest(
    output_dir: &Path,
    cache_dir: &Path,
    identity: &CacheIdentity<'_>,
    state: &CacheDirState,
    manifest_files: BTreeMap<String, CacheShardEntry>,
    expected_shard_names: &FxHashSet<String>,
) -> Result<()> {
    for existing_name in &state.existing_json_files {
        if existing_name != "manifest.json"
            && existing_name != GRAPH_STATE_FILE
            && !expected_shard_names.contains(existing_name)
        {
            let _ = fs::remove_file(cache_dir.join(existing_name));
        }
    }

    let manifest = CacheManifest {
        schema_version: identity.schema_version.to_string(),
        repo_root: identity.repo_root.to_string(),
        vendor_mode: identity.vendor_mode,
        fingerprint: identity.fingerprint.to_string(),
        blueprint_hash: identity.blueprint_hash.to_string(),
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

pub(crate) fn rewrite_cache_shards_for_dirty_units(
    output_dir: &Path,
    manifest: &mut CacheManifest,
    dirty_units: &[ParsedFileUnit],
) -> Result<bool> {
    let cache_dir = output_dir.join("cache");
    create_dir(&cache_dir)?;

    let mut groups: BTreeMap<String, Vec<&ParsedFileUnit>> = BTreeMap::new();
    for unit in dirty_units {
        let Some(entry) = manifest.files.get(&unit.scanned.rel_path) else {
            return Ok(false);
        };
        groups.entry(entry.shard.clone()).or_default().push(unit);
    }

    let mut loaded_packs: BTreeMap<String, Vec<ParsedFileUnit>> = BTreeMap::new();
    for shard_rel in groups.keys() {
        if crate::model::is_packed_cache_shard(shard_rel) {
            let Some(members) = crate::scanner::load_cache_shard_units(output_dir, shard_rel)
            else {
                return Ok(false);
            };
            loaded_packs.insert(shard_rel.clone(), members);
        }
    }

    let mut superseded_shards: Vec<String> = Vec::new();
    for (old_shard, units) in groups {
        if !crate::model::is_packed_cache_shard(&old_shard) {
            for unit in units {
                let new_hash = &unit.scanned.blake3_hash;
                let shard_name = format!(
                    "{}.json",
                    CacheShardEntry::shard_key(&unit.scanned.rel_path, new_hash)
                );
                let shard_rel = format!("cache/{shard_name}");
                let Some(packet) = prepare_cache_shard(unit) else {
                    return Ok(false);
                };
                write_bytes_atomic(&cache_dir.join(&shard_name), packet.json.as_bytes())?;
                let mut previous = String::new();
                if let Some(entry) = manifest.files.get_mut(&unit.scanned.rel_path) {
                    previous = std::mem::take(&mut entry.shard);
                    entry.blake3_hash = new_hash.clone();
                    entry.shard = shard_rel.clone();
                    entry.structural_digest = packet.structural_digest;
                }
                if !previous.is_empty()
                    && previous != shard_rel
                    && !manifest.files.values().any(|entry| entry.shard == previous)
                {
                    superseded_shards.push(previous);
                }
            }
            continue;
        }

        let Some(mut members) = loaded_packs.remove(&old_shard) else {
            return Ok(false);
        };
        for unit in units {
            match members
                .iter_mut()
                .find(|member| member.scanned.rel_path == unit.scanned.rel_path)
            {
                Some(member) => member.clone_from(unit),
                None => members.push(unit.clone()),
            }
        }
        members.sort_by(|a, b| a.scanned.rel_path.cmp(&b.scanned.rel_path));
        let refs: Vec<&ParsedFileUnit> = members.iter().collect();
        let shard_name = crate::model::cache_pack_shard_name(&refs);
        let shard_rel = format!("cache/{shard_name}");
        let json = serialize_pack_json(&refs, &cache_dir, None)?;
        let target = cache_dir.join(&shard_name);
        let known_absent = !target.is_file();
        write_new_or_existing_file(&target, json.as_bytes(), known_absent)?;
        for member in &members {
            if let Some(entry) = manifest.files.get_mut(&member.scanned.rel_path) {
                entry.blake3_hash = member.scanned.blake3_hash.clone();
                entry.shard = shard_rel.clone();
                entry.structural_digest = member.structural_digest();
            }
        }
        if shard_rel != old_shard
            && !manifest
                .files
                .values()
                .any(|entry| entry.shard == old_shard)
        {
            superseded_shards.push(old_shard);
        }
    }

    for shard_rel in superseded_shards {
        let _ = fs::remove_file(output_dir.join(shard_rel));
    }
    Ok(true)
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
            if let Some(cnt) = enclosing_counts.get_mut(tok) {
                *cnt += 1;
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
