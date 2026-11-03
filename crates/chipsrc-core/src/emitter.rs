use crate::error::{ChipsrcError, Result};
use crate::model::{
    ArchLayer, BundleIndexes, CacheManifest, CacheShardEntry, ConvertConfig, ExtractedType,
    FileScope, GraphStateFile, GraphSymbolRef, IncrementalAstCache, ParsedFileUnit, RankedSymbol,
    RepoMetadata, ResolvedCallEdge, SanityReport, SectionShard, SymbolGraphState, SymbolKind,
    TypeKind, VendorMode, Visibility, XrefEntry, CACHE_SCHEMA_VERSION, GRAPH_STATE_FILE,
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

/// Advisory lock staleness threshold (`10 s`). Locks older than this are reclaimed automatically.
pub const LOCK_STALE_AFTER: Duration = Duration::from_secs(10);

/// Maximum lock wait budget for background callers (`auto_refresh_bundles`, `hook post-edit`).
pub const LOCK_WAIT_AUTO_SYNC: Duration = Duration::from_millis(150);

/// Maximum lock wait budget for explicit CLI commands (`convert`, `ensure`).
pub const LOCK_WAIT_EXPLICIT: Duration = Duration::from_secs(5);

/// Interval at which a held lock refreshes its `<out>/cache/.lock` mtime/payload so conversions
/// longer than [`LOCK_STALE_AFTER`] are never mistaken for crashed writers.
pub const LOCK_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Poll interval while waiting for a contended (or undeletable stale) lock.
pub const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(15);

/// Stale temporary file threshold (`60 s`). Pruners delete `*.tmp` files older than this.
const STALE_TMP_MAX_AGE: Duration = Duration::from_secs(60);

static NEXT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
static NEXT_LOCK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Signals the lock heartbeat thread to stop (the boolean) and wakes it immediately (`Condvar`).
type LockHeartbeatSignal = Arc<(Mutex<bool>, Condvar)>;

/// Builds the unique owner payload written into `<out>/cache/.lock`: `<pid>:<unix_ms>:<seq>`.
fn new_lock_owner_token() -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let seq = NEXT_LOCK_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{}:{now_ms}:{seq}\n", std::process::id())
}

/// Returns `true` when `err` means the lock file already exists / is held by another process.
fn is_lock_contention_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists
        || err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(5 | 32 | 80 | 183))
}

/// Returns `true` when the lock file at `lock_path` is stale.
///
/// A lock is stale **only** when its file `modified()` mtime is older than
/// [`LOCK_STALE_AFTER`]. The payload timestamp is informational: a live writer refreshes the mtime
/// and payload from its heartbeat thread every [`LOCK_HEARTBEAT_INTERVAL`], so a long conversion
/// keeps a fresh mtime and is never evicted. A lock with a fresh mtime is treated as live even
/// when its payload timestamp is older (e.g. an external writer that only touches the file), and a
/// live owner PID with a fresh mtime is likewise never evicted.
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

/// Rewrites `lock_path` with this lock's owner token when (and only when) the file still carries
/// that token. Returns `false` when another owner has replaced the lock (which stops the
/// heartbeat); a transient write failure keeps the heartbeat alive and is retried on the next tick.
fn refresh_lock_file(lock_path: &Path, owner_token: &str) -> bool {
    match fs::read(lock_path) {
        Ok(contents) if contents == owner_token.as_bytes() => {
            let _ = fs::write(lock_path, owner_token.as_bytes());
            true
        }
        _ => false,
    }
}

/// Signals `stop` and refreshes the lock file until the thread is told to stop.
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
                // Check before waiting too: `Drop` may signal while a refresh is in flight, and
                // the thread must not sleep a full interval after the owner has already left.
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

/// Advisory exclusive bundle lock on `<out>/cache/.lock`.
///
/// Writes a unique `<pid>:<unix_ms>:<seq>` owner token and keeps the file's mtime fresh with a
/// lightweight heartbeat thread while held. `Drop` stops the heartbeat and removes the lock only
/// when its contents still match this lock's owner token (never deleting a replacement lock).
#[derive(Debug)]
pub struct BundleLock {
    path: PathBuf,
    owner_token: String,
    stop_heartbeat: LockHeartbeatSignal,
    heartbeat: Option<JoinHandle<()>>,
}

impl BundleLock {
    /// Attempts to acquire an exclusive advisory lock at `<out_dir>/cache/.lock`, waiting up to
    /// `wait` if another live process holds the lock.
    ///
    /// - Writes `<pid>:<unix_ms>:<seq>\n` using `File::options().write(true).create_new(true)`.
    /// - Reclaims stale locks (mtime `> 10 s` old) immediately.
    /// - Tolerates arbitrary/garbage lock contents by falling back to file mtime.
    /// - Polls at most every [`LOCK_POLL_INTERVAL`] and always honors the `wait` deadline, even when
    ///   a stale lock cannot be deleted (e.g. a Windows `ERROR_SHARING_VIOLATION`).
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
                    let owner_token = new_lock_owner_token();
                    let _ = std::io::Write::write_all(&mut file, owner_token.as_bytes());
                    drop(file);
                    let (stop_heartbeat, heartbeat) = spawn_lock_heartbeat(
                        lock_path.clone(),
                        owner_token.clone(),
                        LOCK_HEARTBEAT_INTERVAL,
                    );
                    return Ok(Some(Self {
                        path: lock_path,
                        owner_token,
                        stop_heartbeat,
                        heartbeat,
                    }));
                }
                Err(err) if is_lock_contention_error(&err) => {
                    if is_lock_stale(&lock_path) && fs::remove_file(&lock_path).is_ok() {
                        continue;
                    }
                    // The lock is live, or a stale lock could not be removed (sharing violation).
                    // Either way the wait budget is authoritative: never spin past the deadline.
                    let elapsed = start.elapsed();
                    if elapsed >= wait {
                        return Ok(None);
                    }
                    let remaining = wait.saturating_sub(elapsed);
                    std::thread::sleep(LOCK_POLL_INTERVAL.min(remaining));
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
    let tmp_path = temp_sibling_path(path);

    if let Err(source) = fs::write(&tmp_path, bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ChipsrcError::io(path, source));
    }

    rename_with_retry(&tmp_path, path)
}

/// Returns `<dir>/.<name>.<pid>.<seq>.tmp`, the temp-file sibling used for atomic writes.
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

/// Renames `tmp_path` over `path`, retrying sharing-violation failures on Windows.
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

/// Bytes of row text accumulated before a streamed table is flushed to its target.
const STREAM_ROW_BUFFER_BYTES: usize = 1 << 20;

/// Largest existing table that is re-rendered in memory and compared byte-for-byte with
/// [`write_bytes_atomic`]. Above this size the table streams straight into a `.tmp` file so a
/// multi-hundred-megabyte `xref.tsv` never has to exist in memory.
const IN_MEMORY_STREAM_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Where a streamed table's rows go.
enum RowTarget<'a> {
    /// Direct `.tmp` file streaming (new or very large targets).
    File {
        out: &'a mut HashingWriter<std::io::BufWriter<fs::File>>,
        path: &'a Path,
    },
    /// In-memory rendering for small existing targets, handed to [`write_bytes_atomic`] which
    /// compares against the file on disk and skips the write when it is unchanged.
    Memory { bytes: &'a mut Vec<u8> },
}

/// Streaming table writer: callers append rows to [`Self::rows`] and call [`Self::flush_if_full`]
/// after each row, so a multi-hundred-megabyte table never has to exist in memory.
struct RowSink<'a> {
    target: RowTarget<'a>,
    buf: String,
    path: &'a Path,
}

/// Appends `bytes` to the row target, keeping the running hash and length in sync.
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

/// Writer that hashes and counts everything written through it.
struct HashingWriter<W: std::io::Write> {
    inner: W,
    /// `None` when the target does not exist yet: a cold build has nothing to compare against, so
    /// hashing ~480 MB of fresh table text would be wasted CPU.
    hasher: Option<blake3::Hasher>,
    len: u64,
}

/// Writes the table produced by `build` to `path` atomically without materializing it in memory.
///
/// Content that is byte-identical to the file already on disk is skipped (the temp file is
/// discarded), matching [`write_bytes_atomic`]'s write-skip semantics.
fn write_streamed_file<F>(path: &Path, build: F) -> Result<()>
where
    F: FnOnce(&mut RowSink<'_>) -> Result<()>,
{
    let existing_len = fs::metadata(path)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.len());

    // A small table that already exists is rendered in memory and compared by
    // `write_bytes_atomic`: on an incremental edit the result is byte-identical, so no `.tmp`
    // file is written, renamed, or compared on disk. A brand-new table or a very large one keeps
    // streaming straight to a `.tmp` file.
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
        // Close the writer (dropping its `BufWriter`) before unlinking the staging file so a
        // Windows sharing violation cannot leave a truncated `*.tmp` behind.
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
    // Flush explicitly instead of `into_inner()` so a flush failure reports the target path and
    // removes the staging file before returning.
    if let Err(source) = inner.flush() {
        drop(inner);
        let _ = fs::remove_file(&tmp_path);
        return Err(ChipsrcError::io(path, source));
    }
    drop(inner);
    rename_with_retry(&tmp_path, path)
}

/// Streams `path` through BLAKE3 and returns the digest, or `None` when it cannot be read.
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

/// Writes `bytes` to `path`, using a direct create for a file that is known to be absent and the
/// full atomic temp-file + rename path otherwise.
///
/// A bundle writer holds the advisory `BundleLock`, so no other process is mutating the bundle
/// while a brand-new artifact is created; `File::create` + `write_all` therefore needs neither the
/// content-compare stat nor the rename round trip. Overwriting an existing file keeps the atomic
/// path so a concurrent reader never observes a truncated artifact.
fn write_new_or_existing_file(path: &Path, bytes: &[u8], known_absent: bool) -> Result<()> {
    if known_absent {
        return match fs::write(path, bytes) {
            Ok(()) => Ok(()),
            // Racing creation (another writer or a leftover file) falls back to the atomic path.
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

/// Returns `true` when every `index/*.tsv` already exists and is small enough that a rebuild is
/// rendered in memory and compared against the file on disk (the incremental-sync steady state).
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

/// Converts an emitter worker thread join result into the bundle's typed I/O error.
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

/// Where `emit_bundle` gets its per-file cache shards.
pub enum CacheShardSource<'a> {
    /// A worker thread already serialized every unit's shard; the manifest is emitted from these
    /// identities, so the caller may drop its parsed units before calling the emitter.
    Prewritten(&'a PrewrittenCache),
    /// Serialize the units here (e.g. the coordinate-shift tier, which has no writer thread).
    Units(&'a [ParsedFileUnit]),
}

/// Emits the Hierarchical Agent Codebase Bundle (`INDEX.md`, `sections/*.md`,
/// `index/*.tsv`, `cache/manifest.json` + `cache/<shard>.json`, optional `<repo_name>.md`,
/// and `.claudeignore`). `meta.json` is written once by `convert_repo` after final timings
/// are recorded.
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

    // A bundle that has no `sections/` directory yet cannot contain stale shards or temp files, so
    // a cold build skips the section-directory listing (a 1.5k-entry directory walk is pure disk
    // latency) and creates every shard directly instead of through the atomic-replace path.
    let fresh_bundle = !sections_dir.is_dir();
    create_dir(output_dir)?;
    create_dir(&sections_dir)?;
    create_dir(&index_dir)?;
    // Always sweep the (small) `index/` directory first: a failed previous streamed table can
    // leave `index/.*.tmp` even when `sections/` is absent. `cache/` is pruned by
    // `CacheDirState::scan`.
    prune_stale_tmp_files_in_dir(&index_dir);

    let mut existing_md: FxHashSet<String> = FxHashSet::default();
    if !fresh_bundle {
        // Clean stale .md files in output_dir/sections/ that are no longer part of `sections`,
        // and prune any stale *.tmp files (>60s) in the bundle root.
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

    // 1. Stream every generated table straight to disk. A 12k-file bundle produces ~480 MB of TSV
    //    text, so no table is ever materialized in memory.
    //    Cold builds write largest-first on a single thread: parallel streams do not help on a
    //    rotational disk (they only add seeks), and the CPU-side formatting is cheap next to the
    //    I/O. Incremental syncs rebuild the same files concurrently instead (see below).
    let parallel_tables = index_tables_parallelizable(&index_dir);
    if parallel_tables {
        // Incremental sync: every table already exists and fits in memory, so it is re-rendered
        // in memory and compared against the file on disk. Their (pure CPU) formatting is
        // independent of each other, of the Markdown docs, and of the linked-graph state, so
        // concurrent rebuilds keep it off the critical path. Cold builds and large corpora keep
        // the single ordered stream, where disk seeks dominate.
        std::thread::scope(|scope| -> Result<()> {
            let xref = scope.spawn(|| write_xref_tsv_in_memory(&index_dir, indexes));
            let calls = scope.spawn(|| write_calls_tsv_in_memory(&index_dir, indexes));
            let small = scope.spawn(|| write_small_tsv_files(&index_dir, indexes));
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
            join_emit_worker(xref.join(), &index_dir)??;
            join_emit_worker(calls.join(), &index_dir)??;
            join_emit_worker(small.join(), &index_dir)??;
            join_emit_worker(docs.join(), &index_dir)??;
            join_emit_worker(graph.join(), &index_dir)??;
            Ok(())
        })?;
    } else {
        write_xref_tsv_file(&index_dir, indexes)?;
        write_small_tsv_files(&index_dir, indexes)?;
        write_calls_tsv_file(&index_dir, indexes)?;
        write_index_and_sections(
            config,
            metadata,
            sanity,
            sections,
            indexes,
            &sections_dir,
            &existing_md,
        )?;
    }

    // Optional <repo_name>.md if config.single_file is true
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

    // Persist the compact linked-graph state used by the coordinate-shift tier. Cold builds write
    // it after the tables it describes; the incremental path wrote it alongside them. A
    // missing/corrupt file only disables the fast path (callers fall back to a full rebuild).
    if !parallel_tables {
        let graph_state = build_graph_state(indexes, &metadata.fingerprint, metadata.vendor_mode);
        emit_graph_state(output_dir, &graph_state)?;
    }

    // The per-file AST cache is already on disk (the writer thread has been joined by the caller);
    // emit the manifest from the identities it recorded, or serialize the units here when the
    // caller has no writer thread (coordinate-shift tier).
    match cache_source {
        CacheShardSource::Prewritten(cache) => {
            emit_cache_manifest_for_prewritten(config, metadata, blueprint_hash, cache)?
        }
        CacheShardSource::Units(units) => emit_cache_shards_for_units(
            config,
            metadata,
            units,
            blueprint_hash,
            &FxHashMap::default(),
        )?,
    }

    // Ensure .claudeignore entry (only when output_dir is inside repo_path)
    ensure_claudeignore_entry(&config.repo_path, output_dir)
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

const CALLS_TSV_HEADER: &str =
    "caller_id\tcaller_name\tcallee_name\tcallee_id\tfile\tline\ttier\tsection_id\n";
const XREF_TSV_HEADER: &str =
    "symbol\tcategory\trelation\ttarget\tfile\tline\tsection_id\tcontext\n";

/// Appends one `index/calls.tsv` row.
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

/// Appends one `index/xref.tsv` row.
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

/// Builds a table in memory, formatting order-preserving row chunks in parallel.
///
/// Only used on the incremental path, where every table fits in memory; row formatting is pure
/// CPU and dominates once the write is skipped as identical.
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

/// Streams `index/calls.tsv`.
fn write_calls_tsv_file(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_streamed_file(&index_dir.join("calls.tsv"), |sink| {
        sink.rows().push_str(CALLS_TSV_HEADER);
        for c in &indexes.calls {
            append_calls_row(sink.rows(), c);
            sink.flush_if_full()?;
        }
        Ok(())
    })
}

/// Rebuilds `index/calls.tsv` in memory with parallel row formatting (incremental syncs).
fn write_calls_tsv_in_memory(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    let bytes = build_table_bytes(CALLS_TSV_HEADER, &indexes.calls, append_calls_row);
    write_bytes_atomic(&index_dir.join("calls.tsv"), &bytes)
}

/// Streams `index/xref.tsv`.
fn write_xref_tsv_file(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_streamed_file(&index_dir.join("xref.tsv"), |sink| {
        sink.rows().push_str(XREF_TSV_HEADER);
        for x in &indexes.xrefs {
            append_xref_row(sink.rows(), x);
            sink.flush_if_full()?;
        }
        Ok(())
    })
}

/// Rebuilds `index/xref.tsv` in memory with parallel row formatting (incremental syncs).
fn write_xref_tsv_in_memory(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    let bytes = build_table_bytes(XREF_TSV_HEADER, &indexes.xrefs, append_xref_row);
    write_bytes_atomic(&index_dir.join("xref.tsv"), &bytes)
}

/// Streams `index/sections.tsv`, `index/symbols.tsv`, `index/types.tsv`, and `index/macros.tsv`.
fn write_small_tsv_files(index_dir: &Path, indexes: &BundleIndexes) -> Result<()> {
    write_streamed_file(&index_dir.join("sections.tsv"), |sink| {
        sink.rows().push_str(
            "section_id\ttitle\tmodule_path\tarch_layer\tscope\tfile_count\tsymbol_count\ttype_count\tmacro_count\ttoken_estimate\tmd_file\n",
        );
        for s in &indexes.sections {
            let _ = writeln!(
                sink.rows(),
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
            sink.flush_if_full()?;
        }
        Ok(())
    })?;

    write_streamed_file(&index_dir.join("symbols.tsv"), |sink| {
        sink.rows().push_str(
            "symbol_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tsignature\tpagerank\tin_deg\tout_deg\tarch_layer\tscope\tsection_id\tdoc_summary\thub_score\tauthority_score\n",
        );
        for rs in &indexes.symbols {
            let s = &rs.symbol;
            let _ = writeln!(
                sink.rows(),
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
            sink.flush_if_full()?;
        }
        Ok(())
    })?;

    write_streamed_file(&index_dir.join("types.tsv"), |sink| {
        sink.rows().push_str(
            "type_id\tname\tkind\tvisibility\tfile\tstart_line\tend_line\tfields_summary\tarch_layer\tscope\tsection_id\tdoc_summary\n",
        );
        for t in &indexes.types {
            let _ = writeln!(
                sink.rows(),
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
            sink.flush_if_full()?;
        }
        Ok(())
    })?;

    write_streamed_file(&index_dir.join("macros.tsv"), |sink| {
        sink.rows().push_str(
            "name\tkind\tvalue_or_args\thex_addr\tfile\tline\tarch_layer\tscope\tsection_id\tdescription\n",
        );
        for m in &indexes.macros {
            let _ = writeln!(
                sink.rows(),
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
            sink.flush_if_full()?;
        }
        Ok(())
    })
}

/// Writes `INDEX.md` and every `sections/*.md` shard.
///
/// `existing_md` holds the shard file names already present after the stale-shard prune, so those
/// writes keep the atomic temp-file path while brand-new shards are created directly.
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

    // Section shards are independent small files, but on a rotational disk concurrent writers lose
    // more to head thrashing than they gain from parallelism (measured: ~8.6 s with two parallel
    // streams vs ~3 s serial for 1.5k shards). One ordered stream keeps the head moving forward.
    for shard in sections {
        let rel_md = shard
            .summary
            .md_file
            .strip_prefix("sections/")
            .unwrap_or(&shard.summary.md_file);
        write_new_or_existing_file(
            &sections_dir.join(rel_md),
            shard.markdown_body.as_bytes(),
            !existing_md.contains(rel_md),
        )?;
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

/// One snapshot of a bundle's `cache/` directory, taken at most once per convert.
///
/// The shard writer and the manifest emitter both need the set of existing shard files and the
/// previous `manifest.json`; sharing this snapshot means a 12k-shard bundle is listed and parsed
/// once instead of twice.
#[derive(Debug, Default)]
pub struct CacheDirState {
    existing_json_files: FxHashSet<String>,
    prev_manifest: Option<CacheManifest>,
}

impl CacheDirState {
    /// Lists `cache/`, pruning stale `*.tmp` files, and parses `manifest.json` when present.
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

/// Shard identities produced by [`write_cache_shards_for_units`], together with the `cache/`
/// snapshot the writer already paid for, so the manifest can be emitted without a second listing.
pub struct PrewrittenCache {
    shards: FxHashMap<String, PrewrittenShard>,
    state: CacheDirState,
}

impl PrewrittenCache {
    /// Number of per-file shards written or reused by the writer.
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Returns `true` when no shard was produced.
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// Shard identities keyed by repository-relative path.
    pub fn shards(&self) -> &FxHashMap<String, PrewrittenShard> {
        &self.shards
    }
}

/// Writes `cache/manifest.json` plus either per-file `cache/<shard_key>.json` shards (repositories
/// with `<= 500` files) or packed `cache/pack-<16hex>.json` shards (larger repositories), deleting
/// orphaned shards and any legacy `cache.json` file.
pub fn emit_cache_shards(output_dir: &Path, cache: &IncrementalAstCache) -> Result<()> {
    emit_cache_shards_with_prewritten(output_dir, cache, &FxHashMap::default())
}

/// Identity of a cache shard that was already written to disk earlier in the same run.
#[derive(Debug, Clone)]
pub struct PrewrittenShard {
    pub blake3_hash: String,
    pub shard_name: String,
    pub structural_digest: String,
}

/// One parsed unit's per-file AST cache shard, prepared on a parse worker (CPU only) so the
/// I/O-bound write can happen on a dedicated writer thread.
#[derive(Debug)]
pub struct CacheShardPacket {
    pub rel_path: String,
    pub blake3_hash: String,
    pub shard_name: String,
    pub structural_digest: String,
    pub json: String,
}

/// Serializes one parsed unit into a [`CacheShardPacket`]. Returns `None` if the unit cannot be
/// serialized; the caller then falls back to the regular cache-shard emission path.
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

/// Controls whether [`CacheShardWriter`] may reuse shards listed by the previous
/// `cache/manifest.json`.
///
/// A full (`--force`) rebuild never reuses a previous shard, and a clean shard that failed to
/// deserialize and had to be reparsed must be rewritten instead of being trusted by hash alone
/// (SYNC-SCRUT-009).
#[derive(Debug, Clone, Default)]
pub struct CacheShardWritePolicy {
    /// When `false`, every shard is re-serialized from its parsed unit.
    pub reuse_previous: bool,
    /// Repository-relative paths that must be re-serialized even when a previous manifest entry
    /// matches their content hash and shard path.
    pub rewrite: FxHashSet<String>,
}

/// Streaming per-file AST cache writer for one bundle.
///
/// Construct once per convert (it lists `cache/` and parses the previous `cache/manifest.json`
/// exactly once), then hand it successive batches of parsed units as they become available. Each
/// [`Self::write_units`] call serializes its batch in parallel (pure CPU) and writes the shards on
/// the calling thread, so the disk sees one sequential stream of small writes.
pub struct CacheShardWriter {
    cache_dir: PathBuf,
    state: CacheDirState,
    policy: CacheShardWritePolicy,
    written: usize,
    reused: usize,
    bytes: usize,
    elapsed: Duration,
}

impl CacheShardWriter {
    /// Opens the bundle's `cache/` directory for streaming writes, reusing shards whose content
    /// hash and shard path already match the previous `cache/manifest.json`.
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
            },
        )
    }

    /// Opens the bundle's `cache/` directory with an explicit shard-reuse policy.
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
        // Only a manifest written by the same schema/blueprint/vendor mode may drive shard reuse.
        state.prev_manifest = state.prev_manifest.filter(|m| {
            m.schema_version == schema_version
                && m.blueprint_hash == blueprint_hash
                && m.vendor_mode == vendor_mode
        });

        Ok(Self {
            cache_dir,
            state,
            policy: policy.clone(),
            written: 0,
            reused: 0,
            bytes: 0,
            elapsed: Duration::ZERO,
        })
    }

    /// Returns the previous manifest's structural digest when the shard can be reused verbatim:
    /// same content hash, same shard path, a persisted digest, and the shard file on disk.
    ///
    /// This is checked before any JSON serialization or structural-digest hashing, so an
    /// incremental sync over 122 unchanged files does no per-unit CPU work at all.
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

    /// Serializes and writes one cache shard per unit (small repositories), returning their
    /// identity keyed by repository-relative path.
    ///
    /// JSON encoding and structural-digest hashing are pure CPU and run in parallel; the
    /// (I/O-bound) file writes stay on this thread so the disk sees one ordered stream.
    pub fn write_units(
        &mut self,
        units: &[ParsedFileUnit],
    ) -> Result<Vec<(String, PrewrittenShard)>> {
        let started = Instant::now();
        let mut out = Vec::with_capacity(units.len());
        let mut pending: Vec<&ParsedFileUnit> = Vec::new();
        // Reuse is decided from the previous manifest alone: no JSON, no digest hashing.
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
        let mut packets: Vec<CacheShardPacket> = pending
            .par_iter()
            .filter_map(|unit| prepare_cache_shard(unit))
            .collect();
        if packets.len() != pending.len() {
            // Every unit must have a shard on disk: the manifest is emitted from these identities
            // after the parsed units are dropped, so a missing shard would silently drop the file.
            return Err(ChipsrcError::io(
                &self.cache_dir,
                std::io::Error::other("failed to serialize a parsed unit into its AST cache shard"),
            ));
        }
        // Hash-named shards land in random order; writing each batch in name order keeps the
        // directory index updates local, which matters for the 12k-file cold path on NTFS.
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

    /// Serializes and writes one packed cache shard holding `units` (large repositories).
    ///
    /// The pack file name is content-addressed over every member's `(rel_path, blake3_hash)`, so a
    /// pack is reused verbatim when no member changed; a pack containing an edit is rewritten once
    /// with all of its siblings.
    fn write_pack(&mut self, units: &[&ParsedFileUnit]) -> Result<Vec<(String, PrewrittenShard)>> {
        let started = Instant::now();
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
            let json = serialize_pack_json(units, &self.cache_dir)?;
            write_new_or_existing_file(
                &self.cache_dir.join(&shard_name),
                json.as_bytes(),
                !exists,
            )?;
            self.written += 1;
            self.bytes += json.len();
        }
        fill_missing_digests(units, &mut digests);
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

    /// Shards written/reused so far and the bytes written; used for `--timings` diagnostics.
    pub fn stats(&self) -> (usize, usize, usize, Duration) {
        (self.written, self.reused, self.bytes, self.elapsed)
    }
}

/// Serializes every parsed unit and writes its cache shard, returning the identity of each shard
/// that is on disk and matches its unit. Callers run this on a dedicated thread so the I/O-bound
/// per-file cache overlaps the CPU-bound link/graph/shard stages instead of extending the critical
/// path, and so the disk only ever sees one sequential stream of small shard writes.
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
        },
    )
}

/// Same as [`write_cache_shards_for_units`] with an explicit shard-reuse policy.
///
/// A full/`--force` rebuild passes `reuse_previous = false`; an incremental sync whose clean
/// shards all loaded intact passes `reuse_previous = true` with an empty `rewrite` set, and a sync
/// that had to reparse a clean shard lists that path in `rewrite` so the unreadable file is
/// replaced instead of being trusted by its manifest hash.
pub fn write_cache_shards_for_units_with_policy(
    output_dir: &Path,
    units: &[ParsedFileUnit],
    schema_version: &str,
    blueprint_hash: &str,
    vendor_mode: VendorMode,
    policy: &CacheShardWritePolicy,
) -> Result<PrewrittenCache> {
    let mut writer = CacheShardWriter::new_with_policy(
        output_dir,
        schema_version,
        blueprint_hash,
        vendor_mode,
        policy,
    )?;
    let mut available: FxHashMap<String, PrewrittenShard> =
        FxHashMap::with_capacity_and_hasher(units.len(), Default::default());
    if units.len() > crate::model::CACHE_PACK_FILE_THRESHOLD {
        // Large repositories use deterministic 64-unit packs: 12.5k tiny files become ~195
        // ~1.3 MB files, which is the difference between minutes and seconds on a rotational disk.
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
        // Serialize in parallel (pure CPU) but write on this single thread so the disk sees one
        // sequential stream instead of a dozen competing ones; the chunk bounds serialized memory.
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

/// Number of units whose cache shards are serialized together before the writer thread writes
/// them; bounds the serialized (JSON) memory held at once.
const CACHE_SHARD_WRITE_CHUNK: usize = 256;

/// Serializes a packed shard as a JSON array of compact [`ParsedFileUnit`]s.
fn serialize_pack_json(units: &[&ParsedFileUnit], cache_dir: &Path) -> Result<String> {
    let parts: Vec<Option<String>> = units
        .par_iter()
        .map(|unit| serde_json::to_string(unit).ok())
        .collect();
    if parts.iter().any(|part| part.is_none()) {
        return Err(ChipsrcError::io(
            cache_dir,
            std::io::Error::other(
                "failed to serialize a parsed unit into its packed AST cache shard",
            ),
        ));
    }
    let total: usize = parts
        .iter()
        .map(|part| part.as_ref().map_or(0, |text| text.len()))
        .sum();
    let mut json = String::with_capacity(total + units.len() + 2);
    json.push('[');
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            json.push(',');
        }
        if let Some(text) = part {
            json.push_str(text);
        }
    }
    json.push(']');
    Ok(json)
}

/// Computes structural digests in parallel for the members that could not be reused.
fn fill_missing_digests(units: &[&ParsedFileUnit], digests: &mut [Option<String>]) {
    let missing: Vec<usize> = digests
        .iter()
        .enumerate()
        .filter_map(|(idx, digest)| digest.is_none().then_some(idx))
        .collect();
    if missing.is_empty() {
        return;
    }
    let computed: Vec<String> = missing
        .par_iter()
        .map(|&idx| units[idx].structural_digest())
        .collect();
    for (idx, digest) in missing.into_iter().zip(computed) {
        digests[idx] = Some(digest);
    }
}

/// Cache identity written into `cache/manifest.json` and used to decide shard reuse.
struct CacheIdentity<'a> {
    schema_version: &'a str,
    repo_root: &'a str,
    vendor_mode: VendorMode,
    fingerprint: &'a str,
    blueprint_hash: &'a str,
}

/// Emits `cache/<shard>.json` for every file in `cache`, trusting shards already written earlier
/// in this run (`prewritten`, keyed by repository-relative path).
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

/// Emits `cache/<shard>.json` + `cache/manifest.json` for a rel_path-sorted unit slice, deriving the
/// cache identity from [`RepoMetadata`]. This is the path used by a full structural rebuild, whose
/// units are already sorted and are not wrapped in an [`IncrementalAstCache`] BTreeMap.
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

/// Emits `cache/manifest.json` for shards that [`write_cache_shards_for_units`] already put on
/// disk, reusing the `cache/` snapshot the writer took. This lets a structural rebuild drop its
/// parsed units before the emitter runs; the manifest carries exactly the parse-time digests.
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
        // Large repositories use deterministic 64-unit packs, grouped over the rel_path-sorted
        // unit set so the layout matches `write_cache_shards_for_units` exactly.
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

            // A shard streamed to disk earlier in this run is authoritative: it was serialized
            // from exactly this unit, so neither the digest nor the file needs to be recomputed.
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

/// Emits one 64-unit packed shard and its manifest entries.
///
/// The pack is skipped when every member is either already on disk from this run's writer
/// (`prewritten`) or unchanged since the previous manifest; otherwise it is serialized once with
/// all of its members and written atomically (identical content is still skipped by
/// [`write_bytes_atomic`]).
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
        let json = serialize_pack_json(&units, cache_dir)?;
        write_file(&cache_dir.join(&shard_name), &json)?;
    }

    fill_missing_digests(&units, &mut digests);
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

/// Prunes orphaned cache shards (using the directory snapshot taken before this run wrote any
/// shard) and writes `cache/manifest.json`, removing the legacy `cache.json` when present.
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

/// Rewrites the cache shards that own `dirty_units` after a digest-noop update (content changed,
/// structural digest, coordinates, and line counts did not), preserving the bundle's canonical
/// shard layout and updating `manifest` entries in place.
///
/// Only the affected 64-unit packs are read and rewritten; every sibling pack is left untouched.
/// Returns `Ok(false)` without modifying anything when an affected pack cannot be read, so the
/// caller can fall back to the full structural rebuild.
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

    // Read every affected packed shard before mutating the manifest, so a missing or corrupt pack
    // leaves the bundle exactly as it was and the caller can take the full structural path.
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
            // A per-file shard (small repository or a pre-pack bundle): rewrite it directly.
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
        let json = serialize_pack_json(&refs, &cache_dir)?;
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
        ExtractedImport, ExtractedMacro, ExtractedSymbol, LanguageKind, ParsedFileUnit,
        RawCallSite, RawXrefSite, ResolutionTier, ScannedFile, SymbolKind, VendorMode, Visibility,
        CACHE_SCHEMA_VERSION,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    /// Builds a minimal parsed unit for cache-shard and packing tests.
    fn cache_unit(rel_path: &str, hash: &str, symbol: &str) -> ParsedFileUnit {
        let owner = rel_path.to_string();
        ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: owner.clone(),
                abs_path: PathBuf::from(rel_path),
                language: LanguageKind::Python,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Domain,
                size_bytes: 64,
                mtime_secs: 1_700_000_000,
                mtime_nanos: 0,
                blake3_hash: hash.to_string(),
                line_count: 2,
            },
            symbols: vec![ExtractedSymbol {
                symbol_id: format!("{owner}::{symbol}"),
                name: symbol.to_string(),
                qualified_name: symbol.to_string(),
                kind: SymbolKind::Function,
                visibility: Visibility::Public,
                file: owner.clone(),
                start_line: 1,
                end_line: 2,
                signature: format!("def {symbol}(value: int) -> int"),
                doc_summary: String::new(),
                enclosing_type: None,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Domain,
                section_id: "mod".to_string(),
            }],
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        }
    }

    /// Builds `count` deterministic parsed units whose rel_paths are spread over seven modules.
    fn cache_units(count: usize) -> Vec<ParsedFileUnit> {
        (0..count)
            .map(|i| {
                let rel_path = format!("mod{:02}/f{i:04}.py", i % 7);
                cache_unit(&rel_path, &format!("hash{i:016}"), &format!("probe_{i}"))
            })
            .collect()
    }

    fn pack_mtimes(cache_dir: &Path) -> BTreeMap<String, SystemTime> {
        let mut mtimes = BTreeMap::new();
        let entries = fs::read_dir(cache_dir).expect("read cache dir");
        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if !name.starts_with("pack-") {
                continue;
            }
            let modified = entry
                .metadata()
                .expect("pack metadata")
                .modified()
                .expect("mtime");
            mtimes.insert(name, modified);
        }
        mtimes
    }

    fn pack_bytes(cache_dir: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut packs = BTreeMap::new();
        for name in pack_mtimes(cache_dir).into_keys() {
            let bytes = fs::read(cache_dir.join(&name)).expect("read pack");
            packs.insert(name, bytes);
        }
        packs
    }

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

    /// Cache shards store the owning path once (the unit's `scanned.rel_path`) instead of once per
    /// entry, and use compact one-letter field names. This test pins the on-disk shape: the path is
    /// omitted from every entry, every other field survives, and load restores the path plus
    /// `symbol_id`.
    #[test]
    fn cache_shard_omits_owning_path_and_restores_it_on_load() {
        let tmp = TestTempDir::new("shard_format");
        let out_dir = tmp.0.join("bundle");
        let rel_path = "src/app.c";

        let unit = ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: rel_path.to_string(),
                abs_path: PathBuf::from(rel_path),
                language: LanguageKind::C,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::App,
                size_bytes: 42,
                mtime_secs: 1_700_000_000,
                mtime_nanos: 7,
                blake3_hash: "abcdefabcdefabcd".to_string(),
                line_count: 3,
            },
            symbols: vec![ExtractedSymbol {
                symbol_id: format!("{rel_path}::main"),
                name: "main".to_string(),
                qualified_name: "main".to_string(),
                kind: SymbolKind::Entrypoint,
                visibility: Visibility::Public,
                file: rel_path.to_string(),
                start_line: 1,
                end_line: 3,
                signature: "int main(void)".to_string(),
                doc_summary: String::new(),
                enclosing_type: None,
                arch_layer: ArchLayer::App,
                scope: FileScope::FirstParty,
                section_id: "01-app".to_string(),
            }],
            types: vec![ExtractedType {
                type_id: "Cfg".to_string(),
                name: "Cfg".to_string(),
                kind: TypeKind::Struct,
                visibility: Visibility::Public,
                file: rel_path.to_string(),
                start_line: 5,
                end_line: 8,
                fields_summary: "a: int".to_string(),
                doc_summary: String::new(),
                arch_layer: ArchLayer::App,
                scope: FileScope::FirstParty,
                section_id: "01-app".to_string(),
            }],
            macros: vec![ExtractedMacro {
                name: "LIMIT".to_string(),
                kind: crate::model::MacroKind::Constant,
                value_or_args: "10".to_string(),
                hex_addr: None,
                file: rel_path.to_string(),
                line: 2,
                arch_layer: ArchLayer::App,
                scope: FileScope::FirstParty,
                section_id: "01-app".to_string(),
                description: "limit".to_string(),
            }],
            imports: vec![ExtractedImport {
                file: rel_path.to_string(),
                line: 1,
                raw_path: "\"cfg.h\"".to_string(),
                imported_names: vec!["Cfg".to_string()],
                is_system: false,
            }],
            raw_calls: vec![RawCallSite {
                caller_file: rel_path.to_string(),
                caller_name: "main".to_string(),
                caller_start_line: 1,
                callee_name: "helper".to_string(),
                receiver_or_qualifier: None,
                call_line: 2,
            }],
            raw_xrefs: vec![RawXrefSite {
                file: rel_path.to_string(),
                line: 2,
                enclosing_symbol: Some("main".to_string()),
                target_name: "LIMIT".to_string(),
                category: "macro_ref".to_string(),
                context: "10".to_string(),
            }],
            parse_errors: 0,
        };

        let digest_before = unit.structural_digest();
        let packet = prepare_cache_shard(&unit).expect("serialize shard");
        let json: serde_json::Value = serde_json::from_str(&packet.json).expect("parse shard");

        // The owning path survives only inside the unit's `scanned` block (`rel_path` + `abs_path`),
        // never on a symbol/type/macro/import/call/xref entry.
        assert_eq!(
            packet.json.matches(rel_path).count(),
            2,
            "owning path must only appear in the scanned block: {}",
            packet.json
        );
        assert!(json["symbols"][0].get("file").is_none());
        assert!(json["symbols"][0].get("symbol_id").is_none());
        assert!(json["types"][0].get("file").is_none());
        assert!(json["macros"][0].get("file").is_none());
        assert!(json["imports"][0].get("file").is_none());
        assert!(json["raw_calls"][0].get("caller_file").is_none());
        assert!(json["raw_xrefs"][0].get("file").is_none());

        let cache_dir = out_dir.join("cache");
        fs::create_dir_all(&cache_dir).expect("create cache dir");
        write_file(&cache_dir.join(&packet.shard_name), &packet.json).expect("write shard");
        let loaded =
            crate::scanner::load_cache_shard(&out_dir, &format!("cache/{}", packet.shard_name))
                .expect("load shard");
        assert_eq!(loaded.scanned.rel_path, rel_path);
        assert_eq!(loaded.symbols.len(), 1);
        assert_eq!(loaded.symbols[0].file, rel_path);
        assert_eq!(loaded.symbols[0].symbol_id, format!("{rel_path}::main"));
        assert_eq!(loaded.symbols[0].start_line, 1);
        assert_eq!(loaded.types[0].file, rel_path);
        assert_eq!(loaded.types[0].fields_summary, "a: int");
        assert_eq!(loaded.macros[0].file, rel_path);
        assert_eq!(loaded.macros[0].value_or_args, "10");
        assert_eq!(loaded.imports[0].file, rel_path);
        assert_eq!(loaded.raw_calls[0].caller_file, rel_path);
        assert_eq!(loaded.raw_calls[0].callee_name, "helper");
        assert_eq!(loaded.raw_xrefs[0].file, rel_path);
        assert_eq!(loaded.raw_xrefs[0].category, "macro_ref");
        assert_eq!(
            loaded.structural_digest(),
            digest_before,
            "digest must ignore the omitted owning path"
        );
    }

    #[test]
    fn write_streamed_file_matches_in_memory_bytes_and_skips_identical_content() {
        let tmp = TestTempDir::new("streamed_tsv");
        let path = tmp.0.join("index").join("demo.tsv");
        fs::create_dir_all(path.parent().unwrap()).expect("create index dir");

        let rows: Vec<(String, usize)> = (0..5_000)
            .map(|i| (format!("symbol_{i}\twith\ttabs"), i * 7))
            .collect();
        let build_reference = || {
            let mut reference = String::new();
            reference.push_str("name\tline\n");
            for (name, line) in &rows {
                reference.push_str(name);
                reference.push('\t');
                push_usize(&mut reference, *line);
                reference.push('\n');
            }
            reference
        };
        let stream = |sink: &mut RowSink<'_>| -> Result<()> {
            sink.rows().push_str("name\tline\n");
            for (name, line) in &rows {
                sink.rows().push_str(name);
                sink.rows().push('\t');
                push_usize(sink.rows(), *line);
                sink.rows().push('\n');
                // Force many flushes through the 1 MB row buffer.
                sink.flush_if_full()?;
            }
            Ok(())
        };

        write_streamed_file(&path, stream).expect("first streamed write");
        assert_eq!(
            fs::read_to_string(&path).expect("read streamed"),
            build_reference(),
            "streamed rows must equal the in-memory reference table"
        );

        // Identical rewrite must be skipped (mtime preserved) and leave no .tmp behind.
        let past = SystemTime::now() - Duration::from_secs(60);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(past)
            .unwrap();
        let mtime_before = fs::metadata(&path).unwrap().modified().unwrap();

        write_streamed_file(&path, stream).expect("identical streamed write");
        assert_eq!(
            mtime_before,
            fs::metadata(&path).unwrap().modified().unwrap(),
            "identical streamed content must not be rewritten"
        );

        // Different, same-length content must be written through.
        let mut changed = rows.clone();
        changed[0].0 = "symbol_X".to_string();
        write_streamed_file(&path, move |sink| -> Result<()> {
            sink.rows().push_str("name\tline\n");
            for (name, line) in &changed {
                sink.rows().push_str(name);
                sink.rows().push('\t');
                push_usize(sink.rows(), *line);
                sink.rows().push('\n');
                sink.flush_if_full()?;
            }
            Ok(())
        })
        .expect("changed streamed write");
        assert!(fs::read_to_string(&path)
            .expect("read changed")
            .contains("symbol_X"));

        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .expect("read index dir")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .tmp files may remain: {leftovers:?}"
        );
    }

    /// Shards streamed during parse must be authoritative: the emitter must not reserialize or
    /// rewrite them, and the manifest must carry the digests computed on the parse side.
    #[test]
    fn emit_cache_shards_trusts_prewritten_shards() {
        let tmp = TestTempDir::new("prewritten_shards");
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

        let units = vec![
            make_unit("a.py", "1111111111111111", "fn_a"),
            make_unit("b.py", "2222222222222222", "fn_b"),
        ];
        let prewritten = write_cache_shards_for_units(
            &out_dir,
            &units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("write_cache_shards_for_units");
        assert_eq!(prewritten.len(), 2);
        for (rel, shard) in prewritten.shards() {
            assert!(
                out_dir.join("cache").join(&shard.shard_name).is_file(),
                "shard for {rel} must be on disk"
            );
        }

        let mut files = BTreeMap::new();
        for unit in &units {
            files.insert(unit.scanned.rel_path.clone(), unit.clone());
        }
        let cache = IncrementalAstCache {
            schema_version: CACHE_SCHEMA_VERSION.to_string(),
            repo_root: "/repo".to_string(),
            vendor_mode: VendorMode::Active,
            fingerprint: "fp".to_string(),
            blueprint_hash: String::new(),
            files,
        };

        // Backdate both shards: a rewrite would refresh the mtime.
        let past = SystemTime::now() - Duration::from_secs(60);
        let mut mtimes_before = Vec::new();
        for shard in prewritten.shards().values() {
            let path = out_dir.join("cache").join(&shard.shard_name);
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(past)
                .unwrap();
            mtimes_before.push(fs::metadata(&path).unwrap().modified().unwrap());
        }

        emit_cache_shards_with_prewritten(&out_dir, &cache, prewritten.shards())
            .expect("emit_cache_shards_with_prewritten");

        for (shard, before) in prewritten.shards().values().zip(&mtimes_before) {
            let path = out_dir.join("cache").join(&shard.shard_name);
            assert_eq!(
                fs::metadata(&path).unwrap().modified().unwrap(),
                *before,
                "prewritten shard must not be rewritten by the emitter"
            );
        }

        let manifest: CacheManifest = serde_json::from_slice(
            &fs::read(out_dir.join("cache").join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        assert_eq!(manifest.files.len(), 2);
        for (rel, shard) in prewritten.shards() {
            assert_eq!(
                manifest.files[rel].structural_digest, shard.structural_digest,
                "manifest must carry the parse-time structural digest for {rel}"
            );
        }
    }

    /// The structural rebuild drops its parsed units before the emitter runs, so the cache manifest
    /// must be reproducible from the writer's identities alone (and prune stale shards from the
    /// pre-run directory snapshot).
    #[test]
    fn emit_cache_manifest_for_prewritten_matches_units_path_and_prunes_orphans() {
        let tmp = TestTempDir::new("manifest_prewritten");
        let out_dir = tmp.0.join("bundle");
        let make_unit = |rel_path: &str, hash: &str| ParsedFileUnit {
            scanned: ScannedFile {
                rel_path: rel_path.to_string(),
                abs_path: PathBuf::from(rel_path),
                language: LanguageKind::Python,
                scope: FileScope::FirstParty,
                arch_layer: ArchLayer::Domain,
                size_bytes: 10,
                mtime_secs: 1_700_000_000,
                mtime_nanos: 0,
                blake3_hash: hash.to_string(),
                line_count: 1,
            },
            symbols: Vec::new(),
            types: Vec::new(),
            macros: Vec::new(),
            imports: Vec::new(),
            raw_calls: Vec::new(),
            raw_xrefs: Vec::new(),
            parse_errors: 0,
        };
        let units = vec![
            make_unit("a.py", "aaaaaaaaaaaaaaaa"),
            make_unit("b.py", "bbbbbbbbbbbbbbbb"),
        ];
        let config = ConvertConfig::new(tmp.0.join("repo"), out_dir.clone());
        let metadata = RepoMetadata {
            repo_name: "bundle".to_string(),
            source_root: tmp.0.display().to_string(),
            fingerprint: "fp".to_string(),
            vendor_mode: VendorMode::Active,
            total_files: 2,
            ..Default::default()
        };

        fs::create_dir_all(out_dir.join("cache")).unwrap();
        let orphan = out_dir.join("cache").join("0123456789abcdef.json");
        fs::write(&orphan, b"{}").unwrap();

        let prewritten = write_cache_shards_for_units(
            &out_dir,
            &units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("write_cache_shards_for_units");
        emit_cache_manifest_for_prewritten(&config, &metadata, "", &prewritten)
            .expect("emit_cache_manifest_for_prewritten");
        assert!(!orphan.exists(), "orphaned shard must be pruned");

        let manifest: CacheManifest = serde_json::from_slice(
            &fs::read(out_dir.join("cache").join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        assert_eq!(manifest.files.len(), 2);
        for (rel, shard) in prewritten.shards() {
            let entry = &manifest.files[rel];
            assert_eq!(entry.blake3_hash, shard.blake3_hash);
            assert_eq!(entry.shard, format!("cache/{}", shard.shard_name));
            assert_eq!(entry.structural_digest, shard.structural_digest);

            assert!(
                out_dir.join(&entry.shard).is_file(),
                "shard for {rel} must be on disk"
            );
        }

        let from_prewritten = manifest;
        emit_cache_shards_for_units(&config, &metadata, &units, "", &FxHashMap::default())
            .expect("emit_cache_shards_for_units");
        let from_units: CacheManifest = serde_json::from_slice(
            &fs::read(out_dir.join("cache").join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        assert_eq!(
            serde_json::to_value(&from_prewritten).unwrap(),
            serde_json::to_value(&from_units).unwrap(),
            "prewritten and unit-based manifests must be identical"
        );
    }

    /// A >500-file repository stores its parsed units in deterministic 64-unit packs that load
    /// back losslessly, and an unchanged rerun reuses every pack without rewriting it.
    #[test]
    fn packed_cache_shards_are_deterministic_and_round_trip() {
        let tmp = TestTempDir::new("packed_round_trip");
        let out_dir = tmp.0.join("bundle");
        let units = cache_units(501);
        let first = write_cache_shards_for_units(
            &out_dir,
            &units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("write packed cache");

        let mut shard_names: BTreeSet<String> = BTreeSet::new();
        for shard in first.shards().values() {
            assert!(
                shard.shard_name.starts_with("pack-"),
                "{}",
                shard.shard_name
            );
            assert!(shard.shard_name.ends_with(".json"), "{}", shard.shard_name);
            assert_eq!(
                shard.shard_name.len(),
                crate::model::CACHE_PACK_PREFIX.len() + 16 + ".json".len()
            );
            shard_names.insert(shard.shard_name.clone());
        }
        let expected_packs = units.len().div_ceil(crate::model::CACHE_PACK_UNITS);
        assert_eq!(shard_names.len(), expected_packs);
        let cache_dir = out_dir.join("cache");
        assert_eq!(pack_mtimes(&cache_dir).len(), expected_packs);

        let metadata = RepoMetadata {
            source_root: "/repo".to_string(),
            vendor_mode: VendorMode::Active,
            ..Default::default()
        };
        let config = ConvertConfig::new(PathBuf::from("/repo"), out_dir.clone());
        emit_cache_manifest_for_prewritten(&config, &metadata, "", &first).expect("manifest");
        let manifest = crate::scanner::load_cache_manifest(&out_dir).expect("load manifest");
        assert_eq!(manifest.files.len(), units.len());
        for entry in manifest.files.values() {
            assert!(crate::model::is_packed_cache_shard(&entry.shard));
            assert!(!entry.structural_digest.is_empty());
            assert!(out_dir.join(&entry.shard).is_file());
        }

        let cache = crate::scanner::load_cache_file(&out_dir).expect("load packed cache");
        assert_eq!(cache.files.len(), units.len());
        let loaded = cache.files.get("mod00/f0000.py").expect("unit 0");
        assert_eq!(loaded.symbols[0].file, "mod00/f0000.py");
        assert_eq!(loaded.symbols[0].symbol_id, "mod00/f0000.py::probe_0");

        // Unchanged rerun: every pack is reused verbatim (mtime preserved, same names).
        let past = SystemTime::now() - Duration::from_secs(60);
        for name in &shard_names {
            fs::File::options()
                .write(true)
                .open(cache_dir.join(name))
                .expect("open pack")
                .set_modified(past)
                .expect("set pack mtime");
        }
        let before = pack_mtimes(&cache_dir);
        let second = write_cache_shards_for_units(
            &out_dir,
            &units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("rewrite packed cache");
        let second_names: BTreeSet<String> = second
            .shards()
            .values()
            .map(|shard| shard.shard_name.clone())
            .collect();
        assert_eq!(shard_names, second_names);
        assert_eq!(
            before,
            pack_mtimes(&cache_dir),
            "unchanged packs must not be rewritten"
        );
    }

    /// Editing one unit rewrites exactly one packed shard and leaves every other pack byte-identical.
    #[test]
    fn packed_cache_shard_rewrite_keeps_sibling_units() {
        let tmp = TestTempDir::new("packed_rewrite");
        let out_dir = tmp.0.join("bundle");
        let units = cache_units(501);
        let first = write_cache_shards_for_units(
            &out_dir,
            &units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("write packed cache");
        let metadata = RepoMetadata {
            source_root: "/repo".to_string(),
            vendor_mode: VendorMode::Active,
            ..Default::default()
        };
        let config = ConvertConfig::new(PathBuf::from("/repo"), out_dir.clone());
        emit_cache_manifest_for_prewritten(&config, &metadata, "", &first).expect("manifest");

        let cache_dir = out_dir.join("cache");
        let before = pack_bytes(&cache_dir);
        let edited_rel = "mod05/f0005.py";
        let old_shard = first.shards()[edited_rel].shard_name.clone();
        let old_file = old_shard.clone();
        let siblings: Vec<String> = first
            .shards()
            .iter()
            .filter(|(rel_path, shard)| {
                shard.shard_name == old_shard && rel_path.as_str() != edited_rel
            })
            .map(|(rel_path, _)| rel_path.clone())
            .collect();
        assert!(!siblings.is_empty(), "pack must contain sibling units");

        let mut edited_units = units.clone();
        let edited = &mut edited_units[5];
        edited.scanned.blake3_hash = "edited_hash_0005".to_string();
        edited.symbols[0].signature = "def probe_5(value: int, scale: int) -> int".to_string();
        let second = write_cache_shards_for_units(
            &out_dir,
            &edited_units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("rewrite packed cache");
        emit_cache_manifest_for_prewritten(&config, &metadata, "", &second).expect("manifest 2");

        let new_shard = second.shards()[edited_rel].shard_name.clone();
        assert_ne!(old_shard, new_shard);
        assert!(
            !cache_dir.join(&old_file).exists(),
            "old pack must be pruned"
        );
        assert!(cache_dir.join(&new_shard).is_file());

        let after = pack_bytes(&cache_dir);
        for (name, bytes) in &before {
            if *name == old_file {
                continue;
            }
            assert_eq!(
                after.get(name),
                Some(bytes),
                "unrelated pack {name} must be untouched"
            );
        }

        let cache = crate::scanner::load_cache_file(&out_dir).expect("reload packed cache");
        assert_eq!(cache.files.len(), units.len());
        let sibling = cache.files.get(&siblings[0]).expect("sibling unit");
        let original = units
            .iter()
            .find(|unit| unit.scanned.rel_path == siblings[0])
            .expect("original sibling");
        assert_eq!(sibling.scanned.blake3_hash, original.scanned.blake3_hash);
        assert_eq!(sibling.symbols[0].name, original.symbols[0].name);
        let reloaded = cache.files.get(edited_rel).expect("edited unit");
        assert_eq!(reloaded.scanned.blake3_hash, "edited_hash_0005");
    }

    /// The digest-noop tier rewrites only the pack that owns the dirty file and repoints every
    /// sibling manifest entry at the rebuilt pack.
    #[test]
    fn rewrite_cache_shards_for_dirty_units_rebuilds_only_the_affected_pack() {
        let tmp = TestTempDir::new("packed_digest_noop");
        let out_dir = tmp.0.join("bundle");
        let units = cache_units(501);
        let first = write_cache_shards_for_units(
            &out_dir,
            &units,
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("write packed cache");
        let metadata = RepoMetadata {
            source_root: "/repo".to_string(),
            vendor_mode: VendorMode::Active,
            ..Default::default()
        };
        let config = ConvertConfig::new(PathBuf::from("/repo"), out_dir.clone());
        emit_cache_manifest_for_prewritten(&config, &metadata, "", &first).expect("manifest");
        let cache_dir = out_dir.join("cache");
        let before = pack_bytes(&cache_dir);

        let mut manifest = crate::scanner::load_cache_manifest(&out_dir).expect("load manifest");
        let edited_rel = "mod05/f0005.py";
        let old_shard = manifest.files[edited_rel].shard.clone();
        let old_file = old_shard
            .strip_prefix("cache/")
            .expect("cache-relative shard")
            .to_string();
        let mut edited = units[5].clone();
        edited.scanned.blake3_hash = "digest_noop_hash_0005".to_string();
        assert!(rewrite_cache_shards_for_dirty_units(
            &out_dir,
            &mut manifest,
            std::slice::from_ref(&edited),
        )
        .expect("rewrite dirty shard"));

        let new_shard = manifest.files[edited_rel].shard.clone();
        assert_ne!(old_shard, new_shard);
        assert!(out_dir.join(&new_shard).is_file());
        assert!(!out_dir.join(&old_shard).exists());

        let after = pack_bytes(&cache_dir);
        for (name, bytes) in &before {
            if *name == old_file {
                continue;
            }
            assert_eq!(
                after.get(name),
                Some(bytes),
                "unrelated pack {name} must be untouched"
            );
        }

        // Every sibling that used the old pack now uses the new one and keeps its digest.
        for unit in &units {
            let rel_path = unit.scanned.rel_path.as_str();
            if rel_path == edited_rel {
                continue;
            }
            let entry = &manifest.files[rel_path];
            if entry.shard == new_shard {
                assert_eq!(entry.structural_digest, unit.structural_digest());
            }
        }
        // The caller persists the updated manifest; do the same before reloading from disk.
        fs::write(
            cache_dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("serialize manifest"),
        )
        .expect("write manifest");
        let cache = crate::scanner::load_cache_file(&out_dir).expect("reload packed cache");
        assert_eq!(cache.files.len(), units.len());
        assert_eq!(
            cache.files[edited_rel].scanned.blake3_hash,
            "digest_noop_hash_0005"
        );
    }

    /// The parallel in-memory table rebuild used on incremental syncs must be byte-identical to
    /// the streamed table writer used on cold builds.
    #[test]
    fn parallel_table_builder_matches_streamed_bytes() {
        let tmp = TestTempDir::new("parallel_tables");
        let index_dir = tmp.0.join("index");
        fs::create_dir_all(&index_dir).expect("create index dir");

        let calls: Vec<ResolvedCallEdge> = (0..97)
            .map(|i| ResolvedCallEdge {
                caller_id: format!("src/mod_{i}.c::caller_{i}"),
                caller_name: format!("caller_{i}"),
                callee_name: format!("callee\t{i}"),
                callee_id: format!("src/mod_{i}.c::callee_{i}"),
                file: format!("src/mod_{i}.c"),
                line: i + 1,
                tier: if i % 3 == 0 {
                    ResolutionTier::ExternalOrMacro
                } else {
                    ResolutionTier::SameFile
                },
                section_id: format!("0{}-mod", i % 7),
            })
            .collect();
        let xrefs: Vec<XrefEntry> = (0..97)
            .map(|i| XrefEntry {
                symbol: format!("symbol_{i}"),
                category: "macro_ref".to_string(),
                relation: "references".to_string(),
                target: format!("TARGET\t{i}"),
                file: format!("src/mod_{i}.c"),
                line: i + 1,
                section_id: format!("0{}-mod", i % 7),
                context: "line\ncontext".to_string(),
            })
            .collect();
        let indexes = BundleIndexes {
            calls,
            xrefs,
            ..Default::default()
        };

        for table in ["xref.tsv", "calls.tsv"] {
            let path = index_dir.join(table);
            write_xref_tsv_file(&index_dir, &indexes).expect("streamed xref");
            write_calls_tsv_file(&index_dir, &indexes).expect("streamed calls");
            let streamed = fs::read(&path).expect("read streamed table");
            fs::remove_file(&path).expect("remove streamed table");
            write_xref_tsv_in_memory(&index_dir, &indexes).expect("in-memory xref");
            write_calls_tsv_in_memory(&index_dir, &indexes).expect("in-memory calls");
            let in_memory = fs::read(&path).expect("read in-memory table");
            assert_eq!(
                in_memory, streamed,
                "{table} must be byte-identical across both writers"
            );
        }
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

    /// SYNC-SCRUT-001: a held lock refreshes its mtime from a heartbeat thread, so a conversion
    /// longer than `LOCK_STALE_AFTER` is never mistaken for a crashed writer.
    #[test]
    fn bundle_lock_heartbeat_keeps_long_held_lock_fresh() {
        let tmp = TestTempDir::new("bundle_lock_heartbeat");
        let out_dir = tmp.0.join("bundle");
        let lock_path = out_dir.join("cache").join(".lock");
        let lock = BundleLock::acquire(&out_dir, Duration::from_millis(100))
            .expect("acquire")
            .expect("lock should be acquired");

        // Backdate the lock past the stale threshold; only the heartbeat can make it fresh again.
        fs::File::options()
            .write(true)
            .open(&lock_path)
            .unwrap()
            .set_modified(SystemTime::now() - LOCK_STALE_AFTER - Duration::from_secs(20))
            .unwrap();
        assert!(is_lock_stale(&lock_path), "backdated lock must look stale");

        std::thread::sleep(LOCK_HEARTBEAT_INTERVAL + Duration::from_millis(800));
        assert!(
            !is_lock_stale(&lock_path),
            "heartbeat must refresh the lock mtime while it is held"
        );
        let payload = fs::read_to_string(&lock_path).expect("read lock payload");
        assert!(
            payload.trim().split(':').count() == 3,
            "lock payload must be <pid>:<unix_ms>:<seq>, got {payload:?}"
        );

        drop(lock);
        assert!(!lock_path.exists(), "Drop must remove the lock");
    }

    /// SYNC-SCRUT-001: a lock with an ancient payload timestamp but a fresh mtime (e.g. an
    /// external writer that only touches the file) must be treated as live.
    #[test]
    fn bundle_lock_fresh_mtime_with_old_payload_is_not_stolen() {
        let tmp = TestTempDir::new("bundle_lock_old_payload");
        let out_dir = tmp.0.join("bundle");
        let lock_path = out_dir.join("cache").join(".lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        let stale_ms = 1_600_000_000_000u128;
        let payload = format!("{}:{stale_ms}:0\n", std::process::id());
        fs::write(&lock_path, &payload).expect("write live lock");

        let acquired = BundleLock::acquire(&out_dir, Duration::from_millis(80))
            .expect("acquire on fresh-mtime lock");
        assert!(
            acquired.is_none(),
            "a lock with a fresh mtime must never be stolen, even with an old payload timestamp"
        );
        assert_eq!(
            fs::read_to_string(&lock_path).unwrap(),
            payload,
            "the live lock contents must be left untouched"
        );
        let _ = fs::remove_file(&lock_path);
    }

    /// SYNC-SCRUT-001: `Drop` never deletes a replacement lock owned by someone else.
    #[test]
    fn bundle_lock_drop_only_removes_its_own_token() {
        let tmp = TestTempDir::new("bundle_lock_token");
        let out_dir = tmp.0.join("bundle");
        let lock_path = out_dir.join("cache").join(".lock");
        let lock = BundleLock::acquire(&out_dir, Duration::from_millis(100))
            .expect("acquire")
            .expect("lock should be acquired");
        let replacement = "424242:1700000000000:7\n";
        fs::write(&lock_path, replacement).expect("replace lock");

        drop(lock);
        assert!(lock_path.is_file(), "a replacement lock must survive Drop");
        assert_eq!(fs::read_to_string(&lock_path).unwrap(), replacement);
        let _ = fs::remove_file(&lock_path);
    }

    /// SYNC-SCRUT-002: an undeletable stale lock cannot make `acquire` spin past its deadline.
    #[cfg(windows)]
    #[test]
    fn bundle_lock_undeletable_stale_lock_honors_wait_deadline() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;

        let tmp = TestTempDir::new("bundle_lock_undeletable");
        let out_dir = tmp.0.join("bundle");
        let lock_path = out_dir.join("cache").join(".lock");
        fs::create_dir_all(lock_path.parent().unwrap()).unwrap();
        fs::write(&lock_path, "999999:1000:0\n").expect("write stale lock");
        fs::File::options()
            .write(true)
            .open(&lock_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(60))
            .unwrap();
        // Hold the file without FILE_SHARE_DELETE: `remove_file` fails with a sharing violation
        // while `metadata` (read attributes) still succeeds.
        let _guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&lock_path)
            .expect("open lock without delete sharing");

        let started = Instant::now();
        let acquired = BundleLock::acquire(&out_dir, Duration::from_millis(300))
            .expect("acquire with undeletable stale lock");
        let elapsed = started.elapsed();
        assert!(
            acquired.is_none(),
            "an undeletable stale lock must not be acquired"
        );
        assert!(
            elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3),
            "acquire must honor its wait deadline instead of spinning (elapsed {elapsed:?})"
        );
        assert!(lock_path.is_file(), "the undeletable lock must remain");
        drop(_guard);
        let _ = fs::remove_file(&lock_path);
    }

    /// SYNC-SCRUT-003: a failing streamed render unlinks its staging `.tmp` file.
    #[test]
    fn write_streamed_file_removes_tmp_when_render_fails() {
        let tmp = TestTempDir::new("stream_fail_cleanup");
        let index_dir = tmp.0.join("index");
        fs::create_dir_all(&index_dir).unwrap();
        let path = index_dir.join("xref.tsv");
        let chunk = "x".repeat(1 << 20);

        let result = write_streamed_file(&path, |sink| -> Result<()> {
            sink.rows().push_str(&chunk);
            sink.flush_if_full()?;
            sink.rows().push_str("row after flush\n");
            Err(ChipsrcError::io(
                &path,
                std::io::Error::other("streamed render failed"),
            ))
        });
        assert!(result.is_err(), "the render error must be returned");
        assert!(!path.exists(), "no target file may be created on error");
        let tmp_files: Vec<String> = fs::read_dir(&index_dir)
            .expect("read index dir")
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(
            tmp_files.is_empty(),
            "a failing streamed render must unlink its .tmp file, found {tmp_files:?}"
        );
    }

    /// SYNC-SCRUT-009: a schema-2.1.0 shard written before the compact rename (long field names)
    /// must deserialize through the serde aliases.
    #[test]
    fn legacy_long_field_name_shard_deserializes_and_restores_paths() {
        let tmp = TestTempDir::new("legacy_shard");
        let out_dir = tmp.0.join("bundle");
        let cache_dir = out_dir.join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        let legacy = r#"{"scanned":{"rel_path":"alpha.py","abs_path":"alpha.py","language":"python","scope":"first_party","arch_layer":"other","size_bytes":64,"mtime_secs":1793717751,"mtime_nanos":248154200,"blake3_hash":"a75f9cdc468a7d5f","line_count":8},"symbols":[{"name":"alpha","qualified_name":"A::alpha","kind":"method","visibility":"public","start_line":1,"end_line":2,"signature":"def alpha(self)","doc_summary":"doc","enclosing_type":"A","scope":"first_party","arch_layer":"other","section_id":"root","file":"alpha.py","symbol_id":"alpha.py::A::alpha"}],"types":[{"type_id":"alpha.py::Cfg","name":"Cfg","kind":"struct","visibility":"public","start_line":3,"end_line":4,"fields_summary":"a: int","doc_summary":"","scope":"first_party","arch_layer":"other","section_id":"root","file":"alpha.py"}],"macros":[{"name":"LIMIT","kind":"constant","value_or_args":"10","hex_addr":null,"file":"alpha.py","line":5,"scope":"first_party","arch_layer":"other","section_id":"root","description":"limit"}],"imports":[{"file":"alpha.py","line":1,"raw_path":"typing","imported_names":["Optional"],"is_system":true}],"raw_calls":[{"caller_file":"alpha.py","caller_name":"alpha","caller_start_line":1,"callee_name":"helper","receiver_or_qualifier":null,"call_line":2}],"raw_xrefs":[{"file":"alpha.py","line":6,"enclosing_symbol":"alpha","target_name":"Cfg","category":"type_ref","context":"x: Cfg = None"}],"parse_errors":0}"#;
        fs::write(cache_dir.join("legacy.json"), legacy).expect("write legacy shard");

        let units = crate::scanner::load_cache_shard_units(&out_dir, "cache/legacy.json")
            .expect("legacy shard must deserialize");
        assert_eq!(units.len(), 1);
        let unit = &units[0];
        assert_eq!(unit.symbols[0].qualified_name, "A::alpha");
        assert_eq!(unit.symbols[0].enclosing_type.as_deref(), Some("A"));
        assert_eq!(unit.symbols[0].file, "alpha.py");
        assert_eq!(unit.symbols[0].symbol_id, "alpha.py::A::alpha");
        assert_eq!(unit.types[0].fields_summary, "a: int");
        assert_eq!(unit.macros[0].value_or_args, "10");
        assert_eq!(unit.imports[0].imported_names, vec!["Optional".to_string()]);
        assert_eq!(unit.raw_calls[0].caller_start_line, 1);
        assert_eq!(unit.raw_calls[0].callee_name, "helper");
        assert_eq!(unit.raw_xrefs[0].target_name, "Cfg");
        assert_eq!(unit.raw_xrefs[0].context, "x: Cfg = None");
    }

    /// SYNC-SCRUT-009: a clean shard listed in the previous manifest is not reused when the
    /// caller reports that it failed to deserialize and had to be reparsed.
    #[test]
    fn cache_writer_rewrites_shards_excluded_by_policy() {
        let tmp = TestTempDir::new("shard_policy");
        let out_dir = tmp.0.join("bundle");
        let unit = cache_unit("src/a.py", "hash-a", "alpha");
        let first = write_cache_shards_for_units(
            &out_dir,
            std::slice::from_ref(&unit),
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
        )
        .expect("initial shard write");
        let shard_name = first
            .shards()
            .get("src/a.py")
            .expect("shard identity")
            .shard_name
            .clone();
        let shard_path = out_dir.join("cache").join(&shard_name);
        fs::write(&shard_path, b"{not valid json").expect("corrupt shard");

        // Default policy would trust the manifest hash and keep the unreadable file.
        let mut rewrite = FxHashSet::default();
        rewrite.insert("src/a.py".to_string());
        write_cache_shards_for_units_with_policy(
            &out_dir,
            std::slice::from_ref(&unit),
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
            &CacheShardWritePolicy {
                reuse_previous: true,
                rewrite,
            },
        )
        .expect("policy rewrite");
        let loaded =
            crate::scanner::load_cache_shard_units(&out_dir, &format!("cache/{shard_name}"))
                .expect("shard must be readable after the policy rewrite");
        assert_eq!(loaded[0].symbols[0].name, "alpha");

        // `reuse_previous = false` (a `--force` rebuild) rewrites every shard as well.
        fs::write(&shard_path, b"{not valid json").expect("corrupt shard again");
        let policy = CacheShardWritePolicy {
            reuse_previous: false,
            ..Default::default()
        };
        write_cache_shards_for_units_with_policy(
            &out_dir,
            std::slice::from_ref(&unit),
            CACHE_SCHEMA_VERSION,
            "",
            VendorMode::Active,
            &policy,
        )
        .expect("force-policy rewrite");
        let loaded =
            crate::scanner::load_cache_shard_units(&out_dir, &format!("cache/{shard_name}"))
                .expect("shard must be readable after a force-policy rewrite");
        assert_eq!(loaded[0].symbols[0].name, "alpha");
    }
}
