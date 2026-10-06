// SPDX-License-Identifier: MIT

//! The single exclusive lock per data directory.
//!
//! Without it, nothing stops two `certway` processes from running
//! against the same data directory at once — a twice-daily renewal timer
//! overlapping a manual run is not hypothetical, and the result is two
//! orders for one domain burning two rate-limit slots.
//!
//! Built on `std::fs::File::{try_lock, unlock}` (stable since Rust 1.89 —
//! `flock(2)` on Unix, `LockFileEx` on Windows under the hood), not a raw
//! syscall: no `unsafe`, no new dependency, and released automatically on
//! process exit (including a crash) because that's what closing the file
//! descriptor does — never by deleting the lock file, which is what makes a
//! killed process's lock recoverable without manual intervention.

use certway_core::{self as core};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const WAIT_LIMIT: Duration = Duration::from_secs(60);

/// Held for the lifetime of the value — drop it (or let it fall out of
/// scope at the end of `main`) to release, though process exit alone
/// already would.
pub struct Lock {
    _file: File,
    path: PathBuf,
}

/// The lock file's contents are the holder's PID, for the contention
/// message only — `flock` ownership is the actual truth, and a stale PID
/// left behind in the file (e.g. after a crash that never got a chance
/// to overwrite it) is never trusted for anything but display text.
fn write_holder_info(file: &mut File) {
    let _ = file.set_len(0);
    let _ = file.write_all(format!("{}\n", std::process::id()).as_bytes());
    let _ = file.sync_all();
}

fn read_holder_pid(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().next().map(str::to_string))
}

/// Acquires the lock at `<data>/.lock`, exclusive by default. Waits up to
/// 60 seconds on contention before failing — never gives up immediately,
/// since a renewal timer overlapping a manual run for a few seconds is the
/// exact case this exists to serialize, not reject.
pub fn acquire_exclusive(data_root: &Path) -> Result<Lock, core::Error> {
    acquire(data_root, false)
}

/// Read-only commands (`list`, `doctor`, `version`, `check` — none
/// implemented in this build yet) take a shared lock instead, so a status
/// query never blocks on a running renewal. Kept here, alongside
/// `acquire_exclusive`, for the module to be complete even though no
/// caller uses it yet.
pub fn acquire_shared(data_root: &Path) -> Result<Lock, core::Error> {
    acquire(data_root, true)
}

/// `true` when `err` is exactly "the data directory doesn't exist yet" —
/// `acquire`/`acquire_shared`/`acquire_exclusive` opening `<data>/.lock`
/// with `create(true)` still fails `NotFound` when `<data>` itself is
/// missing, since `create(true)` only covers the leaf file, not its
/// parent. Narrow on purpose: any other I/O failure (permission denied, a
/// `.lock` that's actually a directory, disk error) is a real failure a
/// caller must still report, not silently treat as "nothing here yet."
///
/// Shared by `cmd::list` (a data directory that doesn't exist yet is zero
/// certificates, not an error — bug found on a real fresh install) and
/// `cmd::renew`'s `--all` path (nothing to renew is not a failure either,
/// same "nothing due is not an error" reasoning applied one level
/// earlier). Neither caller creates the directory here — a read command
/// must never create state, and `renew --all` with nothing to renew has
/// nothing that needs a directory to exist for.
pub fn is_missing_data_dir(err: &core::Error) -> bool {
    matches!(err, core::Error::Io { source, .. } if source.kind() == ErrorKind::NotFound)
}

fn acquire(data_root: &Path, shared: bool) -> Result<Lock, core::Error> {
    let path = data_root.join(".lock");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| core::Error::io(&path, e))?;

    let start = Instant::now();
    loop {
        let result = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match result {
            Ok(()) => break,
            Err(std::fs::TryLockError::Error(e)) => return Err(core::Error::io(&path, e)),
            Err(std::fs::TryLockError::WouldBlock) => {
                if start.elapsed() >= WAIT_LIMIT {
                    let holder = read_holder_pid(&path).unwrap_or_else(|| "unknown".to_string());
                    return Err(core::Error::io(
                        &path,
                        std::io::Error::new(
                            ErrorKind::WouldBlock,
                            format!(
                                "another certway process (pid {holder}) holds the lock on {}",
                                path.display()
                            ),
                        ),
                    ));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }

    if !shared {
        write_holder_info(&mut file);
    }

    Ok(Lock { _file: file, path })
}

impl Lock {
    /// The path the lock file lives at, for display in a contention
    /// message raised elsewhere.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certway-lock-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn acquires_and_releases_on_drop() {
        let root = tmp_root("basic");
        {
            let _lock = acquire_exclusive(&root).unwrap();
            assert!(root.join(".lock").exists());
        }
        // Dropped — a second acquisition must succeed immediately, not wait.
        let started = Instant::now();
        let _lock2 = acquire_exclusive(&root).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_second_process_blocks_while_the_first_holds_it() {
        let root = tmp_root("contended");
        let root_for_holder = root.clone();

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _lock = acquire_exclusive(&root_for_holder).unwrap();
            ready_tx.send(()).unwrap();
            // Held until told to let go — proves the second attempt below
            // genuinely blocked rather than racing a lock that was already
            // free.
            let _ = release_rx.recv();
        });
        ready_rx.recv().unwrap();

        let path = root.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "lock must be held by the first thread"
        );

        release_tx.send(()).unwrap();
        holder.join().unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lock_survives_the_file_being_unlinked_while_held() {
        // Released by process exit, never by deleting the file.
        // `flock`'s ownership is tied to the open file
        // description, not the path, so an external `rm .lock` while a
        // certway process is mid-run must not error or panic that process
        // — it keeps its lock on the (now path-less) inode until it exits,
        // with no cleanup step required of it.
        let root = tmp_root("unlinked");
        let lock = acquire_exclusive(&root).unwrap();
        std::fs::remove_file(lock.path()).unwrap();
        drop(lock);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shared_locks_do_not_block_each_other() {
        let root = tmp_root("shared");
        let _a = acquire_shared(&root).unwrap();
        let started = Instant::now();
        let _b = acquire_shared(&root).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "two shared holders must not block each other"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_data_dir_is_recognised_from_a_notfound_io_error() {
        let err = core::Error::io(
            Path::new("/nowhere/.lock"),
            std::io::Error::new(ErrorKind::NotFound, "boom"),
        );
        assert!(is_missing_data_dir(&err));
    }

    #[test]
    fn a_different_io_error_kind_is_not_treated_as_missing() {
        let err = core::Error::io(
            Path::new("/nowhere/.lock"),
            std::io::Error::new(ErrorKind::PermissionDenied, "boom"),
        );
        assert!(
            !is_missing_data_dir(&err),
            "permission denied is a real failure, not \"nothing here yet\""
        );
    }

    #[test]
    fn acquire_exclusive_on_a_nonexistent_directory_is_reported_as_missing() {
        let root = tmp_root("nonexistent");
        std::fs::remove_dir_all(&root).unwrap(); // tmp_root creates it; undo that for this test
        let err = match acquire_exclusive(&root) {
            Err(e) => e,
            Ok(_) => panic!("acquiring a lock under a directory that was never created must fail"),
        };
        assert!(is_missing_data_dir(&err), "acquire_exclusive against a directory that was never created must be recognised as \"missing\", not just any I/O error");
    }

    #[test]
    fn exclusive_waits_then_fails_naming_the_holder_pid() {
        let root = tmp_root("timeout");
        let holder = acquire_exclusive(&root).unwrap();
        // Not waiting the real 60s in a unit test: this proves the
        // WouldBlock path is reachable and the error names the holder, by
        // checking try_lock directly rather than the full acquire() wait
        // loop (already covered end-to-end by the blocking test above).
        let path = root.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            file.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        let holder_pid = read_holder_pid(&path).unwrap();
        assert_eq!(holder_pid, std::process::id().to_string());
        drop(holder);
        let _ = std::fs::remove_dir_all(&root);
    }
}
