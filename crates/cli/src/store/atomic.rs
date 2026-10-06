// SPDX-License-Identifier: MIT

//! Atomic file and directory writes.
//!
//! `atomic_write` is the single most important routine in this crate: a web
//! server may read the files it produces at any instant, including
//! mid-write.

use certway_core::{self as core};
use ring::rand::{SecureRandom, SystemRandom};
use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
#[cfg(test)]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Linux's `O_NOFOLLOW` (`0400000` octal, `asm-generic/fcntl.h`) — constant
/// across every Linux architecture this project targets
/// (`x86_64-unknown-linux-musl`). No safe std API
/// exposes it and the `libc` crate is not on the approved dependency list,
/// so `OpenOptionsExt::custom_flags` (itself a safe method — it just ORs an
/// `i32` into the syscall's flags) carries the hardcoded value. Verified
/// live: opening a dangling symlink with this flag fails
/// `ErrorKind::FilesystemLoop` instead of creating the file at the
/// symlink's target.
const O_NOFOLLOW: i32 = 0o400_000;

pub(crate) fn random_suffix() -> Result<String, core::Error> {
    let mut bytes = [0u8; 8];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        core::Error::io(
            Path::new("<random>"),
            std::io::Error::other("failed to generate randomness for a temp file name"),
        )
    })?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Writes `data` to `path` atomically:
///
/// 1. create `<target>.tmp.<random>` in the same directory, `O_EXCL` +
///    `O_NOFOLLOW`
/// 2. `fchmod` the open handle to `mode` while the file is still empty —
///    neutralises the process umask, which would otherwise mask a
///    requested `0600` down to something group/other-readable
/// 3. write all bytes (short writes are already an error from `write_all`)
/// 4. `fsync` the file
/// 5. `rename` over the target (atomic on POSIX)
/// 6. `fsync` the containing directory
///
/// The temp file is removed on any failure in steps 1-5 so a full disk
/// never accumulates partial files across runs.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<(), core::Error> {
    atomic_write_owned(path, data, mode, None)
}

/// `atomic_write`, plus an optional `(uid, gid)` applied to the temp file
/// *before* the rename — the webserver-config editor's own need (record
/// the original file's owner, restore it on the replacement), not the
/// cert/key writers' (which always want the process's default owner).
/// Chowning before rename, not after, matters: `rename` doesn't inherit
/// the replaced file's ownership — the new inode keeps whatever it was
/// created with — so a chown-after-rename would leave a real, visible
/// window where the file exists with the wrong owner. Kept as a sibling
/// function rather than changing `atomic_write`'s signature so every
/// existing caller (cert/key writes) is untouched.
pub fn atomic_write_owned(
    path: &Path,
    data: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), core::Error> {
    // Resolved once, before computing where the temp sibling and the
    // final rename target live. `rename(2)` replaces a symlink itself
    // rather than writing through it to the file it points at — left
    // unresolved, "atomically write to `path`" silently means "turn
    // `path` from a symlink into an independent copy" the very first
    // time `path` happens to be one. Found live: Debian/Ubuntu's own
    // `sites-enabled -> sites-available` convention (`webserver::nginx`'s
    // whole editing story leans on it) — the *first* edit through
    // `sites-enabled/example.com` replaced that symlink outright, so
    // `sites-available/example.com` (the file Debian's own tooling and
    // the user's own `ls`/`cat` still call "the real config") was
    // permanently orphaned, stale from that point on, while `sites-
    // enabled/` quietly held an independent copy. `canonicalize` only
    // succeeds when `path` already exists — a brand new file (the common
    // cert/key-write case, and every `--none`/first-ever nginx edit) has
    // no symlink to resolve and falls back to `path` as given, unchanged
    // from before this fix.
    let real_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    let dir = real_path.parent().ok_or_else(|| {
        core::Error::io(
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no parent directory",
            ),
        )
    })?;
    let file_name = real_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            core::Error::io(
                path,
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"),
            )
        })?;
    let tmp_path: PathBuf = dir.join(format!(".{file_name}.tmp.{}", random_suffix()?));

    if let Err(e) = write_temp(&tmp_path, data, mode, owner) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp_path, &real_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(core::Error::io(path, e));
    }

    let dir_file = File::open(dir).map_err(|e| core::Error::io(dir, e))?;
    dir_file.sync_all().map_err(|e| core::Error::io(dir, e))?;

    Ok(())
}

fn write_temp(
    tmp_path: &Path,
    data: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), core::Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(tmp_path)
        .map_err(|e| core::Error::io(tmp_path, e))?;

    // Explicit fchmod on the open handle, not a later path-based chmod, and
    // not left to `.mode(mode)` above alone: `OpenOptions::mode` is still
    // masked by the process umask at the syscall level (POSIX
    // `actual = requested & ~umask`), it just happens that a `0600`
    // request survives the common `022`/`027`/`077` umasks unchanged
    // because none of those clear an owner bit. The property this crate
    // must not depend on is the *caller's* umask being one of those common
    // ones — an unusual umask that also masks owner bits (or code that
    // forgets to pass `.mode()` at all, silently falling back to Rust's
    // default create mode of `0o666`) would otherwise leave the file
    // more permissive than intended. `fchmod` on the still-empty handle
    // fixes the mode unconditionally, independent of whatever the caller's
    // umask is.
    f.set_permissions(Permissions::from_mode(mode))
        .map_err(|e| core::Error::io(tmp_path, e))?;

    if let Some((uid, gid)) = owner {
        // `fchown` on the open handle, same reasoning as `set_permissions`
        // above: no path re-resolution, so no TOCTOU window between
        // "the file we created" and "the file we're chowning."
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid))
            .map_err(|e| core::Error::io(tmp_path, e))?;
    }

    f.write_all(data)
        .map_err(|e| core::Error::io(tmp_path, e))?;
    f.sync_all().map_err(|e| core::Error::io(tmp_path, e))?;
    Ok(())
}

/// Creates `dir` (and parents) with `mode` set at creation — used both for
/// the resolved data root and for per-certificate/per-account directories.
/// `DirBuilder::mode` is masked by the umask the same way `OpenOptions::mode`
/// is; unlike a file there is no "still empty" handle to `fchmod` afterwards
/// (a directory has no meaningful "empty" content window — its entries are
/// what would be exposed, and none exist immediately after creation), so a
/// best-effort `set_permissions` follow-up closes that gap too.
pub fn create_dir_secure(dir: &Path, mode: u32) -> Result<(), core::Error> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(dir)
        .map_err(|e| core::Error::io(dir, e))?;
    std::fs::set_permissions(dir, Permissions::from_mode(mode)).map_err(|e| core::Error::io(dir, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certway-atomic-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_secure(&dir, 0o700).unwrap();
        dir
    }

    #[test]
    fn writes_exact_content_and_exact_mode() {
        let dir = tmp_dir("basic");
        let target = dir.join("privkey.pem");
        atomic_write(&target, b"secret", 0o600).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// The bug found live: writing to a path that's a symlink used to
    /// `rename` a new file *over* the symlink, replacing it outright —
    /// exactly what Debian/Ubuntu's `sites-enabled -> sites-available`
    /// convention (`webserver::nginx`'s whole editing story) does not
    /// survive. After this write, `path` must still be a symlink to the
    /// same target, and the *target's* content — not `path` itself — must
    /// carry the new bytes.
    #[cfg(unix)]
    #[test]
    fn atomic_write_owned_writes_through_a_symlink_instead_of_replacing_it() {
        let real_dir = tmp_dir("symlink-real-dir");
        let link_dir = tmp_dir("symlink-link-dir");
        let real_file = real_dir.join("example.com");
        std::fs::write(&real_file, b"old content").unwrap();
        let link_file = link_dir.join("example.com");
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();

        atomic_write(&link_file, b"new content", 0o644).unwrap();

        assert!(
            std::fs::symlink_metadata(&link_file)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must survive the write, not be replaced by a regular file"
        );
        assert_eq!(
            std::fs::read_link(&link_file).unwrap(),
            real_file,
            "the symlink must still point at the same real file"
        );
        assert_eq!(
            std::fs::read(&real_file).unwrap(),
            b"new content",
            "the new content must land in the real file the symlink points at"
        );
    }

    /// Proves the owner-preservation code path actually runs and its
    /// result is observable — `fchown` is called and the written file's
    /// metadata reflects it. Limited to the calling process's own
    /// uid/gid: chowning to a genuinely *different* owner requires root
    /// or `CAP_CHOWN`, which this test environment (and CI) doesn't have,
    /// so this can't prove cross-user preservation end to end — only that
    /// nothing in the code path errors and the syscall's effect is real,
    /// not a no-op. `nginx_e2e`-style container tests (root inside the
    /// container) are where a genuinely different owner gets proven.
    #[test]
    fn atomic_write_owned_sets_the_requested_owner() {
        let dir = tmp_dir("owned");
        let probe = dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        let meta = std::fs::metadata(&probe).unwrap();
        let (uid, gid) = (meta.uid(), meta.gid());

        let target = dir.join("nginx.conf");
        atomic_write_owned(&target, b"server {}", 0o644, Some((uid, gid))).unwrap();
        let target_meta = std::fs::metadata(&target).unwrap();
        assert_eq!(target_meta.uid(), uid);
        assert_eq!(target_meta.gid(), gid);
    }

    #[test]
    fn atomic_write_without_owner_matches_atomic_write_owned_none() {
        let dir = tmp_dir("owner-none-parity");
        let a = dir.join("a");
        let b = dir.join("b");
        atomic_write(&a, b"same", 0o644).unwrap();
        atomic_write_owned(&b, b"same", 0o644, None).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    }

    /// Verifies mode is exactly `0600` under a genuinely hostile process
    /// umask of `0o022`. `std` has no safe way to *set* the calling
    /// process's umask (that's `libc::umask`, unavailable here), so this
    /// re-execs the current test binary as a child of
    /// `sh -c 'umask 022 && exec ...'` — the child process inherits that
    /// umask for real, runs this same test function in "child mode"
    /// (guarded by an env var so it performs the write instead of
    /// re-spawning), and the parent inspects the resulting file's mode.
    ///
    /// Worth noting this test doesn't actually catch the bug it sounds
    /// like it catches: an explicit `.mode(0o600)` alone already survives
    /// the common `0o022` umask unchanged (umask only ever clears bits
    /// that are actually set in the request, and `0o600` has no
    /// group/other bits to clear — verified live against both a raw
    /// `open(2)` call and this exact `OpenOptions` call before writing
    /// this test). The regression this test actually guards against is
    /// code that forgets to request a restrictive mode at all and falls
    /// back to `OpenOptions`'s Unix default create mode of `0o666`.
    /// Commenting out *both* `.mode(mode)` and `set_permissions` in
    /// `write_temp` and rerunning this test under `umask 022` produced
    /// `mode = 0o644` (`0o666 & ~0o022`) — confirming this is a real
    /// regression check, not a tautology that would pass either way.
    /// Both lines were restored before this file was committed.
    #[test]
    fn mode_is_exactly_0600_surviving_a_hostile_umask() {
        const CHILD_ENV: &str = "CERTWAY_ATOMIC_UMASK_CHILD_TARGET";

        if let Ok(target) = std::env::var(CHILD_ENV) {
            atomic_write(Path::new(&target), b"key material", 0o600).unwrap();
            return;
        }

        let dir = tmp_dir("umask");
        let target = dir.join("account.key");
        let exe = std::env::current_exe().expect("current_exe");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "umask 022 && exec {} --exact store::atomic::tests::mode_is_exactly_0600_surviving_a_hostile_umask",
                shell_quote(&exe.to_string_lossy())
            ))
            .env(CHILD_ENV, target.to_string_lossy().to_string())
            .status()
            .expect("spawn sh to run the child under umask 022");
        assert!(status.success(), "child write under umask 0o022 failed");

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "temp file's fchmod must survive a 0o022 umask");
    }

    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }

    #[test]
    fn temp_file_removed_on_write_failure() {
        // Writing into a directory that does not exist fails at open time,
        // before any temp file is created — nothing to clean up, and no
        // panic.
        let missing = std::env::temp_dir()
            .join("certway-atomic-does-not-exist")
            .join("x.pem");
        assert!(atomic_write(&missing, b"data", 0o600).is_err());
    }

    /// A stronger version of the same cleanup rule: this time the temp
    /// file *is* successfully created, written, and fsync'd — it is `rename`
    /// itself that fails (renaming a regular file over an existing
    /// directory is always rejected). The temp file must still not survive
    /// the failure.
    #[test]
    fn temp_file_removed_when_rename_target_is_a_directory() {
        let dir = tmp_dir("rename-fail");
        let target = dir.join("privkey.pem");
        std::fs::create_dir(&target).unwrap();

        let result = atomic_write(&target, b"data", 0o600);
        assert!(
            result.is_err(),
            "renaming a file over an existing directory must fail"
        );

        let leftover: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(
            leftover.is_empty(),
            "no temp file must be left behind after a failed rename: {leftover:?}"
        );
    }

    #[test]
    fn a_symlinked_temp_path_is_refused() {
        let dir = tmp_dir("symlink");
        let target = dir.join("privkey.pem");
        let real_tmp_target = dir.join("attacker-controlled");

        // Pre-create the target with the exact final filename our writer
        // uses is impossible (the suffix is random per call), so this
        // exercises the underlying protection directly: any temp-shaped
        // dangling symlink in the directory must never be followed and
        // written through.
        let evil_tmp = dir.join(format!(".{}.tmp.deadbeefdeadbeef", "privkey.pem"));
        std::os::unix::fs::symlink(&real_tmp_target, &evil_tmp).unwrap();

        // atomic_write always picks its own random suffix, so it will not
        // collide with `evil_tmp` above — this directly proves the O_EXCL +
        // O_NOFOLLOW open primitive refuses a pre-planted symlink at a path
        // it *does* try to use, by attempting the open against that exact
        // path the way `write_temp` does.
        let result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&evil_tmp);
        assert!(
            result.is_err(),
            "a pre-planted symlink at the temp path must be refused, not followed"
        );
        assert!(
            !real_tmp_target.exists(),
            "the symlink's target must never be created"
        );

        // And a normal write to the real target still succeeds and is
        // unaffected by the planted symlink sitting alongside it.
        atomic_write(&target, b"real key", 0o600).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"real key");
    }

    #[test]
    fn create_dir_secure_sets_exact_mode_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("certway-dir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_secure(&dir, 0o700).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // Second call on an already-existing directory must not error.
        create_dir_secure(&dir, 0o700).unwrap();
    }
}
