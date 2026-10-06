// SPDX-License-Identifier: MIT

//! Path resolution (`ref/fhs-3.0.md`, `ref/xdg-base-directory-0.8.md`).
//!
//! Three roles, each resolved independently, stopping at the first source
//! that yields a usable path:
//!
//! ```text
//! 1. explicit flag (--out for data, --config-dir for config)
//! 2. CERTWAY_DATA_DIR / CERTWAY_CONFIG_DIR (no such override exists for
//!    log — only two env vars are defined for three roles; implemented
//!    exactly as specified)
//! 3. uid 0 -> the FHS path
//! 4. the XDG variable, if set to a non-empty absolute path
//! 5. $HOME, if set and non-empty, joined with the XDG default subpath
//! 6. fail, naming every source that was tried
//! ```
//!
//! Only Unix targets are implemented — the single build target is
//! `x86_64-unknown-linux-musl`; macOS/Windows path variants are out of
//! scope for this crate today.

use certway_core::{self as core};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Config,
    Data,
    Log,
}

impl Role {
    fn fhs_root(self) -> &'static str {
        match self {
            Role::Config => "/etc/certway",
            Role::Data => "/var/lib/certway",
            Role::Log => "/var/log/certway",
        }
    }

    /// `None` for `Log`: only `CERTWAY_CONFIG_DIR` / `CERTWAY_DATA_DIR`
    /// exist as override variables — no third variable is defined for the
    /// log role. Read literally, not extended by analogy.
    fn env_override(self) -> Option<&'static str> {
        match self {
            Role::Config => Some("CERTWAY_CONFIG_DIR"),
            Role::Data => Some("CERTWAY_DATA_DIR"),
            Role::Log => None,
        }
    }

    fn xdg_var(self) -> &'static str {
        match self {
            Role::Config => "XDG_CONFIG_HOME",
            Role::Data => "XDG_DATA_HOME",
            Role::Log => "XDG_STATE_HOME",
        }
    }

    fn xdg_default_subpath(self) -> &'static str {
        match self {
            Role::Config => ".config",
            Role::Data => ".local/share",
            Role::Log => ".local/state",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Role::Config => "config",
            Role::Data => "data",
            Role::Log => "log",
        }
    }
}

/// `true` when running with an effective uid of 0. No safe std API exposes
/// `geteuid`, and neither `unsafe` FFI nor a new dependency is available,
/// so this reads the kernel-provided `/proc/self/status` — present in
/// any Linux mount namespace regardless of the container
/// image's own contents, unlike `/etc/passwd`, which this function never
/// touches. Fails closed (reports unprivileged) if `/proc` is unavailable,
/// which is the safe direction: it means falling back to an XDG path rather
/// than writing to `/etc` or `/var/lib` without actually having root.
pub(crate) fn running_as_root() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    parse_effective_uid(&status)
        .map(|euid| euid == 0)
        .unwrap_or(false)
}

/// Pulls the effective uid out of `/proc/self/status`'s `Uid:` line, a pure
/// function so the parsing itself is unit-testable without actually running
/// as root. Format: `"Uid:\t<real>\t<effective>\t<saved-set>\t<filesystem>"`
/// — the effective uid is what governs filesystem access, so it's the field
/// this reads, not the real uid at index 0.
fn parse_effective_uid(status_text: &str) -> Option<u32> {
    status_text
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// A non-empty environment variable value, treating an empty string the
/// same as unset (`ref/xdg-base-directory-0.8.md`'s `unset-equals-empty`
/// rule, applied here to every env-derived input for consistency).
fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The XDG base directory for `var`, applying the spec's rule that a
/// relative value is invalid and must be treated as though the variable
/// were unset (`ref/xdg-base-directory-0.8.md`, `absolute-path-required`).
fn xdg_home(var: &str) -> Option<PathBuf> {
    let value = nonempty_env(var)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

/// What was tried and why it didn't yield a path, for the final failure
/// message ("fail, naming every path that was tried"). Kept as prose
/// fragments rather than `PathBuf`s because several
/// steps (uid check, unset env vars) never produce a candidate path to name
/// in the first place.
fn attempted(role: Role, explicit_flag: &'static str) -> Vec<String> {
    let mut tried = vec![format!("{explicit_flag} (not given)")];
    if let Some(env_name) = role.env_override() {
        tried.push(format!("{env_name} (not set)"));
    }
    tried.push("not running as uid 0".to_string());
    tried.push(format!("{} (not set)", role.xdg_var()));
    tried.push("$HOME (not set)".to_string());
    tried
}

/// Resolves the directory for `role`, per the order documented on this
/// module. `explicit` is the CLI flag's value (`--out` for `Data`,
/// `--config-dir` for `Config` — not implemented as a flag yet, so always
/// `None` for `Log`/`Config` today), and `explicit_flag_name` is only used
/// to name that flag in a failure message.
pub fn resolve(
    role: Role,
    explicit: Option<&str>,
    explicit_flag_name: &'static str,
) -> Result<PathBuf, core::Error> {
    if let Some(value) = explicit.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(value));
    }

    if let Some(env_name) = role.env_override() {
        if let Some(value) = nonempty_env(env_name) {
            return Ok(PathBuf::from(value));
        }
    }

    if running_as_root() {
        return Ok(PathBuf::from(role.fhs_root()));
    }

    if let Some(base) = xdg_home(role.xdg_var()) {
        return Ok(base.join("certway"));
    }

    if let Some(home) = nonempty_env("HOME") {
        let home = PathBuf::from(home);
        if home.is_absolute() {
            return Ok(home.join(role.xdg_default_subpath()).join("certway"));
        }
    }

    let tried = attempted(role, explicit_flag_name);
    Err(core::Error::io(
        Path::new(role.label()),
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "could not resolve a {} directory — tried: {}",
                role.label(),
                tried.join("; ")
            ),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Every test in this module mutates process-global environment
    // variables (`std::env::set_var`), so they must never run concurrently
    // with each other — a lock, not `#[test]`'s default parallelism, keeps
    // that true regardless of libtest's scheduling.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, Option<&str>)]) -> EnvGuard {
            let saved = vars
                .iter()
                .map(|(k, _)| (*k, std::env::var(k).ok()))
                .collect();
            for (k, v) in vars {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            EnvGuard { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    const ALL_VARS: &[&str] = &[
        "CERTWAY_DATA_DIR",
        "CERTWAY_CONFIG_DIR",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "HOME",
    ];

    fn clean(overrides: &[(&'static str, Option<&str>)]) -> EnvGuard {
        let mut vars: Vec<(&'static str, Option<&str>)> =
            ALL_VARS.iter().map(|v| (*v, None)).collect();
        for (k, v) in overrides {
            if let Some(slot) = vars.iter_mut().find(|(name, _)| name == k) {
                slot.1 = *v;
            }
        }
        EnvGuard::set(&vars)
    }

    #[test]
    fn explicit_flag_wins_over_everything() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[
            ("CERTWAY_DATA_DIR", Some("/should/not/be/used")),
            ("HOME", Some("/home/x")),
        ]);
        let resolved = resolve(Role::Data, Some("/explicit/out"), "--out").unwrap();
        assert_eq!(resolved, PathBuf::from("/explicit/out"));
    }

    #[test]
    fn env_override_wins_when_no_explicit_flag() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[
            ("CERTWAY_DATA_DIR", Some("/env/data")),
            ("HOME", Some("/home/x")),
        ]);
        let resolved = resolve(Role::Data, None, "--out").unwrap();
        assert_eq!(resolved, PathBuf::from("/env/data"));
    }

    #[test]
    fn unprivileged_with_xdg_set_uses_xdg_plus_certway() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[
            ("XDG_DATA_HOME", Some("/xdg/data")),
            ("HOME", Some("/home/x")),
        ]);
        assert!(
            !running_as_root(),
            "test process must not actually be root for this case to mean anything"
        );
        let resolved = resolve(Role::Data, None, "--out").unwrap();
        assert_eq!(resolved, PathBuf::from("/xdg/data/certway"));
    }

    #[test]
    fn unprivileged_without_xdg_falls_back_to_home_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[("HOME", Some("/home/x"))]);
        let resolved = resolve(Role::Data, None, "--out").unwrap();
        assert_eq!(resolved, PathBuf::from("/home/x/.local/share/certway"));
    }

    #[test]
    fn config_role_default_subpath_is_dot_config() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[("HOME", Some("/home/x"))]);
        let resolved = resolve(Role::Config, None, "--config-dir").unwrap();
        assert_eq!(resolved, PathBuf::from("/home/x/.config/certway"));
    }

    #[test]
    fn container_with_no_home_and_no_xdg_fails_naming_every_source() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[]);
        let err = resolve(Role::Data, None, "--out").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("--out"), "{text}");
        assert!(text.contains("CERTWAY_DATA_DIR"), "{text}");
        assert!(text.contains("XDG_DATA_HOME"), "{text}");
        assert!(text.contains("HOME"), "{text}");
    }

    #[test]
    fn relative_xdg_value_is_treated_as_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[
            ("XDG_DATA_HOME", Some("relative/path")),
            ("HOME", Some("/home/x")),
        ]);
        let resolved = resolve(Role::Data, None, "--out").unwrap();
        assert_eq!(
            resolved,
            PathBuf::from("/home/x/.local/share/certway"),
            "a relative XDG_DATA_HOME must fall through, not be joined against cwd"
        );
    }

    #[test]
    fn empty_xdg_value_is_treated_as_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[("XDG_DATA_HOME", Some("")), ("HOME", Some("/home/x"))]);
        let resolved = resolve(Role::Data, None, "--out").unwrap();
        assert_eq!(resolved, PathBuf::from("/home/x/.local/share/certway"));
    }

    /// The uid-0 ("running as root") case, exercised at the level that's
    /// actually unit-testable without running the suite as uid 0: the
    /// `/proc/self/status` parser that `resolve`'s uid-0 branch relies
    /// on. `resolve` itself picking the FHS path when `running_as_root()`
    /// is true is a one-line `if`, already covered by this parser being
    /// correct plus the unprivileged-path tests above proving the `false`
    /// branch; there is no dependency-free way to fake root from inside a
    /// non-root test process.
    #[test]
    fn effective_uid_zero_is_parsed_as_root() {
        let status = "Name:\tcertway\nState:\tR\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        assert_eq!(parse_effective_uid(status), Some(0));
    }

    #[test]
    fn effective_uid_nonzero_is_parsed_as_not_root() {
        let status = "Name:\tcertway\nState:\tR\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_effective_uid(status), Some(1000));
    }

    #[test]
    fn malformed_status_text_is_none_not_a_panic() {
        assert_eq!(parse_effective_uid(""), None);
        assert_eq!(parse_effective_uid("nothing relevant here"), None);
        assert_eq!(parse_effective_uid("Uid:\tnot-a-number\n"), None);
        assert_eq!(
            parse_effective_uid("Uid:\t0\n"),
            None,
            "only one field after the label — no effective uid present"
        );
    }

    #[test]
    fn empty_explicit_flag_falls_through() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _env = clean(&[("HOME", Some("/home/x"))]);
        let resolved = resolve(Role::Data, Some(""), "--out").unwrap();
        assert_eq!(resolved, PathBuf::from("/home/x/.local/share/certway"));
    }
}
