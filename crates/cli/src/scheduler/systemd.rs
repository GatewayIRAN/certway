// SPDX-License-Identifier: MIT

//! systemd timer scheduling (`ref/systemd-timer-259.md`).

use super::*;

pub const TIMER_NAME: &str = "certway-renew.timer";
pub const SERVICE_NAME: &str = "certway-renew.service";

/// Overrides the unit directory this module reads and writes —
/// **a testing hook, not a user-facing flag.** Real installs always use
/// `DEFAULT_UNIT_DIR`; `list`'s `AUTO` probe (`cmd::list`) and this
/// module's writer both resolve through `resolve_unit_dir`, so the two
/// can never point at different paths — the trap being guarded against
/// is a writer and a status probe silently drifting onto different
/// directories (e.g. one hardcoding `/etc/systemd/system` while the
/// other honours an override), which would make `list` report "not
/// installed" right after a successful install. `systemctl` itself
/// always talks to the *real* system manager regardless of this
/// override, which is why `enable_now` below takes no directory
/// argument: pointing the override at a temp directory can prove the
/// writer and the `AUTO` probe agree, but it cannot make `systemctl
/// enable` succeed against a unit that isn't where the real system
/// manager looks — that failure is reported honestly (`EnableOutcome`),
/// not hidden.
pub const UNIT_DIR_ENV: &str = "CERTWAY_SYSTEMD_DIR";
pub const DEFAULT_UNIT_DIR: &str = "/etc/systemd/system";

pub fn resolve_unit_dir() -> std::path::PathBuf {
    std::env::var(UNIT_DIR_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_UNIT_DIR))
}

pub fn timer_path(unit_dir: &Path) -> std::path::PathBuf {
    unit_dir.join(TIMER_NAME)
}

pub fn service_path(unit_dir: &Path) -> std::path::PathBuf {
    unit_dir.join(SERVICE_NAME)
}

/// `list`'s `AUTO` column and this module's own post-install check both
/// call this — presence only, not `systemctl is-enabled`. That
/// distinction matters: a timer file can exist on disk without being
/// enabled (e.g. `systemctl enable` never ran, or ran and then failed
/// partway), so "the file is there" and "systemd will actually fire it"
/// are different facts — `is_installed` only answers the first one.
pub fn is_installed(unit_dir: &Path) -> bool {
    timer_path(unit_dir).exists()
}

pub fn service_content(exe: &Path) -> String {
    format!("[Unit]\nDescription=certway certificate renewal\n\n[Service]\nType=oneshot\nExecStart={} renew --all --quiet\n", exe.display())
}

/// The `[Timer]` block, wrapped in the minimal `[Unit]`/`[Install]`
/// sections every timer/service pair needs (`ref/systemd-timer-259.md`'s
/// "timer/service pair" concept — a `.timer` alone activates nothing
/// without `[Install] WantedBy=`). Fixed, not templated, and checked
/// byte-for-byte by the test below: nothing here (including the
/// hostname-derived spread) is folded into the file itself — spreading
/// is `RandomizedDelaySec`'s job, applied by systemd at run time, not
/// baked into `OnCalendar`. This stays deliberately literal (no
/// per-host `OnCalendar` minute) even though that means the file looks
/// less "spread out" than the schedule actually is at runtime.
pub const TIMER_CONTENT: &str = "[Unit]\nDescription=certway certificate renewal timer\n\n[Timer]\nOnCalendar=*-*-* 03,15:00:00\nRandomizedDelaySec=7200\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n";

/// A plain-language description of what `TIMER_CONTENT` actually
/// schedules — used by `install`'s "enable" line, kept within the
/// renderer's fixed 28-column detail field (`render::DETAIL_WIDTH`).
/// Deliberately not `"03:14 and 15:14, randomised ±2h"` (a tempting,
/// more specific-sounding string): that text implies a specific,
/// stable per-machine minute and a symmetric ± spread, and neither is
/// true of the unit this module actually writes (`OnCalendar` has no
/// minute offset; the file's own `RandomizedDelaySec=7200` is
/// `systemd`'s 0..+2h, re-rolled each manager start, per
/// `ref/systemd-timer-259.md`'s `RandomizedDelaySec=` entry). Printing
/// numbers like that would be a false claim about the file just
/// written, so this string sticks to what's actually true and fits the
/// column budget.
pub const SCHEDULE_SUMMARY: &str = "03:00 and 15:00 (+0-2h)";

pub fn write_units(unit_dir: &Path, exe: &Path) -> Result<(), core::Error> {
    crate::store::create_dir_secure(unit_dir, 0o755)?;
    crate::store::atomic_write(
        &service_path(unit_dir),
        service_content(exe).as_bytes(),
        0o644,
    )?;
    crate::store::atomic_write(&timer_path(unit_dir), TIMER_CONTENT.as_bytes(), 0o644)?;
    Ok(())
}

fn run_systemctl(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("systemctl").args(args).output();
    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if out.status.success() {
                Ok(stdout)
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                Err(if stderr.is_empty() { stdout } else { stderr })
            }
        }
        Err(e) => Err(format!("could not run systemctl: {e}")),
    }
}

#[derive(Debug, Clone)]
pub struct EnableOutcome {
    pub daemon_reload: Result<(), String>,
    pub enable_now: Result<(), String>,
    /// `true` only when `systemctl is-enabled` itself reports
    /// `enabled` — verified independently rather than assumed from
    /// `enable --now` exiting 0, since a successful daemon-reload and a
    /// successful `enable` call can still leave the timer not actually
    /// enabled (e.g. masked, or another unit conflicting).
    pub is_enabled: bool,
}

impl EnableOutcome {
    pub fn ok(&self) -> bool {
        self.daemon_reload.is_ok() && self.enable_now.is_ok() && self.is_enabled
    }
}

/// `daemon-reload`, then `enable --now` (plain `enable` only wires the
/// `[Install]` symlink for next boot — `ref/systemd-timer-259.md`'s
/// `<never>` table), then verifies with `is-enabled` rather than
/// trusting either call's own exit code alone.
pub fn enable() -> EnableOutcome {
    let daemon_reload = run_systemctl(&["daemon-reload"]).map(|_| ());
    let enable_now = run_systemctl(&["enable", "--now", TIMER_NAME]).map(|_| ());
    let is_enabled = run_systemctl(&["is-enabled", TIMER_NAME])
        .map(|s| s == "enabled")
        .unwrap_or(false);
    EnableOutcome {
        daemon_reload,
        enable_now,
        is_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "certway-scheduler-systemd-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn timer_content_matches_arch_spec_byte_for_byte() {
        assert_eq!(TIMER_CONTENT, "[Unit]\nDescription=certway certificate renewal timer\n\n[Timer]\nOnCalendar=*-*-* 03,15:00:00\nRandomizedDelaySec=7200\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n");
        assert!(TIMER_CONTENT.contains("OnCalendar=*-*-* 03,15:00:00\n"));
        assert!(TIMER_CONTENT.contains("RandomizedDelaySec=7200\n"));
        assert!(TIMER_CONTENT.contains("Persistent=true\n"));
    }

    #[test]
    fn service_content_runs_renew_all_quiet() {
        let content = service_content(Path::new("/usr/local/bin/certway"));
        assert!(content.contains("ExecStart=/usr/local/bin/certway renew --all --quiet\n"));
        assert!(content.contains("Type=oneshot\n"));
    }

    #[test]
    fn write_units_then_is_installed_agree_on_the_same_path() {
        let dir = tmp_dir("agree");
        write_units(&dir, Path::new("/usr/local/bin/certway")).unwrap();
        assert!(
            is_installed(&dir),
            "the probe must find the timer the writer just wrote, at the same path"
        );
        assert_eq!(
            std::fs::read_to_string(timer_path(&dir)).unwrap(),
            TIMER_CONTENT
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_installed_false_before_any_write() {
        let dir = tmp_dir("absent");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!is_installed(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_unit_dir_defaults_when_env_unset() {
        // Guarded by a lock shared with the sibling override test so
        // the two never race on the same process-global env var.
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var(UNIT_DIR_ENV);
        assert_eq!(
            resolve_unit_dir(),
            std::path::PathBuf::from(DEFAULT_UNIT_DIR)
        );
    }

    #[test]
    fn resolve_unit_dir_honours_the_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(UNIT_DIR_ENV, "/tmp/certway-test-units");
        assert_eq!(
            resolve_unit_dir(),
            std::path::PathBuf::from("/tmp/certway-test-units")
        );
        std::env::remove_var(UNIT_DIR_ENV);
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
