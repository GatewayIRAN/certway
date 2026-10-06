// SPDX-License-Identifier: MIT

//! Environment detection and the scheduler preference table.
//!
//! Detection reports what exists; `choose_scheduler` decides what's used —
//! kept as two separate steps on purpose: what's present and what's best to
//! use are different questions, and collapsing them would make it
//! impossible to prefer systemd over cron, or external scheduling over
//! either, without rewriting the detection logic itself.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// The only target this build runs on (this project builds and ships
    /// exclusively for `x86_64-unknown-linux-musl`). macOS/Windows
    /// detection is out of scope for this stage.
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Docker,
    Kubernetes,
    /// PID 1, or a cgroup naming a container runtime, without the more
    /// specific Docker/Kubernetes signals.
    Generic,
}

impl Container {
    pub fn label(self) -> &'static str {
        match self {
            Container::Docker => "Docker",
            Container::Kubernetes => "Kubernetes",
            Container::Generic => "container",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheduler {
    Systemd,
    Cron,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    pub os: Os,
    pub container: Option<Container>,
    /// Every scheduler mechanism detected present, in detection order —
    /// **not** a preference. `choose_scheduler` decides what's actually
    /// used.
    pub scheduler: Vec<Scheduler>,
    pub privileged: bool,
    /// Left `false` by `detect()` — this crate's startup sequence detects
    /// the environment before it resolves the data root, so the path this
    /// field needs to check isn't known yet at detection time. Callers set
    /// it afterward via `with_persistent_data` once the data root has been
    /// resolved.
    pub persistent_data: bool,
}

impl Env {
    /// Real-environment detection — the only impure entry point in this
    /// module, mirroring `caps.rs`'s `detect`/`resolve` split.
    pub fn detect() -> Env {
        resolve(
            Path::new("/.dockerenv").exists(),
            std::env::var_os("KUBERNETES_SERVICE_HOST").is_some(),
            std::process::id(),
            std::fs::read_to_string("/proc/1/cgroup").ok().as_deref(),
            Path::new("/run/systemd/system").is_dir(),
            which("crontab").is_some(),
            crate::store::running_as_root(),
        )
    }

    /// Fills in `persistent_data` now that `data_root` is known. Fails
    /// open (reports persistent, so no spurious warning) when
    /// `/proc/self/mountinfo` can't be read or parsed — on the one Linux
    /// target this ships for, that file is effectively always present, so
    /// the fail-open case is theoretical rather than a real gap.
    pub fn with_persistent_data(mut self, data_root: &Path) -> Env {
        self.persistent_data = check_persistent_data(data_root).unwrap_or(true);
        self
    }
}

/// Pure resolution from explicit inputs — the testable core. `detect`
/// supplies the real process/filesystem state.
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    dockerenv: bool,
    k8s_env_set: bool,
    own_pid: u32,
    cgroup_1: Option<&str>,
    systemd_dir: bool,
    cron_on_path: bool,
    privileged: bool,
) -> Env {
    let container = if dockerenv {
        Some(Container::Docker)
    } else if k8s_env_set {
        Some(Container::Kubernetes)
    } else if own_pid == 1 || cgroup_1.map(cgroup_names_a_runtime).unwrap_or(false) {
        Some(Container::Generic)
    } else {
        None
    };

    let mut scheduler = Vec::new();
    if systemd_dir {
        scheduler.push(Scheduler::Systemd);
    }
    if cron_on_path {
        scheduler.push(Scheduler::Cron);
    }

    Env {
        os: Os::Linux,
        container,
        scheduler,
        privileged,
        persistent_data: false,
    }
}

/// The generic-container heuristic: this process's own PID is 1 (typical
/// for the entrypoint process inside a container), or `/proc/1/cgroup`
/// names a container runtime. A substring match against the handful of
/// runtimes that show up in a cgroup path — deliberately not an exhaustive
/// parser, since a false negative here only means falling through to "not
/// a container," never a crash.
fn cgroup_names_a_runtime(text: &str) -> bool {
    const NEEDLES: &[&str] = &["docker", "kubepods", "containerd", "lxc", "podman"];
    let lower = text.to_ascii_lowercase();
    NEEDLES.iter().any(|n| lower.contains(n))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    find_on_path(&path_var.to_string_lossy(), bin)
}

/// The pure search this module's `cron` detection signal reduces to: does
/// any directory in `path_var` (colon-separated, as `PATH` always is on
/// this build's one target) contain an executable named `bin`.
fn find_on_path(path_var: &str, bin: &str) -> Option<std::path::PathBuf> {
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(bin);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// The "persistent data" signal: is `data_root` on a
/// mount other than the container overlay filesystem. `None` means "could
/// not determine" (missing/unparseable `/proc/self/mountinfo`), distinct
/// from an actual `false` — `Env::with_persistent_data` decides what to do
/// with that.
pub fn check_persistent_data(data_root: &Path) -> Option<bool> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    persistent_data_from_mountinfo(&text, data_root)
}

/// Parses Linux's `/proc/self/mountinfo` (`proc(5)`) to find the mount
/// actually covering `data_root` — the entry whose mount point is the
/// longest prefix of it, matching how the kernel itself resolves the
/// containing filesystem — and reports whether that filesystem is an
/// overlay (`overlay`/`aufs`, the two Linux uses for container layering).
/// `None` only when no line has a parseable mount point at all (a
/// genuinely malformed file); an ordinary file with no matching entry still
/// can't happen for an absolute `data_root`, since the root mount `/` is
/// always present and always a prefix.
fn persistent_data_from_mountinfo(text: &str, data_root: &Path) -> Option<bool> {
    let target = data_root.to_string_lossy();
    let mut best: Option<(usize, bool)> = None;

    for line in text.lines() {
        let Some(dash_pos) = line.find(" - ") else {
            continue;
        };
        let (left, right) = line.split_at(dash_pos);
        let Some(mount_point) = left.split_whitespace().nth(4) else {
            continue;
        };
        if !target.starts_with(mount_point) {
            continue;
        }
        let after_dash = &right[3..];
        let fstype = after_dash.split_whitespace().next().unwrap_or("");
        let is_overlay = matches!(fstype, "overlay" | "aufs");
        let mp_len = mount_point.len();

        let replace = match best {
            None => true,
            Some((len, _)) => mp_len > len,
        };
        if replace {
            best = Some((mp_len, is_overlay));
        }
    }

    best.map(|(_, is_overlay)| !is_overlay)
}

// ---------------------------------------------------------------------
// The scheduler preference table
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerChoice {
    SystemdTimer {
        reason: &'static str,
    },
    Cron {
        reason: &'static str,
    },
    /// Container: advise external scheduling rather than self-scheduling.
    /// This must never be demoted below rank 1, even when nothing else is
    /// present — a container with no systemd and no cron on `PATH` is
    /// still a container, and installing a self-scheduled job inside one
    /// is exactly the wrong advice. Watch mode is the fallback a *user*
    /// reaches for manually (`renew --all --watch`); it is never something
    /// `install` auto-selects.
    AdviseExternal {
        reason: &'static str,
    },
    /// Linux, not a container, no systemd, no cron on `PATH`. The
    /// preference table this function encodes doesn't spell this case out
    /// explicitly — its "Linux, no systemd" case implicitly assumes cron is
    /// at least available to fall back to — so this is the honest label for
    /// what's left once every other case has been ruled out.
    Unsupported {
        reason: &'static str,
    },
}

impl SchedulerChoice {
    pub fn reason(&self) -> &'static str {
        match self {
            SchedulerChoice::SystemdTimer { reason }
            | SchedulerChoice::Cron { reason }
            | SchedulerChoice::AdviseExternal { reason }
            | SchedulerChoice::Unsupported { reason } => reason,
        }
    }
}

/// The scheduler preference policy, as code. Detection (`Env`) reports what
/// exists; this decides what's used.
pub fn choose_scheduler(env: &Env) -> SchedulerChoice {
    if env.container.is_some() {
        return SchedulerChoice::AdviseExternal {
            reason: "containers should use external scheduling — a CronJob, a host timer, or watch mode — not a self-scheduled job",
        };
    }
    if env.scheduler.contains(&Scheduler::Systemd) {
        return SchedulerChoice::SystemdTimer {
            reason: "preferred over cron: survives reboot, logs to journal",
        };
    }
    if env.scheduler.contains(&Scheduler::Cron) {
        return SchedulerChoice::Cron {
            reason: "no systemd on this machine; cron is available",
        };
    }
    SchedulerChoice::Unsupported {
        reason: "no systemd, no cron, and not a container",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certway-env-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- container detection -------------------------------------------

    #[test]
    fn dockerenv_marks_docker() {
        let env = resolve(true, false, 1234, None, false, false, false);
        assert_eq!(env.container, Some(Container::Docker));
    }

    #[test]
    fn k8s_env_var_marks_kubernetes() {
        let env = resolve(false, true, 1234, None, false, false, false);
        assert_eq!(env.container, Some(Container::Kubernetes));
    }

    #[test]
    fn dockerenv_wins_over_k8s_when_both_present() {
        let env = resolve(true, true, 1234, None, false, false, false);
        assert_eq!(env.container, Some(Container::Docker));
    }

    #[test]
    fn own_pid_one_marks_generic_container() {
        let env = resolve(false, false, 1, None, false, false, false);
        assert_eq!(env.container, Some(Container::Generic));
    }

    #[test]
    fn cgroup_naming_kubepods_marks_generic_container() {
        let cgroup = "0::/kubepods/besteffort/pod123/abc\n";
        let env = resolve(false, false, 1234, Some(cgroup), false, false, false);
        assert_eq!(env.container, Some(Container::Generic));
    }

    #[test]
    fn ordinary_host_has_no_container() {
        let cgroup = "0::/user.slice/user-1000.slice\n";
        let env = resolve(false, false, 1234, Some(cgroup), false, false, false);
        assert_eq!(env.container, None);
    }

    // -- scheduler / privilege detection --------------------------------

    #[test]
    fn systemd_and_cron_both_recorded_when_both_present() {
        let env = resolve(false, false, 1234, None, true, true, false);
        assert_eq!(env.scheduler, vec![Scheduler::Systemd, Scheduler::Cron]);
    }

    #[test]
    fn privileged_flag_passes_through() {
        let env = resolve(false, false, 1234, None, false, false, true);
        assert!(env.privileged);
    }

    // -- find_on_path ----------------------------------------------------

    #[test]
    fn find_on_path_locates_an_executable() {
        let dir = tmp_dir("which-exec");
        let bin = dir.join("crontab");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&bin).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(&bin, perms).unwrap();

        let path_var = format!("/certway-does-not-exist:{}", dir.display());
        assert_eq!(find_on_path(&path_var, "crontab"), Some(bin));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_on_path_skips_a_non_executable_file() {
        let dir = tmp_dir("which-noexec");
        let bin = dir.join("crontab");
        std::fs::write(&bin, b"data").unwrap();
        let mut perms = std::fs::metadata(&bin).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o644);
        std::fs::set_permissions(&bin, perms).unwrap();

        assert_eq!(find_on_path(&dir.display().to_string(), "crontab"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_on_path_none_when_nowhere_on_path() {
        assert_eq!(
            find_on_path("/certway-does-not-exist:/also-does-not-exist", "crontab"),
            None
        );
    }

    // -- persistent_data_from_mountinfo -----------------------------------

    const SAMPLE_MOUNTINFO: &str = "\
36 35 98:0 / / rw,relatime shared:1 - ext4 /dev/root rw
40 36 0:26 / /var/lib/certway rw,relatime shared:3 - overlay overlay rw
41 36 0:27 / /var/lib/certway-data rw,relatime shared:4 - ext4 /dev/sdb1 rw
";

    #[test]
    fn overlay_mount_is_not_persistent() {
        assert_eq!(
            persistent_data_from_mountinfo(SAMPLE_MOUNTINFO, Path::new("/var/lib/certway")),
            Some(false)
        );
    }

    #[test]
    fn a_real_filesystem_mount_is_persistent() {
        assert_eq!(
            persistent_data_from_mountinfo(SAMPLE_MOUNTINFO, Path::new("/var/lib/certway-data")),
            Some(true)
        );
    }

    #[test]
    fn path_with_no_specific_mount_falls_back_to_root() {
        assert_eq!(
            persistent_data_from_mountinfo(
                SAMPLE_MOUNTINFO,
                Path::new("/home/x/.local/share/certway")
            ),
            Some(true)
        );
    }

    #[test]
    fn unparseable_mountinfo_is_none() {
        assert_eq!(
            persistent_data_from_mountinfo(
                "garbage with no dash marker\n",
                Path::new("/var/lib/certway")
            ),
            None
        );
    }

    // -- choose_scheduler: the preference policy -----------------------

    #[test]
    fn systemd_present_wins_over_cron() {
        let env = resolve(false, false, 1234, None, true, true, false);
        assert!(matches!(
            choose_scheduler(&env),
            SchedulerChoice::SystemdTimer { .. }
        ));
    }

    #[test]
    fn no_systemd_falls_back_to_cron() {
        let env = resolve(false, false, 1234, None, false, true, false);
        assert!(matches!(
            choose_scheduler(&env),
            SchedulerChoice::Cron { .. }
        ));
    }

    #[test]
    fn nothing_available_and_not_a_container_is_unsupported() {
        let env = resolve(false, false, 1234, None, false, false, false);
        assert!(matches!(
            choose_scheduler(&env),
            SchedulerChoice::Unsupported { .. }
        ));
    }

    /// The load-bearing case: the container row never promotes watch mode
    /// to first place, even when nothing else is present at all.
    #[test]
    fn container_never_promotes_watch_even_when_nothing_else_present() {
        let env = resolve(true, false, 1234, None, false, false, false);
        assert!(matches!(
            choose_scheduler(&env),
            SchedulerChoice::AdviseExternal { .. }
        ));
    }

    #[test]
    fn container_with_systemd_and_cron_still_advises_external() {
        let env = resolve(true, false, 1234, None, true, true, false);
        assert!(matches!(
            choose_scheduler(&env),
            SchedulerChoice::AdviseExternal { .. }
        ));
    }
}
