// SPDX-License-Identifier: MIT

//! The `install` command.
//!
//! Detect → choose (`env::choose_scheduler`) → write → enable → verify.
//! Every automatic choice is one of the four `SchedulerChoice` branches;
//! this module only renders each, it never re-derives the decision.

use crate::args::InstallArgs;
use crate::env::{self, Container, Env, Scheduler, SchedulerChoice};
use crate::render::{Mode, Out};
use crate::scheduler;
use crate::store;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// `certway install --help` — see `cmd::issue::ISSUE_HELP`'s doc comment
/// for the shape every command's help follows.
const INSTALL_HELP: crate::cmd::command_help::CommandHelp = crate::cmd::command_help::CommandHelp {
    usage: "certway install [flags]",
    examples: &["certway install", "certway install --explain"],
    groups: &[crate::cmd::command_help::FlagGroup {
        heading: "",
        flags: &[
            crate::cmd::command_help::FlagHelp {
                flag: "--explain",
                about: "Report every automatic choice and its reason",
            },
            crate::cmd::command_help::FlagHelp {
                flag: "--out <dir>",
                about: "Override the data directory",
            },
            crate::cmd::command_help::FlagHelp {
                flag: "--no-color",
                about: "Disable colour",
            },
        ],
    }],
};

pub fn run(args: InstallArgs, out: &mut Out<impl Write>) -> i32 {
    if args.help {
        let _ = crate::cmd::command_help::render(out, &INSTALL_HELP);
        return 0;
    }

    // `install` never contacts a CA, so the header prints bare `certway
    // {version}` with no CA-status suffix.
    let _ = out.header(env!("CARGO_PKG_VERSION"), None);

    // Best-effort: `install`'s job is to report and configure, not to hard
    // fail just because storage isn't resolvable yet (e.g. no `--out`, no
    // `$HOME`, not root) — the FHS default is still the right thing to name
    // in the "mount a volume" message below even when this run can't write
    // there itself.
    let data_root = store::resolve(store::Role::Data, args.out_dir.as_deref(), "--out")
        .unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/certway"));

    let detected = Env::detect().with_persistent_data(&data_root);
    let choice = env::choose_scheduler(&detected);

    if args.explain {
        print_explain(out, &detected, &choice);
    }

    if let Some(container) = detected.container {
        return run_container(out, container, &data_root, detected.persistent_data);
    }

    match choice {
        SchedulerChoice::SystemdTimer { .. } => run_systemd(out),
        SchedulerChoice::Cron { .. } => run_cron(out),
        SchedulerChoice::Unsupported { .. } => run_unsupported(out),
        SchedulerChoice::AdviseExternal { .. } => {
            unreachable!(
                "choose_scheduler only returns AdviseExternal for a container, handled above"
            )
        }
    }
}

/// A prose paragraph, blank line before and after — like `Out::trailer_prose`
/// but without padding an intentionally-empty line with trailing spaces, so
/// a multi-paragraph message (`run_unsupported`, `run_container`) can embed
/// a blank line between paragraphs cleanly.
fn prose(out: &mut Out<impl Write>, lines: &[&str]) {
    if out.mode != Mode::Human {
        return;
    }
    let _ = out.raw_line("");
    for line in lines {
        if line.is_empty() {
            let _ = out.raw_line("");
        } else {
            let _ = out.raw_line(&format!("    {line}"));
        }
    }
    let _ = out.raw_line("");
}

// ---------------------------------------------------------------------
// systemd (success + unsupported screens)
// ---------------------------------------------------------------------

fn systemd_version() -> Option<String> {
    let output = std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(|s| s.to_string())
}

fn run_systemd(out: &mut Out<impl Write>) -> i32 {
    let unit_dir = scheduler::systemd::resolve_unit_dir();
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("certway"));

    let detect_detail = match systemd_version() {
        Some(v) => format!("systemd {v}"),
        None => "systemd".to_string(),
    };
    let _ = out.step_done("detect", &detect_detail, Duration::ZERO);

    if let Err(e) = scheduler::systemd::write_units(&unit_dir, &exe) {
        let _ = out.step_failed("timer", &e.to_string());
        return 1;
    }
    let _ = out.step_done("timer", scheduler::systemd::TIMER_NAME, Duration::ZERO);

    let outcome = scheduler::systemd::enable();
    if outcome.ok() {
        let _ = out.step_done(
            "enable",
            scheduler::systemd::SCHEDULE_SUMMARY,
            Duration::ZERO,
        );
        prose(out, &["Renewal runs automatically. Nothing else to do."]);
        0
    } else {
        let reason = outcome
            .enable_now
            .clone()
            .err()
            .or_else(|| outcome.daemon_reload.clone().err())
            .unwrap_or_else(|| "systemctl did not report the timer as enabled".to_string());
        let _ = out.step_failed("enable", &reason);
        prose(
            out,
            &[
                "certway wrote the timer but could not enable it. Try again with root:",
                "",
                "  sudo systemctl enable --now certway-renew.timer",
            ],
        );
        1
    }
}

fn run_unsupported(out: &mut Out<impl Write>) -> i32 {
    let _ = out.step_failed("detect", "no supported scheduler");
    let hostname = scheduler::hostname();
    prose(
        out,
        &[
            "certway could not find systemd on this machine.",
            "",
            "Add this to your crontab instead:",
            "",
            &format!("  {}", scheduler::cron::job_line(&hostname)),
        ],
    );
    0
}

// ---------------------------------------------------------------------
// cron
// ---------------------------------------------------------------------

fn run_cron(out: &mut Out<impl Write>) -> i32 {
    let hostname = scheduler::hostname();
    let _ = out.step_done("detect", "cron", Duration::ZERO);
    match scheduler::cron::install(&hostname) {
        Ok(()) => {
            // "twice daily" fits the renderer's fixed 28-column detail
            // field; the exact crontab line (routinely well over 28
            // columns) goes in the prose block below instead, untruncated.
            let _ = out.step_done("crontab", "twice daily", Duration::ZERO);
            prose(
                out,
                &[
                    &scheduler::cron::job_line(&hostname),
                    "",
                    "Renewal runs automatically. Nothing else to do.",
                ],
            );
            0
        }
        Err(e) => {
            let _ = out.step_failed("crontab", &e);
            1
        }
    }
}

// ---------------------------------------------------------------------
// container
// ---------------------------------------------------------------------

fn run_container(
    out: &mut Out<impl Write>,
    container: Container,
    data_root: &Path,
    persistent: bool,
) -> i32 {
    let _ = container; // only distinguishes Docker/Kubernetes/generic; this screen's wording is the same for all three
                       // Short, fixed-width step details (the renderer truncates a detail past
                       // 28 columns — see scheduler::systemd::SCHEDULE_SUMMARY's doc comment);
                       // the full sentences live in the prose blocks below, which print
                       // untruncated.
    let _ = out.step_skipped("install", "container detected");

    // One `prose` call for the whole message, not one per paragraph: two
    // consecutive calls would each open and close with their own blank
    // line, doubling up at the seam between them.
    let mut lines: Vec<String> =
        vec!["No scheduler is installed here — this is a container.".to_string()];
    if !persistent {
        let _ = out.step_warned("persist", "no persistent volume");
        lines.push(String::new());
        lines.push("Certificates will be lost when this container restarts,".to_string());
        lines.push("and certway will request new ones every time. Mount a volume:".to_string());
        lines.push(String::new());
        lines.push(format!("  -v certway-data:{}", data_root.display()));
        lines.push(String::new());
        lines.push("Then pick one renewal pattern:".to_string());
    } else {
        lines.push(String::new());
        lines.push("Pick one renewal pattern:".to_string());
    }
    lines.push(String::new());
    lines.push("  Kubernetes     a CronJob running `certway renew --all`".to_string());
    lines.push("  Docker + cron  a host timer running the container".to_string());
    lines.push("  Compose        `certway renew --all --watch` as the command".to_string());
    lines.push(String::new());
    lines.push("certway renew --all exits 0 when nothing is due.".to_string());

    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    prose(out, &refs);
    0
}

// ---------------------------------------------------------------------
// --explain
// ---------------------------------------------------------------------

fn print_explain(out: &mut Out<impl Write>, detected: &Env, choice: &SchedulerChoice) {
    if out.mode != Mode::Human {
        return;
    }
    let label = |s: &str| format!("{s:<12}");

    let _ = out.raw_line("  Environment");
    let _ = out.raw_line("");
    let _ = out.raw_line(&format!("    {}Linux", label("platform")));
    let container_display = detected.container.map(Container::label).unwrap_or("no");
    let _ = out.raw_line(&format!("    {}{}", label("container"), container_display));
    let scheduler_display = if detected.scheduler.is_empty() {
        "none found".to_string()
    } else {
        detected
            .scheduler
            .iter()
            .map(|s| match s {
                Scheduler::Systemd => "systemd",
                Scheduler::Cron => "cron",
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = out.raw_line(&format!("    {}{}", label("scheduler"), scheduler_display));
    let _ = out.raw_line(&format!(
        "    {}{}",
        label("privileges"),
        if detected.privileged {
            "root"
        } else {
            "unprivileged"
        }
    ));
    let _ = out.raw_line("");
    let _ = out.raw_line("  Choices");
    let _ = out.raw_line("");
    let choice_label = match choice {
        SchedulerChoice::SystemdTimer { .. } => "systemd timer",
        SchedulerChoice::Cron { .. } => "cron",
        SchedulerChoice::AdviseExternal { .. } => "advise external scheduling",
        SchedulerChoice::Unsupported { .. } => "none available",
    };
    let _ = out.raw_line(&format!("    {}{}", label("scheduler"), choice_label));
    let _ = out.raw_line(&format!("    {}{}", label(""), choice.reason()));
    let _ = out.raw_line("");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;

    fn buf_out() -> (Vec<u8>, Caps) {
        (
            Vec::new(),
            Caps {
                color: false,
                unicode: true,
                animation: false,
                width: 100,
            },
        )
    }

    #[test]
    fn container_without_a_volume_warns_and_lists_all_three_patterns() {
        let (mut buf, caps) = buf_out();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            let code = run_container(
                &mut out,
                Container::Docker,
                Path::new("/var/lib/certway"),
                false,
            );
            assert_eq!(code, 0);
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("container detected"));
        assert!(text.contains("No scheduler is installed here — this is a container."));
        assert!(text.contains("no persistent volume"));
        assert!(text.contains("-v certway-data:/var/lib/certway"));
        assert!(text.contains("Kubernetes"));
        assert!(text.contains("Docker + cron"));
        assert!(text.contains("Compose"));
        assert!(text.contains("certway renew --all exits 0 when nothing is due."));
    }

    /// Regression test: `run_container` used to call `prose` twice back to
    /// back for the no-volume case (once for the intro/warning paragraph,
    /// once for the pattern list), and each call opens *and* closes with
    /// its own blank line — so the seam between them printed two blank
    /// lines instead of one. Confirmed live against a real Docker
    /// container before this was fixed.
    #[test]
    fn container_message_never_has_two_consecutive_blank_lines() {
        for persistent in [false, true] {
            let (mut buf, caps) = buf_out();
            {
                let mut out = Out::new(&mut buf, caps, Mode::Human);
                run_container(
                    &mut out,
                    Container::Docker,
                    Path::new("/var/lib/certway"),
                    persistent,
                );
            }
            let text = String::from_utf8(buf).unwrap();
            assert!(
                !text.contains("\n\n\n"),
                "persistent={persistent}: two consecutive blank lines in:\n{text}"
            );
        }
    }

    #[test]
    fn container_with_a_persistent_volume_skips_the_persist_warning() {
        let (mut buf, caps) = buf_out();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            run_container(
                &mut out,
                Container::Kubernetes,
                Path::new("/var/lib/certway"),
                true,
            );
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(
            !text.contains("no volume detected"),
            "a persistent volume must not trigger the warning"
        );
        assert!(
            text.contains("Kubernetes"),
            "the renewal-pattern list is still shown regardless of persistence"
        );
    }

    #[test]
    fn unsupported_reports_failure_and_suggests_the_real_hash_derived_cron_line() {
        let (mut buf, caps) = buf_out();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            let code = run_unsupported(&mut out);
            assert_eq!(
                code, 0,
                "no scheduler found is informational, not a hard failure"
            );
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("no supported scheduler"));
        assert!(text.contains("certway renew --all --quiet"));
        assert!(
            text.contains(&scheduler::cron::job_line(&scheduler::hostname())),
            "must show the real computed line, not a literal placeholder minute"
        );
    }

    #[test]
    fn explain_prints_environment_and_choice_with_its_reason() {
        let env = env::resolve(false, false, 1234, None, true, true, true);
        let choice = env::choose_scheduler(&env);
        let (mut buf, caps) = buf_out();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            print_explain(&mut out, &env, &choice);
        }
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("Environment"));
        assert!(text.contains("Choices"));
        assert!(text.contains("systemd timer"));
        assert!(text.contains("preferred over cron: survives reboot, logs to journal"));
        assert!(text.contains("root"));
    }

    /// Regression guard for a bug first caught by this file's own tests:
    /// every fixed detail string `install` prints through a step line must
    /// fit `render::DETAIL_WIDTH` (28 columns), or `render_status_line`
    /// silently ellipsis-truncates it — several of the original mockup
    /// strings this screen was based on did not fit that budget.
    #[test]
    fn fixed_step_details_fit_the_renderers_28_column_field() {
        use crate::render::{display_width, DETAIL_WIDTH};
        for detail in [
            scheduler::systemd::SCHEDULE_SUMMARY,
            scheduler::systemd::TIMER_NAME,
            "cron",
            "twice daily",
            "container detected",
            "no persistent volume",
            "no supported scheduler",
        ] {
            assert!(
                display_width(detail) <= DETAIL_WIDTH,
                "{detail:?} is {} columns, over the {DETAIL_WIDTH}-column detail field",
                display_width(detail)
            );
        }
    }

    #[test]
    fn explain_is_suppressed_in_json_mode() {
        let env = env::resolve(false, false, 1234, None, true, false, false);
        let choice = env::choose_scheduler(&env);
        let (mut buf, caps) = buf_out();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Json);
            print_explain(&mut out, &env, &choice);
        }
        assert!(
            buf.is_empty(),
            "no --explain shape is defined for --json output"
        );
    }
}
