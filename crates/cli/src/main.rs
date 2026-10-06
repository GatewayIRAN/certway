// SPDX-License-Identifier: MIT
#![forbid(unsafe_code)]

use certway::args::{self, Command};
use certway::caps::Caps;
use certway::render::{Mode, Out};
use std::io::Write;

fn main() {
    // Startup order: install the signal handler, then parse arguments (no
    // I/O), then resolve capabilities, then construct the writer, then
    // dispatch. The signal handler goes first so a Ctrl-C during argument
    // parsing or capability detection is still caught, rather than falling
    // through to the OS default. `certway::signal::install` is the one
    // place in this crate `unsafe` is permitted (`libc::signal`, isolated
    // in `signal::raw`) — see that module's doc comment for why.
    //
    // Its `bool` return matters: `signal(2)` can fail (`SIG_ERR`), and
    // silently ignoring that would leave certway believing it can clean up
    // on interrupt when it can't — reported below, once `out` exists, not
    // discarded here.
    let signals_ok = certway::signal::install();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let parsed = args::parse(&raw);

    let caps = Caps::detect();

    let (mode, caps) = match &parsed {
        Ok(Command::Issue(a)) if a.json => (Mode::Json, caps.force_json()),
        Ok(Command::Issue(a)) if a.quiet => (
            Mode::Quiet,
            if a.no_color {
                caps.force_no_color()
            } else {
                caps
            },
        ),
        Ok(Command::Issue(a)) if a.no_color => (Mode::Human, caps.force_no_color()),
        Ok(Command::Renew(a)) if a.json => (Mode::Json, caps.force_json()),
        Ok(Command::Renew(a)) if a.quiet => (
            Mode::Quiet,
            if a.no_color {
                caps.force_no_color()
            } else {
                caps
            },
        ),
        Ok(Command::Renew(a)) if a.no_color => (Mode::Human, caps.force_no_color()),
        Ok(Command::List(a)) if a.json => (Mode::Json, caps.force_json()),
        Ok(Command::List(a)) if a.no_color => (Mode::Human, caps.force_no_color()),
        Ok(Command::Install(a)) if a.no_color => (Mode::Human, caps.force_no_color()),
        Ok(Command::Export(a)) if a.json => (Mode::Json, caps.force_json()),
        Ok(Command::Export(a)) if a.no_color => (Mode::Human, caps.force_no_color()),
        Ok(Command::Rollback(a)) if a.no_color => (Mode::Human, caps.force_no_color()),
        _ => (Mode::Human, caps),
    };

    let stdout = std::io::stdout();
    let mut out = Out::new(stdout.lock(), caps, mode);

    // Only the commands that do work interrupt-cleanup would ever matter
    // for — `issue`/`renew` (which can leave behind in-progress ACME
    // challenge or DNS-01 record state) and `install` (a partially-written
    // scheduler config). `--help`/
    // `--version`/`list` never create anything a Ctrl-C could leave
    // behind, so warning there would just be noise about a risk that
    // command doesn't carry.
    let signals_relevant = matches!(
        &parsed,
        Ok(Command::Issue(_)) | Ok(Command::Renew(_)) | Ok(Command::Install(_))
    );
    if !signals_ok && signals_relevant {
        let _ = out.step_warned("signals", "cleanup on interrupt unavailable");
    }

    let exit_code = match parsed {
        Ok(Command::Help) => {
            let _ = certway::cmd::help::render(&mut out);
            0
        }
        Ok(Command::Version) => {
            let _ = certway::cmd::version::render(&mut out);
            0
        }
        Ok(Command::Issue(a)) => certway::cmd::issue::run(a, &mut out),
        Ok(Command::Renew(a)) => certway::cmd::renew::run(a, &mut out),
        Ok(Command::List(a)) => certway::cmd::list::run(a, &mut out),
        Ok(Command::Install(a)) => certway::cmd::install::run(a, &mut out),
        Ok(Command::Export(a)) => certway::cmd::export::run(a, &mut out),
        Ok(Command::Rollback(a)) => certway::cmd::rollback::run(a, &mut out),
        Ok(Command::Check(a)) => certway::cmd::check::run(a, &mut out),
        Ok(Command::Doctor(a)) => certway::cmd::doctor::run(a, &mut out),
        Ok(Command::Import(a)) => certway::cmd::import::run(a, &mut out),
        Ok(Command::Revoke(a)) => certway::cmd::revoke::run(a, &mut out),
        Ok(Command::Delete(a)) => certway::cmd::delete::run(a, &mut out),
        Ok(Command::Account(a)) => certway::cmd::account::run(a, &mut out),
        Ok(Command::NotYetImplemented(name)) => {
            // Generated from `args::IMPLEMENTED_COMMANDS`, not a literal —
            // a hardcoded list is what let this message claim "only
            // `issue` is available" while `list`/`install`/`export`/
            // `rollback`/`renew` had all shipped.
            let available = certway::args::IMPLEMENTED_COMMANDS.join(", ");
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("  certway: {name} is not built yet"));
            let _ = out.raw_line("");
            let _ = out.raw_line(&format!("    Available: {available}"));
            let _ = out.raw_line("");
            2
        }
        Err(e) => {
            let _ = print_arg_error(&mut out, &e);
            2
        }
    };

    let _ = out.flush();
    std::process::exit(exit_code);
}

fn print_arg_error(out: &mut Out<impl Write>, err: &args::ArgError) -> std::io::Result<()> {
    if out.mode == Mode::Json {
        return Ok(());
    }
    out.raw_line("")?;
    out.raw_line(&format!("  certway: {}", err.message))?;
    if let Some(suggestion) = &err.suggestion {
        out.raw_line(&format!("    {suggestion}"))?;
    }
    out.raw_line("")
}
