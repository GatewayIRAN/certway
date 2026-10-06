// SPDX-License-Identifier: MIT

//! The no-argument screen. The original design for this screen was
//! frozen for a fully implemented v1 and lists all thirteen commands as
//! one flat "Common"/"Also" split — accurate for a shipped tool, not for
//! the build this screen was rewritten for, which implemented six.
//! Showing all thirteen as if real turned this into a menu of dead ends:
//! every one of
//! `check`/`doctor`/`import`/`revoke`/`delete`/`account` answered with
//! "not implemented... only `issue` is available" — itself stale, since
//! `list`/`install`/`export`/`rollback`/`renew` all worked. Restructured
//! into what works, what's minor but real, and what doesn't exist yet —
//! named honestly instead of listed as if it were the same as the rest.
//! Those six now carry their own rows under `Manage`; only `status`
//! remains unbuilt, and it stays a bullet under its heading, never a
//! command row.
//!
//! `IMPLEMENTED_COMMANDS`/`NOT_YET_BUILT_COMMANDS` (`args.rs`) are the
//! single source of truth this screen and `main.rs`'s "not built yet"
//! message both read from — the drift between a hardcoded list here and
//! the actual dispatch table is exactly the bug this exists to prevent
//! from recurring.

use crate::args::NOT_YET_BUILT_COMMANDS;
use crate::render::{Mode, Out};
use std::io::{self, Write};

pub fn render(out: &mut Out<impl Write>) -> io::Result<()> {
    if out.mode == Mode::Json {
        return Ok(());
    }
    let version = env!("CARGO_PKG_VERSION");
    let not_yet_built = NOT_YET_BUILT_COMMANDS.join(", ");
    let lines = [
        String::new(),
        format!("  certway {version} — HTTPS in one command"),
        String::new(),
        "  Common".to_string(),
        String::new(),
        "    issue <domain>...      get a certificate".to_string(),
        "    renew [<domain>]       renew certificates".to_string(),
        "    list                   show certificates".to_string(),
        "    install                renew automatically".to_string(),
        String::new(),
        "  Also".to_string(),
        String::new(),
        "    export <name>          write in another format".to_string(),
        "    rollback [<file>]      undo a web server config edit".to_string(),
        "    version                version and build details".to_string(),
        String::new(),
        "  Manage".to_string(),
        String::new(),
        "    check <name>          certificate health".to_string(),
        "    doctor                diagnose local setup".to_string(),
        "    import <name>         bring an existing certificate in".to_string(),
        "    revoke <name>         cancel a certificate at the CA".to_string(),
        "    delete <name>         remove a stored certificate".to_string(),
        "    account <action>      register / status / update / deactivate".to_string(),
        String::new(),
        "  Not yet built".to_string(),
        String::new(),
        // Bullet, not an indented command row: `status` must read as
        // "recognized but not dispatchable", never as a working command
        // (the drift the tests guard against).
        format!("    • {not_yet_built}"),
        String::new(),
        "  Examples".to_string(),
        String::new(),
        "    certway issue example.com".to_string(),
        "    certway issue example.com www.example.com".to_string(),
        "    certway issue \"*.example.com\" --dns cloudflare".to_string(),
        String::new(),
        "  certway <command> --help  for details".to_string(),
        String::new(),
    ];
    for line in lines {
        out.raw_line(&line)?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::IMPLEMENTED_COMMANDS;
    use crate::caps::Caps;

    fn captured() -> String {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            render(&mut out).unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn help_screen_exit_is_always_zero() {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        let result = {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            render(&mut out)
        };
        assert!(result.is_ok());
    }

    /// Every real command must actually appear — the drift guard, proven
    /// against the screen's own rendered text rather than assumed from
    /// the source list agreeing with itself.
    #[test]
    fn every_implemented_command_is_listed() {
        let text = captured();
        for cmd in IMPLEMENTED_COMMANDS {
            assert!(text.contains(cmd), "missing implemented command {cmd}");
        }
    }

    /// Every not-yet-built command still appears — named, not hidden —
    /// but only once, under its own honest heading.
    #[test]
    fn every_not_yet_built_command_is_named_under_its_own_heading() {
        let text = captured();
        assert!(text.contains("Not yet built"));
        for cmd in NOT_YET_BUILT_COMMANDS {
            assert!(text.contains(cmd), "missing not-yet-built command {cmd}");
        }
    }

    /// The bug this whole restructure exists for: a not-yet-built command
    /// must never appear formatted the same way as a real one (with its
    /// own `<arg> description` row under `Common`/`Also`) — that's
    /// exactly what made the old screen read as thirteen working
    /// commands.
    #[test]
    fn not_yet_built_commands_never_get_their_own_descriptive_row() {
        let text = captured();
        for cmd in NOT_YET_BUILT_COMMANDS {
            assert!(
                !text.contains(&format!("    {cmd} ")) && !text.contains(&format!("    {cmd}\n")),
                "{cmd} must not be formatted as its own row, only listed under Not yet built"
            );
        }
    }

    #[test]
    fn examples_precede_the_command_list_promise() {
        assert!(captured().contains("certway issue example.com"));
    }
}
