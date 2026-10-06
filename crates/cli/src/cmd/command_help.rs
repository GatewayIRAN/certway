// SPDX-License-Identifier: MIT

//! Per-command `--help`: a usage line, two examples, then every flag the
//! command actually accepts with a one-line description — examples
//! first. Most people copy an example and never read the option list, so
//! putting examples first gets the majority of users to a working
//! command without ever needing the flags below. This shape is used for
//! every command's help, not just the top-level screen.
//!
//! Before this, `certway <command> --help` had three different shapes
//! across six commands: `issue --help` silently fell back to the entire
//! top-level menu (no flags at all), `list`/`export`/`rollback` gave a
//! bare usage signature, `renew`/`install` the same. The main menu's own
//! closing line — `certway <command> --help  for details` — didn't
//! deliver on any of them. One shape, used by all six.
//!
//! Flag descriptions reuse the exact wording used to describe the same
//! flag elsewhere (the "Effect" column in the user-facing docs), grouped
//! the same way that table groups them, rather than being re-worded here
//! — so the two descriptions of a flag's behavior can't quietly drift
//! apart and start disagreeing.

use crate::render::{Mode, Out};
use std::io::{self, Write};

pub struct FlagHelp {
    pub flag: &'static str,
    pub about: &'static str,
}

pub struct FlagGroup {
    /// Empty for a command with too few flags to bother grouping
    /// (`list`, `install`, `export`, `rollback`) — printed as one plain
    /// list with no sub-heading.
    pub heading: &'static str,
    pub flags: &'static [FlagHelp],
}

pub struct CommandHelp {
    pub usage: &'static str,
    pub examples: &'static [&'static str],
    pub groups: &'static [FlagGroup],
}

/// The widest a flag column gets before its description moves to its own
/// line — keeps a long flag like `--preferred-challenges <list>` from
/// pushing every other row's description ragged.
const FLAG_COLUMN_WIDTH: usize = 24;

pub fn render(out: &mut Out<impl Write>, help: &CommandHelp) -> io::Result<()> {
    if out.mode == Mode::Json {
        return Ok(());
    }
    out.raw_line("")?;
    out.raw_line(&format!("  {}", help.usage))?;
    out.raw_line("")?;
    out.raw_line("  Examples")?;
    out.raw_line("")?;
    for example in help.examples {
        out.raw_line(&format!("    {example}"))?;
    }
    for group in help.groups {
        out.raw_line("")?;
        if !group.heading.is_empty() {
            out.raw_line(&format!("  {}", group.heading))?;
            out.raw_line("")?;
        }
        for f in group.flags {
            if f.flag.len() >= FLAG_COLUMN_WIDTH {
                out.raw_line(&format!("    {}", f.flag))?;
                out.raw_line(&format!("        {}", f.about))?;
            } else {
                let padded = format!("{:<width$}", f.flag, width = FLAG_COLUMN_WIDTH);
                out.raw_line(&format!("    {padded}{}", f.about))?;
            }
        }
    }
    out.raw_line("")?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Caps;

    fn captured(help: &CommandHelp) -> String {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        };
        let mut buf = Vec::new();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Human);
            render(&mut out, help).unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    const SAMPLE: CommandHelp = CommandHelp {
        usage: "certway sample <name> [flags]",
        examples: &["certway sample foo", "certway sample foo --bar"],
        groups: &[FlagGroup {
            heading: "",
            flags: &[FlagHelp {
                flag: "--bar",
                about: "does the bar thing",
            }],
        }],
    };

    #[test]
    fn examples_are_printed_before_any_flag() {
        let text = captured(&SAMPLE);
        let examples_at = text.find("certway sample foo").unwrap();
        let flag_at = text.find("--bar").unwrap();
        assert!(
            examples_at < flag_at,
            "examples must precede flags: {text}"
        );
    }

    #[test]
    fn usage_examples_and_flag_description_all_present() {
        let text = captured(&SAMPLE);
        assert!(text.contains("certway sample <name> [flags]"));
        assert!(text.contains("certway sample foo --bar"));
        assert!(text.contains("does the bar thing"));
    }

    #[test]
    fn json_mode_prints_nothing() {
        let caps = Caps {
            color: false,
            unicode: true,
            animation: false,
            width: 80,
        }
        .force_json();
        let mut buf = Vec::new();
        {
            let mut out = Out::new(&mut buf, caps, Mode::Json);
            render(&mut out, &SAMPLE).unwrap();
        }
        assert!(String::from_utf8(buf).unwrap().is_empty());
    }
}
