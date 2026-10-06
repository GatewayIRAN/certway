// SPDX-License-Identifier: MIT

//! `certway version`: the first line every bug report should contain.
//! Commit/build date/target come from `build.rs` (`env!`, not a literal —
//! the same rule already applied to the crate's own version via
//! `CARGO_PKG_VERSION`: a fact that can be pulled from the build itself
//! should never be hand-typed and left to drift out of sync), extended
//! here to the three facts that exist specifically to answer "which exact
//! build is this."
//!
//! `tls` is the one literal in this screen: it names a *dependency's*
//! version, and there is no `env!`/reflection equivalent for that the way
//! `CARGO_PKG_VERSION` covers this crate's own. Update it by hand
//! alongside `Cargo.toml`'s `rustls` entry if that pin ever moves.

use crate::render::{Mode, Out};
use std::io::{self, Write};

const TLS_LABEL: &str = "rustls 0.23.43 (ring)";

pub fn render(out: &mut Out<impl Write>) -> io::Result<()> {
    if out.mode == Mode::Json {
        return Ok(());
    }
    let version = env!("CARGO_PKG_VERSION");
    let commit = env!("CERTWAY_COMMIT");
    let built = env!("CERTWAY_BUILD_DATE");
    let target = env!("CERTWAY_TARGET");
    let lines = [
        String::new(),
        format!("  certway {version}"),
        String::new(),
        format!("    commit     {commit}"),
        format!("    built      {built}"),
        format!("    target     {target}"),
        format!("    tls        {TLS_LABEL}"),
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
    fn shows_version_commit_built_target_and_tls() {
        let text = captured();
        assert!(text.contains(&format!("certway {}", env!("CARGO_PKG_VERSION"))));
        assert!(text.contains("commit "));
        assert!(text.contains("built  "));
        assert!(text.contains("target "));
        assert!(text.contains("tls        rustls 0.23.43 (ring)"));
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
            render(&mut out).unwrap();
        }
        assert!(String::from_utf8(buf).unwrap().is_empty());
    }
}
