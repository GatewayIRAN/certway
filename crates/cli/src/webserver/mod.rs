// SPDX-License-Identifier: MIT

//! Web-server detection across three tiers: self-managing (Caddy/Traefik,
//! which obtain their own certificates and are never edited), real config
//! editing (nginx, handled by the `nginx` submodule), and advice-only
//! (Apache, HAProxy). Apache stays advice-only — its config layout varies
//! too much across distros to edit safely without the kind of real-install
//! testing nginx here has had.
//!
//! Detection order, stopping at the first signal that matches for a given
//! candidate:
//!
//! ```text
//! running process name  (strongest — the server is actually running)
//! binary on PATH        (installed)
//! config directory exists (installed, possibly not running)
//! ```
//!
//! `detect`/`config_dir_exists` below only check the directory's
//! existence, never its contents — actual config reading is `nginx`'s job.

pub mod nginx;

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    Nginx,
    Apache,
    HaProxy,
    Caddy,
    Traefik,
}

impl Server {
    pub fn name(self) -> &'static str {
        match self {
            Server::Nginx => "nginx",
            Server::Apache => "Apache",
            Server::HaProxy => "HAProxy",
            Server::Caddy => "Caddy",
            Server::Traefik => "Traefik",
        }
    }
}

struct Candidate {
    server: Server,
    process_names: &'static [&'static str],
    path_binaries: &'static [&'static str],
    config_dirs: &'static [&'static str],
}

/// Caddy/Traefik are checked first and deliberately refuse editing: a host
/// that happens to run both a self-managing server and, say, a leftover
/// unused nginx binary on `PATH` should still be told about the one
/// actually obtaining certificates for it.
const CANDIDATES: &[Candidate] = &[
    Candidate {
        server: Server::Caddy,
        process_names: &["caddy"],
        path_binaries: &["caddy"],
        config_dirs: &["/etc/caddy"],
    },
    Candidate {
        server: Server::Traefik,
        process_names: &["traefik"],
        path_binaries: &["traefik"],
        config_dirs: &["/etc/traefik"],
    },
    Candidate {
        server: Server::Nginx,
        process_names: &["nginx"],
        path_binaries: &["nginx"],
        config_dirs: &["/etc/nginx"],
    },
    Candidate {
        server: Server::Apache,
        process_names: &["apache2", "httpd"],
        path_binaries: &["apache2", "httpd"],
        config_dirs: &["/etc/apache2", "/etc/httpd"],
    },
    Candidate {
        server: Server::HaProxy,
        process_names: &["haproxy"],
        path_binaries: &["haproxy"],
        config_dirs: &["/etc/haproxy"],
    },
];

/// Detects the first web server matching any signal, in `CANDIDATES`
/// order. `None` when nothing matches — callers report that explicitly to
/// the user rather than staying silent about it.
pub fn detect() -> Option<Server> {
    detect_with(&is_process_running, &is_on_path, &config_dir_exists)
}

/// `detect`, with every I/O signal injected — the seam that makes every
/// candidate/order case testable without `/proc`, `PATH`, or the real
/// filesystem.
fn detect_with(
    process_running: &dyn Fn(&str) -> bool,
    on_path: &dyn Fn(&str) -> bool,
    config_dir: &dyn Fn(&str) -> bool,
) -> Option<Server> {
    for candidate in CANDIDATES {
        if candidate.process_names.iter().any(|n| process_running(n)) {
            return Some(candidate.server);
        }
    }
    for candidate in CANDIDATES {
        if candidate.path_binaries.iter().any(|b| on_path(b)) {
            return Some(candidate.server);
        }
    }
    for candidate in CANDIDATES {
        if candidate.config_dirs.iter().any(|d| config_dir(d)) {
            return Some(candidate.server);
        }
    }
    None
}

fn is_process_running(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
            if comm.trim() == name {
                return true;
            }
        }
    }
    false
}

fn is_on_path(bin: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| dir.join(bin).is_file())
}

fn config_dir_exists(dir: &str) -> bool {
    Path::new(dir).is_dir()
}

/// The advisory lines for a detected server, or for finding none.
/// `fullchain_path`/`key_path` are this run's actual resolved paths, not a
/// placeholder like `example.com`.
pub fn advice(server: Option<Server>, fullchain_path: &str, key_path: &str) -> Vec<String> {
    match server {
        None => vec!["No web server detected on this host.".to_string()],
        Some(Server::Nginx) => vec![
            "nginx detected. Add these two lines to the right server block:".to_string(),
            String::new(),
            format!("    ssl_certificate      {fullchain_path};"),
            format!("    ssl_certificate_key  {key_path};"),
        ],
        Some(Server::Apache) => vec![
            "Apache detected. Add these lines to the right VirtualHost:".to_string(),
            String::new(),
            "    SSLEngine on".to_string(),
            format!("    SSLCertificateFile      {fullchain_path}"),
            format!("    SSLCertificateKeyFile   {key_path}"),
        ],
        Some(Server::HaProxy) => vec!["HAProxy detected. Use `--format combined` to write the key and chain HAProxy needs in one file.".to_string()],
        Some(Server::Caddy) => vec![
            "Caddy detected.".to_string(),
            String::new(),
            "Caddy obtains certificates automatically.".to_string(),
            "certway is probably not needed on this server.".to_string(),
        ],
        Some(Server::Traefik) => vec![
            "Traefik detected.".to_string(),
            String::new(),
            "Traefik obtains certificates automatically through its own ACME resolver.".to_string(),
            "certway is probably not needed on this server.".to_string(),
        ],
    }
}

/// `true` for the two tiers that obtain certificates themselves — deliberately
/// never a config-editing candidate, at any stage.
pub fn is_self_managing(server: Server) -> bool {
    matches!(server, Server::Caddy | Server::Traefik)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> bool {
        false
    }

    #[test]
    fn no_signal_matches_is_none() {
        assert_eq!(detect_with(&none, &none, &none), None);
    }

    #[test]
    fn process_name_is_the_strongest_signal() {
        let process = |n: &str| n == "nginx";
        assert_eq!(detect_with(&process, &none, &none), Some(Server::Nginx));
    }

    #[test]
    fn path_binary_matches_when_no_process_is_running() {
        let path = |b: &str| b == "haproxy";
        assert_eq!(detect_with(&none, &path, &none), Some(Server::HaProxy));
    }

    #[test]
    fn config_dir_is_the_last_resort_signal() {
        let dir = |d: &str| d == "/etc/apache2";
        assert_eq!(detect_with(&none, &none, &dir), Some(Server::Apache));
    }

    #[test]
    fn apache_matches_the_rhel_httpd_name_too() {
        let process = |n: &str| n == "httpd";
        assert_eq!(detect_with(&process, &none, &none), Some(Server::Apache));
    }

    /// Caddy/Traefik are checked before nginx/Apache/HAProxy even when a
    /// later candidate's process is also technically found — `CANDIDATES`
    /// order, proven directly rather than assumed from reading the table.
    #[test]
    fn caddy_takes_priority_over_a_stray_nginx_binary_on_path() {
        let path = |b: &str| b == "nginx" || b == "caddy";
        assert_eq!(detect_with(&none, &path, &none), Some(Server::Caddy));
    }

    #[test]
    fn caddy_and_traefik_are_self_managing_others_are_not() {
        assert!(is_self_managing(Server::Caddy));
        assert!(is_self_managing(Server::Traefik));
        assert!(!is_self_managing(Server::Nginx));
        assert!(!is_self_managing(Server::Apache));
        assert!(!is_self_managing(Server::HaProxy));
    }

    // -- advice: content assertions per detected server type --------------

    #[test]
    fn nginx_advice_names_the_exact_directives_and_this_runs_paths() {
        let lines = advice(
            Some(Server::Nginx),
            "/var/lib/certway/example.com/fullchain.pem",
            "/var/lib/certway/example.com/privkey.pem",
        );
        let joined = lines.join("\n");
        assert!(joined.contains("ssl_certificate      /var/lib/certway/example.com/fullchain.pem;"));
        assert!(joined.contains("ssl_certificate_key  /var/lib/certway/example.com/privkey.pem;"));
    }

    #[test]
    fn apache_advice_names_the_exact_directives_and_never_writes_sslcertificatechainfile() {
        let lines = advice(Some(Server::Apache), "/a/fullchain.pem", "/a/privkey.pem");
        let joined = lines.join("\n");
        assert!(joined.contains("SSLCertificateFile      /a/fullchain.pem"));
        assert!(joined.contains("SSLCertificateKeyFile   /a/privkey.pem"));
        // Deprecated since Apache 2.4.8 — must never appear in the
        // generated advice.
        assert!(!joined.contains("SSLCertificateChainFile"));
    }

    #[test]
    fn haproxy_advice_suggests_format_combined() {
        let lines = advice(Some(Server::HaProxy), "/a", "/b");
        assert!(lines.join("\n").contains("--format combined"));
    }

    /// Proves Caddy's advice only ever reports, never edits: `advice`
    /// returns strings for the caller to print and performs no filesystem
    /// write of its own — asserted by construction (the function signature
    /// takes no writable path) and by content (no instruction telling the
    /// user certway changed anything).
    #[test]
    fn caddy_advice_reports_and_refuses_to_suggest_editing() {
        let lines = advice(Some(Server::Caddy), "/a", "/b");
        let joined = lines.join("\n");
        assert!(joined.contains("obtains certificates automatically"));
        assert!(!joined.to_lowercase().contains("ssl_certificate"));
        assert!(!joined.to_lowercase().contains("edit"));
    }

    #[test]
    fn traefik_advice_reports_and_refuses_to_suggest_editing() {
        let lines = advice(Some(Server::Traefik), "/a", "/b");
        let joined = lines.join("\n");
        assert!(joined.contains("obtains certificates automatically"));
        assert!(!joined.to_lowercase().contains("edit"));
    }

    #[test]
    fn no_server_detected_says_so() {
        let lines = advice(None, "/a", "/b");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].to_lowercase().contains("no web server detected"));
    }
}
