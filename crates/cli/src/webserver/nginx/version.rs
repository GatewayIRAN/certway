// SPDX-License-Identifier: MIT

//! Parses `nginx -v`/`nginx -V` output. Both write entirely to
//! **stderr** — confirmed against the pinned
//! `nginx:1.29.3` container (`nginx -V 2>/tmp/err 1>/tmp/out` gave 0 bytes
//! on stdout, 1679 on stderr); code that reads stdout gets an empty string
//! and silently gets nothing. Callers must pass stderr's captured text
//! here, not stdout's.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NginxVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

/// Parses the `nginx version: nginx/X.Y.Z` line from `nginx -v` (or `-V`,
/// same first line) stderr output. Verified format against the pin:
/// `nginx version: nginx/1.29.3`.
pub fn parse_version(stderr: &str) -> Option<NginxVersion> {
    let line = stderr.lines().find(|l| l.contains("nginx version:"))?;
    let after_slash = line.rsplit('/').next()?.trim();
    let mut parts = after_slash.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // The patch component can carry trailing text in some builds (rare);
    // take only the leading digits rather than failing the whole parse.
    let patch_raw = parts.next()?;
    let patch_digits: String = patch_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let patch = patch_digits.parse().ok()?;
    Some(NginxVersion {
        major,
        minor,
        patch,
    })
}

/// Parses the `configure arguments:` line for the compiled `--prefix`,
/// `--conf-path` (when the build overrides it separately), and whether
/// `--with-http_ssl_module` is present.
///
/// **`--conf-path` is not always absent.** The pinned `nginx:1.29.3`
/// container's build has no separate `--conf-path`, so `<prefix>/
/// nginx.conf` looks like the whole answer there — but Ubuntu's packaged
/// nginx (`nginx/1.28.3 (Ubuntu)`) is a far more common way people
/// actually run nginx than that one pinned Docker image, and it
/// configures `--prefix=/usr/share/nginx` and
/// `--conf-path=/etc/nginx/nginx.conf` as two *independent* values.
/// `<prefix>/nginx.conf` there resolves to `/usr/share/nginx/nginx.conf`,
/// which does not exist — `detect_installation` would silently fail to
/// find any real Ubuntu/Debian nginx's actual config at all. `--conf-path`,
/// when present, is now the answer; `<prefix>/nginx.conf` is the fallback
/// for builds (the pinned container included) that never set it
/// separately.
pub fn parse_configure_arguments(stderr: &str) -> Option<ConfigureArguments> {
    let line = stderr
        .lines()
        .find(|l| l.trim_start().starts_with("configure arguments:"))?;
    let args = line.split_once("configure arguments:")?.1;
    let mut prefix = None;
    let mut conf_path = None;
    let mut has_http_ssl_module = false;
    for token in args.split_whitespace() {
        if let Some(p) = token.strip_prefix("--prefix=") {
            prefix = Some(p.to_string());
        }
        if let Some(c) = token.strip_prefix("--conf-path=") {
            conf_path = Some(c.to_string());
        }
        if token == "--with-http_ssl_module" {
            has_http_ssl_module = true;
        }
    }
    Some(ConfigureArguments {
        prefix,
        conf_path,
        has_http_ssl_module,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigureArguments {
    pub prefix: Option<String>,
    /// `--conf-path`, only when the build set it as a distinct value from
    /// `--prefix` — see `parse_configure_arguments`'s doc comment.
    pub conf_path: Option<String>,
    pub has_http_ssl_module: bool,
}

/// `http2 on;` (separate directive) vs `listen ... http2` (combined) —
/// confirmed live against the pin: `http2 on;` passes `nginx -t` clean on
/// 1.29.3 with no warning; `listen 443 ssl http2;` also passes but logs
/// `the "listen ... http2" directive is deprecated, use the "http2"
/// directive instead`. The separate form was introduced in 1.25.1 and
/// doesn't exist before that (`unknown directive` there), so the cutoff is
/// exact, not a style preference.
pub fn supports_http2_directive(version: NginxVersion) -> bool {
    version
        >= (NginxVersion {
            major: 1,
            minor: 25,
            patch: 1,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED_V_OUTPUT: &str = "nginx version: nginx/1.29.3\nbuilt by gcc 14.2.0 (Debian 14.2.0-19) \nbuilt with OpenSSL 3.5.1 1 Jul 2025 (running with OpenSSL 3.5.4 30 Sep 2025)\nTLS SNI support enabled\nconfigure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --with-http_ssl_module --with-http_v2_module\n";

    #[test]
    fn parses_the_pinned_containers_real_output() {
        let v = parse_version(PINNED_V_OUTPUT).unwrap();
        assert_eq!(
            v,
            NginxVersion {
                major: 1,
                minor: 29,
                patch: 3
            }
        );
    }

    #[test]
    fn parses_prefix_and_ssl_module_from_the_pinned_containers_real_output() {
        let c = parse_configure_arguments(PINNED_V_OUTPUT).unwrap();
        assert_eq!(c.prefix.as_deref(), Some("/etc/nginx"));
        assert!(c.has_http_ssl_module);
        assert_eq!(
            c.conf_path, None,
            "the pinned container never sets --conf-path separately"
        );
    }

    /// Captured live from a real Ubuntu 26.04 box's packaged nginx
    /// (`apt install nginx`, `nginx/1.28.3 (Ubuntu)`) — the bug this
    /// module's own doc comment now explains: `--prefix` and
    /// `--conf-path` are two independent values here, not one implying
    /// the other.
    const UBUNTU_V_OUTPUT: &str = "nginx version: nginx/1.28.3 (Ubuntu)\nbuilt with OpenSSL 3.5.5 27 Jan 2026\nTLS SNI support enabled\nconfigure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=stderr --lock-path=/var/lock/nginx.lock --pid-path=/run/nginx.pid --with-http_ssl_module --with-http_v2_module\n";

    #[test]
    fn parses_prefix_and_conf_path_as_independent_values_from_real_ubuntu_output() {
        let c = parse_configure_arguments(UBUNTU_V_OUTPUT).unwrap();
        assert_eq!(c.prefix.as_deref(), Some("/usr/share/nginx"));
        assert_eq!(c.conf_path.as_deref(), Some("/etc/nginx/nginx.conf"));
        assert!(c.has_http_ssl_module);
    }

    #[test]
    fn missing_ssl_module_is_detected() {
        let c = parse_configure_arguments(
            "configure arguments: --prefix=/etc/nginx --with-http_v2_module\n",
        )
        .unwrap();
        assert!(!c.has_http_ssl_module);
    }

    #[test]
    fn garbage_input_is_none_not_a_panic() {
        assert_eq!(parse_version("not nginx output at all"), None);
        assert_eq!(parse_configure_arguments("not nginx output at all"), None);
    }

    #[test]
    fn empty_input_is_none_not_a_panic() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_configure_arguments(""), None);
    }

    #[test]
    fn http2_directive_cutoff_is_1_25_1() {
        assert!(!supports_http2_directive(NginxVersion {
            major: 1,
            minor: 25,
            patch: 0
        }));
        assert!(supports_http2_directive(NginxVersion {
            major: 1,
            minor: 25,
            patch: 1
        }));
        assert!(supports_http2_directive(NginxVersion {
            major: 1,
            minor: 29,
            patch: 3
        }));
        assert!(!supports_http2_directive(NginxVersion {
            major: 1,
            minor: 24,
            patch: 9
        }));
    }
}
