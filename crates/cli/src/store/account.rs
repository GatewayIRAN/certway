// SPDX-License-Identifier: MIT

//! Account key persistence — every `certway issue` run used to call
//! `AccountKey::generate()` fresh, burning a "new registrations per hour"
//! slot and orphaning every certificate's authorizations every time.
//! Persisting and reusing the account key across runs fixes that.
//!
//! ```text
//! <data>/account/<ca-host>/
//!   ├── account.key     0600, PKCS#8 PEM
//!   └── account.json    0644, no secrets
//! ```
//!
//! Staging and production are separate worlds — keyed by the directory
//! URL's hostname, never a single shared key.

use super::atomic::{atomic_write, create_dir_secure};
use super::pem;
use certway_core::json::{write_object, Json, JsonVal};
use certway_core::{self as core, AccountKey};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Extracts the host from an ACME directory URL for use as the account
/// storage key. Deliberately minimal — not a general URL parser, just
/// enough to pull the authority out of `scheme://host[:port][/path]`,
/// which is all an ACME directory URL ever is.
pub fn host_from_url(url: &str) -> &str {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let end = after_scheme
        .find(['/', ':', '?'])
        .unwrap_or(after_scheme.len());
    &after_scheme[..end]
}

pub struct AccountPaths {
    pub dir: PathBuf,
    pub key: PathBuf,
    pub json: PathBuf,
}

pub fn account_paths(data_root: &Path, ca_host: &str) -> AccountPaths {
    let dir = data_root.join("account").join(ca_host);
    let key = dir.join("account.key");
    let json = dir.join("account.json");
    AccountPaths { dir, key, json }
}

/// Loads the persisted account key for `ca_host`, or generates and persists
/// a new one.
///
/// A *present but unparseable* `account.key` is a hard error naming the
/// path, never a silent regeneration. Looking like recovery while
/// actually minting a fresh identity would orphan every certificate tied
/// to the old key and double rate-limit consumption — silently
/// regenerating on a parse failure is exactly the bug this module exists
/// to prevent, just one level down.
/// `relax_permissions` is `--relax-permissions`: a container running as
/// an arbitrary UID can't always control a mounted
/// volume's ownership, and without this escape hatch certway hard-fails in
/// exactly that environment with no way around it. `true` downgrades an
/// insecure-permissions finding to a warning (the second element of the
/// returned tuple) instead of refusing to use the key. A freshly generated
/// key is never loose to begin with, so relaxation never applies to that
/// path — only to a pre-existing key/directory found on disk.
pub fn load_or_generate_key(
    paths: &AccountPaths,
    relax_permissions: bool,
) -> Result<(AccountKey, bool), core::Error> {
    if paths.key.exists() {
        return load_key(&paths.dir, &paths.key, relax_permissions);
    }

    create_dir_secure(&paths.dir, 0o700)?;
    let key = AccountKey::generate()?;
    let pem_text = pem::encode_pkcs8_pem(&key.to_pkcs8());
    atomic_write(&paths.key, pem_text.as_bytes(), 0o600)?;
    Ok((key, false))
}

fn load_key(dir: &Path, path: &Path, relax_permissions: bool) -> Result<(AccountKey, bool), core::Error> {
    let dir_relaxed = check_dir_permissions(dir, relax_permissions)?;
    let key_relaxed = check_key_permissions(path, relax_permissions)?;

    let pem_text = std::fs::read_to_string(path).map_err(|e| core::Error::io(path, e))?;
    let der =
        pem::decode_pkcs8_pem(&pem_text).map_err(|detail| unparseable_account_key(path, detail))?;
    let key = AccountKey::from_pkcs8(&der)
        .map_err(|_| unparseable_account_key(path, "key bytes do not decode as PKCS#8 ECDSA"))?;
    Ok((key, dir_relaxed || key_relaxed))
}

fn unparseable_account_key(path: &Path, detail: &str) -> core::Error {
    core::Error::io(
        path,
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "account key at {} is corrupt or not PKCS#8 PEM ({detail}) — refusing to generate a replacement, \
                 which would silently orphan every certificate issued under the existing account",
                path.display()
            ),
        ),
    )
}

/// Key directories must be `0700`, verified on read, same as the key
/// file itself — a key directory group/other can
/// traverse is a real exposure even if the file inside is individually
/// `0600` (it still leaks the file's existence and metadata, and a
/// misconfigured deployment that loosened one likely loosened both).
/// `relax_permissions` downgrades the refusal to `Ok(true)` — the caller
/// renders it as a warning instead of failing — for containers running as
/// an arbitrary UID that can't control a mounted volume's ownership.
fn check_dir_permissions(dir: &Path, relax_permissions: bool) -> Result<bool, core::Error> {
    let mode = std::fs::metadata(dir)
        .map_err(|e| core::Error::io(dir, e))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        if relax_permissions {
            return Ok(true);
        }
        return Err(core::Error::io(
            dir,
            std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!("account directory {} is accessible by group or other (mode {:o}); refusing to use it", dir.display(), mode & 0o777),
            ),
        ));
    }
    Ok(false)
}

/// `account.key` must be `0600` on read, hard error if group or other has
/// any bit set — a private key readable by another
/// user on the machine is already compromised. `--relax-permissions`
/// (`relax_permissions` here) is the one documented way to proceed anyway,
/// named to make its cost obvious rather than hidden behind a default.
fn check_key_permissions(path: &Path, relax_permissions: bool) -> Result<bool, core::Error> {
    let mode = std::fs::metadata(path)
        .map_err(|e| core::Error::io(path, e))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        if relax_permissions {
            return Ok(true);
        }
        return Err(core::Error::io(
            path,
            std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!("account key at {} is readable by group or other (mode {:o}); refusing to use it", path.display(), mode & 0o777),
            ),
        ));
    }
    Ok(false)
}

/// Writes `account.json` — URL, contact, and ToS-agreed timestamp, and
/// nothing that could substitute for the key. The stored URL is never
/// trusted as authoritative: every run still POSTs `newAccount` with
/// `onlyReturnExisting: true` first. This
/// file exists for humans and `doctor`, not to skip that round trip.
pub fn save_account_record(
    paths: &AccountPaths,
    url: &str,
    contact: Option<&str>,
    agreed_tos: bool,
    now_unix_secs: u64,
) -> Result<(), core::Error> {
    let mut fields: Vec<(&str, JsonVal)> = vec![("url", JsonVal::Str(url))];
    if let Some(c) = contact {
        fields.push(("contact", JsonVal::Str(c)));
    }
    let ts;
    if agreed_tos {
        ts = now_unix_secs.to_string();
        fields.push(("tos_agreed_at", JsonVal::Str(&ts)));
    }
    let body = write_object(&fields);
    atomic_write(&paths.json, body.as_bytes(), 0o644)
}

/// Reads back `account.json` for display purposes only. An unparseable
/// `account.json` is not fatal — a future `doctor`/`list` command would
/// warn and treat it as absent; this build has no
/// caller for that path yet (`issue` only writes it), so this exists for
/// completeness and its own unit tests.
pub fn read_account_record(path: &Path) -> Option<(String, Option<String>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let json = Json::parse(text.as_bytes()).ok()?;
    let url = json.str("url").ok()?.to_string();
    let contact = json.opt_str("contact").map(str::to_string);
    Some((url, contact))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certway-account-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn host_from_url_strips_scheme_path_and_port() {
        assert_eq!(
            host_from_url("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "acme-staging-v02.api.letsencrypt.org"
        );
        assert_eq!(host_from_url("https://example.com:1234/dir"), "example.com");
        assert_eq!(host_from_url("http://localhost:14000/dir"), "localhost");
    }

    #[test]
    fn generates_once_and_reuses_on_second_call() {
        let root = tmp_root("reuse");
        let paths = account_paths(&root, "acme-staging-v02.api.letsencrypt.org");

        let (first, first_relaxed) = load_or_generate_key(&paths, false).unwrap();
        assert!(paths.key.exists());
        assert!(!first_relaxed, "a freshly generated key is never loose");
        let mode = std::fs::metadata(&paths.key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let (second, second_relaxed) = load_or_generate_key(&paths, false).unwrap();
        assert!(!second_relaxed);
        assert_eq!(
            first.thumbprint(),
            second.thumbprint(),
            "second call must load the same key, not generate a new one"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn corrupt_key_is_a_hard_error_naming_the_path_and_never_replaced() {
        let root = tmp_root("corrupt");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();
        atomic_write(&paths.key, b"not a pem key at all", 0o600).unwrap();

        let err = load_or_generate_key(&paths, false).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains(&paths.key.display().to_string()),
            "error must name the path: {text}"
        );

        // The corrupt file must still be there, byte for byte — no silent
        // regeneration.
        assert_eq!(std::fs::read(&paths.key).unwrap(), b"not a pem key at all");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsafe_permissions_are_a_hard_error_on_read_by_default() {
        let root = tmp_root("unsafe-perm");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();
        // A key genuinely written by us, but with group-readable bits —
        // simulating a misconfigured deployment, not corruption.
        let key = AccountKey::generate().unwrap();
        let pem_text = pem::encode_pkcs8_pem(&key.to_pkcs8());
        std::fs::write(&paths.key, pem_text.as_bytes()).unwrap();
        std::fs::set_permissions(&paths.key, std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = load_or_generate_key(&paths, false).unwrap_err();
        assert!(
            err.to_string().contains("readable by group or other"),
            "{err}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsafe_directory_permissions_are_also_a_hard_error_on_read_by_default() {
        let root = tmp_root("unsafe-dir-perm");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();
        let key = AccountKey::generate().unwrap();
        let pem_text = pem::encode_pkcs8_pem(&key.to_pkcs8());
        std::fs::write(&paths.key, pem_text.as_bytes()).unwrap();
        std::fs::set_permissions(&paths.key, std::fs::Permissions::from_mode(0o600)).unwrap();
        // The file alone is safe — it's the containing directory that's
        // loosened, e.g. by a misconfigured deployment's umask.
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o750)).unwrap();

        let err = load_or_generate_key(&paths, false).unwrap_err();
        assert!(
            err.to_string().contains("accessible by group or other"),
            "{err}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--relax-permissions`: the same loose key
    /// that's a hard error by default must load successfully when relaxed,
    /// and report back that it did so — the caller renders that as a
    /// warning rather than staying silent about it.
    #[test]
    fn relax_permissions_downgrades_an_unsafe_key_to_a_reported_warning() {
        let root = tmp_root("relax-perm-key");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();
        let key = AccountKey::generate().unwrap();
        let pem_text = pem::encode_pkcs8_pem(&key.to_pkcs8());
        std::fs::write(&paths.key, pem_text.as_bytes()).unwrap();
        std::fs::set_permissions(&paths.key, std::fs::Permissions::from_mode(0o640)).unwrap();

        let (loaded, relaxed) = load_or_generate_key(&paths, true).unwrap();
        assert_eq!(loaded.thumbprint(), key.thumbprint());
        assert!(relaxed, "loose permissions under --relax-permissions must be reported, not silent");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Same as above, for the containing directory rather than the key file.
    #[test]
    fn relax_permissions_downgrades_an_unsafe_directory_to_a_reported_warning() {
        let root = tmp_root("relax-perm-dir");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();
        let key = AccountKey::generate().unwrap();
        let pem_text = pem::encode_pkcs8_pem(&key.to_pkcs8());
        std::fs::write(&paths.key, pem_text.as_bytes()).unwrap();
        std::fs::set_permissions(&paths.key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o750)).unwrap();

        let (loaded, relaxed) = load_or_generate_key(&paths, true).unwrap();
        assert_eq!(loaded.thumbprint(), key.thumbprint());
        assert!(relaxed);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn account_json_round_trips_url_and_contact() {
        let root = tmp_root("json");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();

        save_account_record(
            &paths,
            "https://acme-v02.api.letsencrypt.org/acct/123",
            Some("mailto:a@b.com"),
            true,
            1_700_000_000,
        )
        .unwrap();

        let mode = std::fs::metadata(&paths.json).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);

        let (url, contact) = read_account_record(&paths.json).unwrap();
        assert_eq!(url, "https://acme-v02.api.letsencrypt.org/acct/123");
        assert_eq!(contact.as_deref(), Some("mailto:a@b.com"));

        let text = std::fs::read_to_string(&paths.json).unwrap();
        assert!(
            !text.contains("BEGIN"),
            "account.json must never carry key material"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn account_json_omits_contact_when_none_given() {
        let root = tmp_root("json-no-contact");
        let paths = account_paths(&root, "acme-v02.api.letsencrypt.org");
        create_dir_secure(&paths.dir, 0o700).unwrap();

        save_account_record(
            &paths,
            "https://acme-v02.api.letsencrypt.org/acct/1",
            None,
            true,
            1_700_000_000,
        )
        .unwrap();
        let (_, contact) = read_account_record(&paths.json).unwrap();
        assert_eq!(contact, None);

        let _ = std::fs::remove_dir_all(&root);
    }
}
