// SPDX-License-Identifier: MIT

//! Paths, atomic writes, permissions, and locking — everything `certway`
//! touches on disk.

pub mod account;
pub mod ari;
pub mod atomic;
pub mod cert;
pub mod link;
pub mod lock;
pub mod paths;
pub mod pem;

pub use account::{
    account_paths, host_from_url, load_or_generate_key, save_account_record, AccountPaths,
};
pub use ari::{ari_cache_path, invalidate_ari_cache, read_ari_cache, write_ari_cache};
pub use atomic::{atomic_write, create_dir_secure};
pub use cert::{
    add_export, apply_links, cert_dir_name, cert_paths, read_config, tighten_permissions,
    write_certificate, CertConfig, CertPaths, ExportSpec, HookConfig, LinkSpec,
};
pub use link::TargetState;
pub use lock::{acquire_exclusive, acquire_shared, is_missing_data_dir, Lock};
pub(crate) use paths::running_as_root;
pub use paths::{resolve, Role};
