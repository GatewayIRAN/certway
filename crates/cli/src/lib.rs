// SPDX-License-Identifier: MIT
// `forbid`, not `deny`, would also block the one documented exception this
// crate carries: `signal::raw`'s `#![allow(unsafe_code)]`, the isolated
// module wrapping `libc::signal` (`certway-core` has no such exception and
// keeps `forbid`). `deny` still refuses `unsafe` everywhere else — an inner
// `allow` only overrides `deny`, never `forbid` (rustc E0453) — so this is
// the minimum loosening that makes `signal::raw` possible at all, not a
// general relaxation.
#![deny(unsafe_code)]

//! The certway binary. Everything user-facing: arguments, output, files.
//! `certway-core` never prints; this crate is the only place that does.

pub mod args;
pub mod caps;
pub mod cmd;
pub mod env;
pub mod hooks;
pub mod render;
pub mod report;
pub mod scheduler;
pub mod signal;
pub mod steps;
pub mod store;
pub mod trailer;
pub mod webserver;
