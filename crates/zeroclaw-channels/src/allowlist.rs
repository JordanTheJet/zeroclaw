//! Shared `allowed_users` matching used by every chat channel.
//!
//! The matcher primitives now live in [`zeroclaw_config::allowlist`] so the
//! plugin-channel runtime (`zeroclaw-runtime`, which must not depend on this
//! crate) can apply the *same* sender authorization a native channel does — a
//! channel plugin authenticates senders identically to its built-in
//! counterpart. This module re-exports them unchanged so every existing
//! `crate::allowlist::…` call site is untouched.
//!
//! Semantics (unchanged): `["*"]` admits anyone; an empty list denies everyone
//! ("configured but not opened"); otherwise the per-entry comparison —
//! case-sensitive/insensitive exact match, or a caller-provided matcher for
//! domain-class email / E.164 phone — decides.

pub use zeroclaw_config::allowlist::{Match, email_match, is_user_allowed, is_user_allowed_by};
