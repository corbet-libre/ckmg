//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`it::<name>::<test>`); `tests/unit` still holds the library's `#[path]` unit tests.
mod account_device;
mod account_signing;
mod attestation;
mod browser_tor;
mod current_signing;
mod device_certificate;
mod device_formats;
mod device_scope;
mod device_signing;
mod intent;
mod keys;
mod mutant_kills_mut101;
mod mutant_kills_mut115;
mod native_records;
mod native_tor;
mod passport;
mod profile_custody;
mod record_recipient;
mod support;
mod transient_authority;
mod transport_authority;
mod transport_session;
mod wallet_engine;
