//! [![github]](https://github.com/emo-crab/scap-rs)&ensp;[![crates-io]](https://crates.io/crates/nvd-cwe)&ensp;[![docs-rs]](crate)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! The CWE Schema is maintained by The MITRE Corporation and developed in partnership with the
//! public CWE Community. For more information, including how to get involved in the project and
//! how to submit change requests, please visit the CWE website at <https://cwe.mitre.org>.
//!

// https://cwe.mitre.org/data/downloads.html
pub mod categories;
pub mod content_history;
pub mod external_references;
pub mod mapping_notes;
pub mod notes;
pub mod relationships;
pub mod structured_text;
pub mod views;
pub mod weakness_catalog;
pub mod weaknesses;
