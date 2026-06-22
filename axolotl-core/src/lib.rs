//! axolotl-core — Logique pure pour Axolotl Zero.
//!
//! Aucune dépendance sur esp-idf : ce crate est testable sur host avec
//! `cargo test -p axolotl-core`.

pub mod acl;
pub mod card;
pub mod crypto1;
pub mod diff;
pub mod dump;
pub mod keys;
pub mod layout;
pub mod mfd;
pub mod protocol;
pub mod subghz;

pub use card::NfcUid;
pub use dump::MifareDump;
pub use layout::ClassicType;
