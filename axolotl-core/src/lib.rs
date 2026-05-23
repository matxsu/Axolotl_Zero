//! axolotl-core — Logique pure pour Axolotl Zero.
//!
//! Aucune dépendance sur esp-idf : ce crate est testable sur host avec
//! `cargo test -p axolotl-core`.

pub mod card;
pub mod dump;
pub mod keys;
pub mod layout;
pub mod protocol;

pub use card::NfcUid;
pub use dump::MifareDump;
pub use layout::ClassicType;
