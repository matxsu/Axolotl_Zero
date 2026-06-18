//! Constantes protocole MIFARE Classic / Ultralight.
pub const MIFARE_AUTH_A: u8 = 0x60;
pub const MIFARE_AUTH_B: u8 = 0x61;
pub const MIFARE_READ: u8 = 0x30;
pub const MIFARE_WRITE: u8 = 0xA0;

/// Ultralight write command — écrit une seule page (4 bytes), différent du
/// Classic WRITE (0xA0) qui écrit un bloc entier (16 bytes).
pub const MIFARE_UL_WRITE: u8 = 0xA2;
