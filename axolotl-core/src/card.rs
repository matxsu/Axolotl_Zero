//! Identifiant de carte NFC ISO 14443A.

pub struct NfcUid {
    pub bytes: [u8; 7],
    pub len: usize,
    pub atqa: [u8; 2],
    pub sak: u8,
}

impl NfcUid {
    /// Nom lisible du type de carte d'après le SAK.
    /// Référence : NXP AN10833 Table 4.
    pub fn card_type(&self) -> &'static str {
        match self.sak {
            0x08 | 0x88 | 0x28 => "MIFARE Classic 1K",
            0x18 | 0x38 => "MIFARE Classic 4K",
            0x09 => "MIFARE Mini",
            0x00 => "NTAG/Ultralight",
            0x20 => "ISO 14443-4",
            _ => "ISO 14443A",
        }
    }

    /// Vrai si la carte parle Crypto1 (auth par clé KeyA/KeyB).
    pub fn is_mifare_classic(&self) -> bool {
        matches!(self.sak, 0x08 | 0x09 | 0x18 | 0x28 | 0x38 | 0x88)
    }

    /// Vrai si la carte est une Ultralight ou NTAG (lecture sans auth).
    pub fn is_ultralight(&self) -> bool {
        self.sak == 0x00
    }

    /// Représentation hex compacte `XX:XX:XX:XX`.
    pub fn to_hex(&self) -> heapless::String<32> {
        let mut s: heapless::String<32> = heapless::String::new();
        for i in 0..self.len {
            if i > 0 {
                s.push(':').ok();
            }
            let b = self.bytes[i];
            s.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap_or('?')
                    .to_ascii_uppercase(),
            )
            .ok();
            s.push(
                char::from_digit((b & 0xF) as u32, 16)
                    .unwrap_or('?')
                    .to_ascii_uppercase(),
            )
            .ok();
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid_with_sak(sak: u8) -> NfcUid {
        NfcUid {
            bytes: [0; 7],
            len: 4,
            atqa: [0x00, 0x04],
            sak,
        }
    }

    #[test]
    fn card_type_classic_1k() {
        for sak in [0x08, 0x88, 0x28] {
            let u = uid_with_sak(sak);
            assert_eq!(u.card_type(), "MIFARE Classic 1K", "sak={:#04x}", sak);
            assert!(u.is_mifare_classic());
            assert!(!u.is_ultralight());
        }
    }

    #[test]
    fn card_type_classic_4k() {
        for sak in [0x18, 0x38] {
            let u = uid_with_sak(sak);
            assert_eq!(u.card_type(), "MIFARE Classic 4K", "sak={:#04x}", sak);
            assert!(u.is_mifare_classic());
        }
    }

    #[test]
    fn card_type_ultralight() {
        let u = uid_with_sak(0x00);
        assert_eq!(u.card_type(), "NTAG/Ultralight");
        assert!(!u.is_mifare_classic());
        assert!(u.is_ultralight());
    }

    #[test]
    fn card_type_unknown_falls_back() {
        let u = uid_with_sak(0xFF);
        assert_eq!(u.card_type(), "ISO 14443A");
    }

    #[test]
    fn to_hex_4_byte_uid() {
        let mut u = uid_with_sak(0x08);
        u.bytes[0..4].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x12]);
        u.len = 4;
        assert_eq!(u.to_hex().as_str(), "AB:CD:EF:12");
    }

    #[test]
    fn to_hex_7_byte_uid() {
        let mut u = uid_with_sak(0x00);
        u.bytes = [0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6];
        u.len = 7;
        assert_eq!(u.to_hex().as_str(), "04:A1:B2:C3:D4:E5:F6");
    }

    #[test]
    fn to_hex_pads_low_nibble() {
        let mut u = uid_with_sak(0x08);
        u.bytes[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        u.len = 4;
        assert_eq!(u.to_hex().as_str(), "01:02:03:04");
    }
}
