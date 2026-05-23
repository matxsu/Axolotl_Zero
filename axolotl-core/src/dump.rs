//! Dump complet d'une carte MIFARE Classic — supporte 1K et 4K.

use crate::layout::ClassicType;

pub struct MifareDump {
    pub card_type: ClassicType,
    pub blocks: Vec<[u8; 16]>,
    pub readable: Vec<bool>,
}

impl MifareDump {
    pub fn new(card_type: ClassicType) -> Self {
        let n = card_type.block_count();
        Self {
            card_type,
            blocks: vec![[0u8; 16]; n],
            readable: vec![false; n],
        }
    }

    /// Nombre de blocs lus avec succès.
    pub fn readable_count(&self) -> usize {
        self.readable.iter().filter(|&&r| r).count()
    }

    /// Nombre total de blocs sur la carte.
    pub fn total_blocks(&self) -> usize {
        self.card_type.block_count()
    }

    /// Sérialise en binaire brut — les blocs non lisibles sont mis à zéro.
    /// Format compatible .mfd (Proxmark3, Flipper Zero).
    /// Taille : 1024 bytes pour 1K, 4096 bytes pour 4K.
    pub fn to_mfd_bytes(&self) -> Vec<u8> {
        let size = self.card_type.dump_size();
        let mut out = vec![0u8; size];
        for (i, block) in self.blocks.iter().enumerate() {
            if self.readable[i] {
                let off = i * 16;
                out[off..off + 16].copy_from_slice(block);
            }
        }
        out
    }

    /// Désérialise depuis un .mfd. La taille doit correspondre à `card_type`
    /// (1024 pour 1K, 4096 pour 4K). Tous les blocs sont marqués lisibles
    /// car on assume que le fichier stocke un dump complet.
    /// Retourne `None` si la taille ne correspond pas.
    pub fn from_mfd_bytes(card_type: ClassicType, data: &[u8]) -> Option<Self> {
        if data.len() != card_type.dump_size() {
            return None;
        }
        let mut dump = Self::new(card_type);
        for i in 0..card_type.block_count() {
            let off = i * 16;
            dump.blocks[i].copy_from_slice(&data[off..off + 16]);
            dump.readable[i] = true;
        }
        Some(dump)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_1k_has_64_blocks() {
        let d = MifareDump::new(ClassicType::Classic1K);
        assert_eq!(d.blocks.len(), 64);
        assert_eq!(d.readable.len(), 64);
        assert_eq!(d.total_blocks(), 64);
        assert_eq!(d.readable_count(), 0);
    }

    #[test]
    fn new_4k_has_256_blocks() {
        let d = MifareDump::new(ClassicType::Classic4K);
        assert_eq!(d.blocks.len(), 256);
        assert_eq!(d.readable.len(), 256);
        assert_eq!(d.total_blocks(), 256);
    }

    #[test]
    fn new_mini_has_20_blocks() {
        let d = MifareDump::new(ClassicType::Mini);
        assert_eq!(d.blocks.len(), 20);
    }

    #[test]
    fn mfd_size_1k_is_1024() {
        let d = MifareDump::new(ClassicType::Classic1K);
        assert_eq!(d.to_mfd_bytes().len(), 1024);
    }

    #[test]
    fn mfd_size_4k_is_4096() {
        let d = MifareDump::new(ClassicType::Classic4K);
        assert_eq!(d.to_mfd_bytes().len(), 4096);
    }

    #[test]
    fn mfd_all_zero_when_nothing_readable() {
        let d = MifareDump::new(ClassicType::Classic1K);
        assert!(d.to_mfd_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn mfd_preserves_readable_blocks() {
        let mut d = MifareDump::new(ClassicType::Classic1K);
        d.blocks[5] = [0xAA; 16];
        d.readable[5] = true;
        let out = d.to_mfd_bytes();
        // Bloc 5 doit être à l'offset 80..96
        assert_eq!(&out[80..96], &[0xAA; 16]);
        // Le reste doit rester zéro
        assert!(out[0..80].iter().all(|&b| b == 0));
        assert!(out[96..].iter().all(|&b| b == 0));
    }

    #[test]
    fn mfd_skips_non_readable_blocks() {
        let mut d = MifareDump::new(ClassicType::Classic1K);
        // On écrit dans les blocs mais on ne marque pas readable
        d.blocks[5] = [0xBB; 16];
        // readable[5] reste false
        let out = d.to_mfd_bytes();
        // La sérialisation doit ignorer le bloc et laisser des zéros
        assert!(out[80..96].iter().all(|&b| b == 0));
    }

    #[test]
    fn readable_count_increments() {
        let mut d = MifareDump::new(ClassicType::Classic1K);
        assert_eq!(d.readable_count(), 0);
        d.readable[0] = true;
        d.readable[5] = true;
        d.readable[63] = true;
        assert_eq!(d.readable_count(), 3);
    }

    #[test]
    fn from_mfd_rejects_wrong_size() {
        // 1K expects 1024 bytes
        assert!(MifareDump::from_mfd_bytes(ClassicType::Classic1K, &[0u8; 512]).is_none());
        assert!(MifareDump::from_mfd_bytes(ClassicType::Classic1K, &[0u8; 1025]).is_none());
        // 4K expects 4096 bytes
        assert!(MifareDump::from_mfd_bytes(ClassicType::Classic4K, &[0u8; 1024]).is_none());
    }

    #[test]
    fn from_mfd_loads_1k() {
        let bytes = vec![0xCDu8; 1024];
        let dump = MifareDump::from_mfd_bytes(ClassicType::Classic1K, &bytes).unwrap();
        assert_eq!(dump.blocks.len(), 64);
        assert!(dump.readable.iter().all(|&r| r));
        for block in &dump.blocks {
            assert_eq!(block, &[0xCD; 16]);
        }
    }

    #[test]
    fn mfd_roundtrip_1k() {
        let mut original = MifareDump::new(ClassicType::Classic1K);
        for i in 0..64 {
            original.blocks[i] = [(i as u8); 16];
            original.readable[i] = true;
        }
        let bytes = original.to_mfd_bytes();
        let restored = MifareDump::from_mfd_bytes(ClassicType::Classic1K, &bytes).unwrap();
        assert_eq!(restored.blocks, original.blocks);
    }

    #[test]
    fn mfd_roundtrip_4k() {
        let mut original = MifareDump::new(ClassicType::Classic4K);
        for i in 0..256 {
            original.blocks[i] = [(i as u8); 16];
            original.readable[i] = true;
        }
        let bytes = original.to_mfd_bytes();
        assert_eq!(bytes.len(), 4096);
        let restored = MifareDump::from_mfd_bytes(ClassicType::Classic4K, &bytes).unwrap();
        assert_eq!(restored.blocks, original.blocks);
    }
}
