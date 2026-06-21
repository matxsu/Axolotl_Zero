//! Layout des cartes MIFARE Classic — math pure secteur/bloc.
//!
//! - Mini : 5 secteurs × 4 blocs = 20 blocs (320 bytes)
//! - 1K : 16 secteurs × 4 blocs = 64 blocs (1024 bytes)
//! - 4K : 32 secteurs × 4 blocs + 8 secteurs × 16 blocs = 256 blocs (4096 bytes)
//!
//! Le piège du 4K : les secteurs ≥ 32 contiennent 16 blocs au lieu de 4.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClassicType {
    Mini,
    Classic1K,
    Classic4K,
}

impl ClassicType {
    /// Détecte le type d'après le SAK.
    /// Retourne `None` si le SAK ne correspond à aucun MIFARE Classic.
    pub fn from_sak(sak: u8) -> Option<Self> {
        match sak {
            0x08 | 0x88 | 0x28 => Some(Self::Classic1K),
            0x18 | 0x38 => Some(Self::Classic4K),
            0x09 => Some(Self::Mini),
            _ => None,
        }
    }

    pub fn sector_count(self) -> u8 {
        match self {
            Self::Mini => 5,
            Self::Classic1K => 16,
            Self::Classic4K => 40,
        }
    }

    pub fn block_count(self) -> usize {
        match self {
            Self::Mini => 20,
            Self::Classic1K => 64,
            Self::Classic4K => 256,
        }
    }

    /// Taille totale en bytes (1 bloc = 16 bytes).
    pub fn dump_size(self) -> usize {
        self.block_count() * 16
    }

    /// Nombre de blocs dans un secteur donné.
    /// - 4K : secteurs 0..32 → 4 blocs, secteurs 32..40 → 16 blocs.
    /// - 1K/Mini : toujours 4 blocs.
    pub fn sector_block_count(self, sector: u8) -> u8 {
        match self {
            Self::Classic4K if (32..40).contains(&sector) => 16,
            _ => 4,
        }
    }

    /// Index du premier bloc d'un secteur, ou `None` si secteur hors limite.
    pub fn sector_first_block(self, sector: u8) -> Option<u8> {
        if sector >= self.sector_count() {
            return None;
        }
        match self {
            Self::Mini | Self::Classic1K => Some(sector * 4),
            Self::Classic4K => {
                if sector < 32 {
                    Some(sector * 4)
                } else {
                    // Secteurs 32..39 : 16 blocs chacun, démarrent à 128.
                    Some(128 + (sector - 32) * 16)
                }
            }
        }
    }

    /// Index du bloc trailer (le dernier bloc, contenant KeyA + AC + KeyB).
    /// Le calcul passe par u16 car pour 4K secteur 39 : 240 + 16 = 256 (overflow u8).
    pub fn sector_trailer(self, sector: u8) -> Option<u8> {
        let first = self.sector_first_block(sector)? as u16;
        let count = self.sector_block_count(sector) as u16;
        Some((first + count - 1) as u8)
    }

    /// Vrai si `block` est un sector trailer.
    pub fn is_trailer(self, block: usize) -> bool {
        if block >= self.block_count() {
            return false;
        }
        match self {
            Self::Mini | Self::Classic1K => block % 4 == 3,
            Self::Classic4K => {
                if block < 128 {
                    block % 4 == 3
                } else {
                    (block - 128) % 16 == 15
                }
            }
        }
    }

    /// Vrai si `block` est un bloc data (ni bloc 0 manufacturer, ni trailer).
    pub fn is_data_block(self, block: usize) -> bool {
        block != 0 && block < self.block_count() && !self.is_trailer(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_sak_classic_1k() {
        assert_eq!(ClassicType::from_sak(0x08), Some(ClassicType::Classic1K));
        assert_eq!(ClassicType::from_sak(0x88), Some(ClassicType::Classic1K));
        assert_eq!(ClassicType::from_sak(0x28), Some(ClassicType::Classic1K));
    }

    #[test]
    fn from_sak_classic_4k() {
        assert_eq!(ClassicType::from_sak(0x18), Some(ClassicType::Classic4K));
        assert_eq!(ClassicType::from_sak(0x38), Some(ClassicType::Classic4K));
    }

    #[test]
    fn from_sak_mini() {
        assert_eq!(ClassicType::from_sak(0x09), Some(ClassicType::Mini));
    }

    #[test]
    fn from_sak_not_classic() {
        assert_eq!(ClassicType::from_sak(0x00), None); // Ultralight
        assert_eq!(ClassicType::from_sak(0x20), None); // ISO 14443-4
        assert_eq!(ClassicType::from_sak(0xFF), None);
    }

    #[test]
    fn classic_1k_counts() {
        let c = ClassicType::Classic1K;
        assert_eq!(c.sector_count(), 16);
        assert_eq!(c.block_count(), 64);
        assert_eq!(c.dump_size(), 1024);
    }

    #[test]
    fn classic_4k_counts() {
        let c = ClassicType::Classic4K;
        assert_eq!(c.sector_count(), 40);
        assert_eq!(c.block_count(), 256);
        assert_eq!(c.dump_size(), 4096);
    }

    #[test]
    fn classic_1k_sector_layout() {
        let c = ClassicType::Classic1K;
        assert_eq!(c.sector_first_block(0), Some(0));
        assert_eq!(c.sector_first_block(15), Some(60));
        assert_eq!(c.sector_first_block(16), None);
        assert_eq!(c.sector_trailer(0), Some(3));
        assert_eq!(c.sector_trailer(15), Some(63));
        assert_eq!(c.sector_block_count(0), 4);
        assert_eq!(c.sector_block_count(15), 4);
    }

    #[test]
    fn classic_4k_small_sectors() {
        let c = ClassicType::Classic4K;
        // Secteurs 0..31 : 4 blocs chacun
        assert_eq!(c.sector_first_block(0), Some(0));
        assert_eq!(c.sector_first_block(31), Some(124));
        assert_eq!(c.sector_trailer(0), Some(3));
        assert_eq!(c.sector_trailer(31), Some(127));
        assert_eq!(c.sector_block_count(31), 4);
    }

    #[test]
    fn classic_4k_large_sectors() {
        let c = ClassicType::Classic4K;
        // Secteurs 32..39 : 16 blocs chacun, démarrent à 128
        assert_eq!(c.sector_first_block(32), Some(128));
        assert_eq!(c.sector_first_block(33), Some(144));
        assert_eq!(c.sector_first_block(39), Some(240));
        // Le bloc trailer est le 16ème (offset +15)
        assert_eq!(c.sector_trailer(32), Some(143));
        assert_eq!(c.sector_trailer(39), Some(255));
        assert_eq!(c.sector_block_count(32), 16);
        assert_eq!(c.sector_block_count(39), 16);
    }

    #[test]
    fn classic_4k_out_of_bounds() {
        let c = ClassicType::Classic4K;
        assert_eq!(c.sector_first_block(40), None);
        assert_eq!(c.sector_trailer(40), None);
    }

    /// Vérifie qu'il n'y a pas de chevauchement de blocs entre secteurs
    /// et que le dernier bloc du secteur N précède le premier du secteur N+1.
    #[test]
    fn classic_4k_no_overlap() {
        let c = ClassicType::Classic4K;
        for s in 0..(c.sector_count() - 1) {
            let trailer = c.sector_trailer(s).unwrap();
            let next_first = c.sector_first_block(s + 1).unwrap();
            assert_eq!(
                next_first,
                trailer + 1,
                "secteur {} trailer={} mais secteur {} start={}",
                s,
                trailer,
                s + 1,
                next_first
            );
        }
    }

    #[test]
    fn classic_1k_trailers() {
        let c = ClassicType::Classic1K;
        // Trailers à 3, 7, 11, ..., 63
        for s in 0..16u8 {
            let trailer = (s * 4 + 3) as usize;
            assert!(c.is_trailer(trailer), "block {} doit etre trailer", trailer);
        }
        // Blocs 0, 1, 2 ne sont pas des trailers
        assert!(!c.is_trailer(0));
        assert!(!c.is_trailer(1));
        assert!(!c.is_trailer(2));
        assert!(!c.is_trailer(60));
        // Hors plage
        assert!(!c.is_trailer(64));
    }

    #[test]
    fn classic_4k_trailers() {
        let c = ClassicType::Classic4K;
        // Small sectors 0..31 : trailers à 3, 7, ..., 127
        for s in 0..32u8 {
            let trailer = (s * 4 + 3) as usize;
            assert!(c.is_trailer(trailer), "small trailer {} loupe", trailer);
        }
        // Large sectors 32..39 : trailers à 143, 159, ..., 255
        for s in 0..8u8 {
            let trailer = 128 + (s as usize) * 16 + 15;
            assert!(c.is_trailer(trailer), "large trailer {} loupe", trailer);
        }
        // Bloc 128 (premier bloc du secteur 32) n'est PAS trailer
        assert!(!c.is_trailer(128));
        assert!(!c.is_trailer(142)); // avant-dernier du large secteur 32
        // Hors plage
        assert!(!c.is_trailer(256));
    }

    #[test]
    fn is_data_block_excludes_block0_and_trailers() {
        let c = ClassicType::Classic1K;
        // Block 0 = manufacturer
        assert!(!c.is_data_block(0));
        // Block 3 = trailer
        assert!(!c.is_data_block(3));
        // Block 1, 2 = data
        assert!(c.is_data_block(1));
        assert!(c.is_data_block(2));
        // Block 60 = data (first of sector 15)
        assert!(c.is_data_block(60));
        // Block 63 = trailer
        assert!(!c.is_data_block(63));
        // Hors plage
        assert!(!c.is_data_block(64));
    }
}
