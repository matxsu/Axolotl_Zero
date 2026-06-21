//! Parsing des access bits MIFARE Classic.
//!
//! Le sector trailer (bloc 3 des secteurs 1K, ou bloc 15 des large 4K) :
//! ```text
//!   0..6   : KeyA (toujours lu en zéros)
//!   6..9   : Access bits (3 bytes, avec redondance inversée)
//!   9      : User byte (libre)
//!   10..16 : KeyB
//! ```
//!
//! Les access bits encodent (C1, C2, C3) par bloc (4 jeux : blocs 0,1,2 + trailer).
//! Référence : NXP MF1S503xH datasheet §8.7.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockAccess {
    pub c1: bool,
    pub c2: bool,
    pub c3: bool,
}

impl BlockAccess {
    /// Encodage compact (C1, C2, C3) en valeur 0..7
    pub fn as_octal(&self) -> u8 {
        (self.c1 as u8) << 2 | (self.c2 as u8) << 1 | (self.c3 as u8)
    }

    /// Description lisible de l'accès pour un *bloc de données*.
    /// Format : "rd/wr/inc/dec".
    /// Source : MF1S503xH Table 7.
    pub fn data_block_desc(&self) -> &'static str {
        match self.as_octal() {
            0b000 => "read+write KeyA|B",        // transport
            0b010 => "read KeyA|B, write never", // read-only
            0b100 => "read KeyA|B, write KeyB",
            0b110 => "read KeyA|B, write KeyB, dec KeyA|B",
            0b001 => "read+write+inc+dec KeyA|B (value)",
            0b011 => "read KeyB, write KeyB",
            0b101 => "read KeyB, write never",
            0b111 => "no access",
            _ => "?",
        }
    }
}

/// 4 jeux d'access bits (un par bloc dans la portée du trailer).
/// Pour les small sectors (1K + 4K secteurs 0..31) : 4 blocs (3 data + 1 trailer).
/// Pour les large sectors (4K secteurs 32..39) : 4 groupes de blocs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessConditions {
    pub blocks: [BlockAccess; 4],
}

impl AccessConditions {
    /// Parse les 3 bytes d'access bits (positions 6,7,8 du trailer).
    /// Retourne `None` si la redondance inversée est corrompue.
    pub fn parse(bytes: [u8; 3]) -> Option<Self> {
        let b6 = bytes[0];
        let b7 = bytes[1];
        let b8 = bytes[2];

        // Layout (NXP MF1S503xH Table 6) — chaque nibble :
        //   b6 low  = !C1[3..0],  b6 high = !C2[3..0]
        //   b7 low  = !C3[3..0],  b7 high =  C1[3..0]
        //   b8 low  =  C2[3..0],  b8 high =  C3[3..0]
        let c1_inv = b6 & 0x0F;
        let c2_inv = (b6 >> 4) & 0x0F;
        let c3_inv = b7 & 0x0F;
        let c1 = (b7 >> 4) & 0x0F;
        let c2 = b8 & 0x0F;
        let c3 = (b8 >> 4) & 0x0F;

        // Redondance inversée : Cx XOR !Cx doit valoir 0x0F.
        if (c1 ^ c1_inv) != 0x0F || (c2 ^ c2_inv) != 0x0F || (c3 ^ c3_inv) != 0x0F {
            return None;
        }

        let mut blocks = [BlockAccess::default(); 4];
        for (i, block) in blocks.iter_mut().enumerate() {
            *block = BlockAccess {
                c1: (c1 >> i) & 1 == 1,
                c2: (c2 >> i) & 1 == 1,
                c3: (c3 >> i) & 1 == 1,
            };
        }
        Some(Self { blocks })
    }

    /// Vrai si l'ACL correspond aux access bits par défaut "transport" NXP
    /// (FF 07 80) : data libre, trailer write-KeyA-only.
    pub fn is_factory_default(&self) -> bool {
        self.blocks[0].as_octal() == 0
            && self.blocks[1].as_octal() == 0
            && self.blocks[2].as_octal() == 0
            && self.blocks[3].as_octal() == 0b001
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_default_parses() {
        // 0xFF 0x07 0x80 = défaut NXP
        let acl = AccessConditions::parse([0xFF, 0x07, 0x80]).unwrap();
        // Data blocks (0,1,2) ont C1=C2=C3=0
        assert_eq!(acl.blocks[0].as_octal(), 0);
        assert_eq!(acl.blocks[1].as_octal(), 0);
        assert_eq!(acl.blocks[2].as_octal(), 0);
        // Trailer (block 3) a C3=1, C1=C2=0
        assert_eq!(acl.blocks[3].as_octal(), 0b001);
        assert!(acl.is_factory_default());
    }

    #[test]
    fn corrupted_returns_none() {
        // 0x00 0x00 0x00 : c1=0, c1_inv=0 → c1 ^ c1_inv = 0 ≠ 0x0F
        assert_eq!(AccessConditions::parse([0x00, 0x00, 0x00]), None);
        // 0xFF 0xFF 0xFF : c1=0x0F, c1_inv=0x0F → c1 ^ c1_inv = 0 ≠ 0x0F
        assert_eq!(AccessConditions::parse([0xFF, 0xFF, 0xFF]), None);
    }

    #[test]
    fn data_block_desc_factory() {
        let b = BlockAccess {
            c1: false,
            c2: false,
            c3: false,
        };
        assert_eq!(b.data_block_desc(), "read+write KeyA|B");
    }

    #[test]
    fn data_block_desc_readonly() {
        let b = BlockAccess {
            c1: false,
            c2: true,
            c3: false,
        };
        assert_eq!(b.data_block_desc(), "read KeyA|B, write never");
    }

    #[test]
    fn block_access_as_octal() {
        let b = BlockAccess {
            c1: true,
            c2: false,
            c3: true,
        };
        assert_eq!(b.as_octal(), 0b101);
    }

    #[test]
    fn read_only_acl() {
        // ACL où tous les data blocks sont en lecture seule (C2=1)
        // C1=0000, C2=1110 (blocs 1,2,3), C3=0000
        // Wait — let me build this properly.
        // For blocks 0,1,2: C1=0,C2=1,C3=0 → octal 010 (read-only with KeyA|B)
        // For block 3: factory (001)
        // C1 = 0000, !C1 = 1111
        // C2 = 0111 (block 0,1,2 set), !C2 = 1000
        // C3 = 1000 (block 3 set), !C3 = 0111
        // byte[0] = !C2 nibble high, !C1 nibble low = 1000_1111 = 0x8F
        // byte[1] = C1 high, !C3 low = 0000_0111 = 0x07
        // byte[2] = C3 high, C2 low = 1000_0111 = 0x87
        let acl = AccessConditions::parse([0x8F, 0x07, 0x87]).unwrap();
        assert_eq!(acl.blocks[0].as_octal(), 0b010);
        assert_eq!(acl.blocks[1].as_octal(), 0b010);
        assert_eq!(acl.blocks[2].as_octal(), 0b010);
        assert_eq!(acl.blocks[3].as_octal(), 0b001);
        assert!(!acl.is_factory_default());
    }
}
