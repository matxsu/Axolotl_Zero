//! Diff entre deux MifareDump — utile pour détecter des changements
//! sur une carte de monnaie/badge dans le temps.

use crate::dump::MifareDump;

#[derive(Debug, PartialEq, Eq)]
pub struct BlockDiff {
    pub block: usize,
    pub old: [u8; 16],
    pub new: [u8; 16],
}

/// Compare deux dumps et retourne la liste des blocs qui diffèrent.
/// Les deux dumps doivent être du même `ClassicType` (sinon liste vide).
/// Un bloc non lisible dans l'un des deux est ignoré (pas remonté).
pub fn dump_diff(old: &MifareDump, new: &MifareDump) -> Vec<BlockDiff> {
    if old.card_type != new.card_type {
        return Vec::new();
    }
    let mut out = Vec::new();
    let n = old.total_blocks().min(new.total_blocks());
    for i in 0..n {
        if !old.readable[i] || !new.readable[i] {
            continue;
        }
        if old.blocks[i] != new.blocks[i] {
            out.push(BlockDiff {
                block: i,
                old: old.blocks[i],
                new: new.blocks[i],
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::ClassicType;

    #[test]
    fn identical_dumps_have_no_diff() {
        let mut d = MifareDump::new(ClassicType::Classic1K);
        for i in 0..64 {
            d.blocks[i] = [i as u8; 16];
            d.readable[i] = true;
        }
        let d2 = MifareDump::from_mfd_bytes(ClassicType::Classic1K, &d.to_mfd_bytes()).unwrap();
        assert!(dump_diff(&d, &d2).is_empty());
    }

    #[test]
    fn one_changed_block_returns_one_diff() {
        let mut a = MifareDump::new(ClassicType::Classic1K);
        let mut b = MifareDump::new(ClassicType::Classic1K);
        for i in 0..64 {
            a.blocks[i] = [0; 16];
            a.readable[i] = true;
            b.blocks[i] = [0; 16];
            b.readable[i] = true;
        }
        b.blocks[5] = [0xFF; 16];
        let diffs = dump_diff(&a, &b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].block, 5);
        assert_eq!(diffs[0].old, [0; 16]);
        assert_eq!(diffs[0].new, [0xFF; 16]);
    }

    #[test]
    fn non_readable_blocks_excluded() {
        let mut a = MifareDump::new(ClassicType::Classic1K);
        let mut b = MifareDump::new(ClassicType::Classic1K);
        // Block 5 has different content but only readable in `a`
        a.blocks[5] = [0xAA; 16];
        a.readable[5] = true;
        b.blocks[5] = [0xBB; 16];
        // b.readable[5] reste false
        assert!(dump_diff(&a, &b).is_empty());
    }

    #[test]
    fn type_mismatch_returns_empty() {
        let a = MifareDump::new(ClassicType::Classic1K);
        let b = MifareDump::new(ClassicType::Classic4K);
        assert!(dump_diff(&a, &b).is_empty());
    }
}
