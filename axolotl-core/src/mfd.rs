//! Détection automatique du format .mfd via la taille du fichier.
//!
//! Convention Proxmark / Flipper Zero :
//! - Mini : 320 bytes
//! - 1K   : 1024 bytes
//! - 4K   : 4096 bytes

use crate::layout::ClassicType;

/// Devine le type de carte d'après la taille en bytes du dump.
pub fn detect_format(byte_count: usize) -> Option<ClassicType> {
    match byte_count {
        320 => Some(ClassicType::Mini),
        1024 => Some(ClassicType::Classic1K),
        4096 => Some(ClassicType::Classic4K),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_1k() {
        assert_eq!(detect_format(1024), Some(ClassicType::Classic1K));
    }

    #[test]
    fn detect_4k() {
        assert_eq!(detect_format(4096), Some(ClassicType::Classic4K));
    }

    #[test]
    fn detect_mini() {
        assert_eq!(detect_format(320), Some(ClassicType::Mini));
    }

    #[test]
    fn detect_invalid() {
        assert_eq!(detect_format(0), None);
        assert_eq!(detect_format(1023), None);
        assert_eq!(detect_format(2048), None);
        assert_eq!(detect_format(usize::MAX), None);
    }

    /// Confirme que pour chaque type valide, sa taille round-trip via detect_format.
    #[test]
    fn detect_roundtrip() {
        for t in [
            ClassicType::Mini,
            ClassicType::Classic1K,
            ClassicType::Classic4K,
        ] {
            assert_eq!(detect_format(t.dump_size()), Some(t));
        }
    }
}
