//! Crypto1 — chiffrement propriétaire MIFARE Classic.
//! Port Rust de crapto1 (nfc-tools/mfoc). Réf : Garcia et al.,
//! "Dismantling MIFARE Classic", ESORICS 2008.

/// Polynôme de rétroaction pour les bits impairs (positions 1,3,5,…,47).
const LF_POLY_ODD: u32 = 0x29CE5C;
/// Polynôme de rétroaction pour les bits pairs (positions 0,2,4,…,46).
const LF_POLY_EVEN: u32 = 0x870804;

/// État du Crypto1 : 48 bits répartis en deux mots de 24 bits.
/// `odd`  = bits 1,3,5,…,47 du LFSR 48 bits.
/// `even` = bits 0,2,4,…,46 du LFSR 48 bits.
#[derive(Clone, Copy)]
pub struct Crypto1 {
    pub odd: u32,
    pub even: u32,
}

impl Crypto1 {
    /// Charge la clé de 48 bits — identique à `crypto1_create()` de crapto1.
    /// L'ordre de chargement utilise `^ 7` sur les indices (bit reordering MIFARE).
    pub fn new(key: u64) -> Self {
        let mut s = Crypto1 { odd: 0, even: 0 };
        // k de 23 à 0 → i = 2k+1 de 47 à 1.
        for k in (0..24usize).rev() {
            let i = 2 * k + 1;
            s.odd  = (s.odd  << 1) | ((key >> ((i - 1) ^ 7)) as u32 & 1);
            s.even = (s.even << 1) | ((key >> (i       ^ 7)) as u32 & 1);
        }
        s
    }

    /// Initialise pour une session d'auth MIFARE Classic.
    /// Équivaut à `crypto1_create(key)` + `crypto1_word(s, uid ^ nt, 0)`.
    pub fn init_auth(key: u64, uid: u32, nt: u32) -> Self {
        let mut s = Self::new(key);
        s.word_in(uid ^ nt, false);
        s
    }

    /// Injecte un mot de 32 bits LSB en premier dans le chiffrement.
    /// Équivaut à `crypto1_word(s, word, enc)` de crapto1.
    pub fn word_in(&mut self, word: u32, encrypted: bool) {
        for i in 0..32 {
            let _ = self.step((word >> i) & 1, encrypted);
        }
    }

    /// Un pas du LFSR : retourne le bit de sortie du filtre.
    /// Équivaut à `crypto1_bit()` de crapto1.
    #[inline]
    pub fn step(&mut self, in_bit: u32, encrypted: bool) -> u8 {
        let ret = Self::filter(self.odd);
        let feedin = (ret as u32 & (encrypted as u32)) ^ in_bit
            ^ parity32(LF_POLY_ODD  & self.odd)  as u32
            ^ parity32(LF_POLY_EVEN & self.even) as u32;
        self.even = (self.even << 1) | parity32(LF_POLY_EVEN & self.odd) as u32;
        self.odd  = (self.odd  << 1) | parity32(LF_POLY_ODD  & (self.even >> 1)) as u32;
        self.odd ^= feedin & 1;
        ret
    }

    /// Génère `n` bits du keystream (LSB en premier, bit 0 = premier bit sorti).
    pub fn keystream_bits(&mut self, n: u32) -> u64 {
        let mut ks = 0u64;
        for i in 0..n {
            ks |= (self.step(0, false) as u64) << i;
        }
        ks
    }

    /// Génère 8 bits du keystream (LSB en premier).
    pub fn keystream_byte(&mut self) -> u8 {
        let mut b = 0u8;
        for i in 0..8 {
            b |= self.step(0, false) << i;
        }
        b
    }

    /// Génère 32 bits du keystream (LSB en premier).
    /// Équivaut à `crypto1_word(s, 0, 0)` de crapto1.
    pub fn keystream_word(&mut self) -> u32 {
        let mut w = 0u32;
        for i in 0..32 {
            w |= (self.step(0, false) as u32) << i;
        }
        w
    }

    /// Filtre non-linéaire — port exact de `filter()` de crapto1.
    /// 5 nibbles de `odd` indexent des tables 4→2 bits ; sortie = bit f de 0xe8a7.
    #[inline]
    fn filter(x: u32) -> u8 {
        // wrapping_shr : shift de 32 → 0, comme un overflow unsigned C.
        let mut f: u32;
        f  = 0x000f_22c0_u32.wrapping_shr(1 + (x        & 0xf) * 2) & 3;
        f ^= 0x0006_c9c0_u32.wrapping_shr(1 + (x >>  4  & 0xf) * 2) & 3;
        f ^= 0x0003_c8b0_u32.wrapping_shr(1 + (x >>  8  & 0xf) * 2) & 3;
        f ^= 0x000e_c57e_u32.wrapping_shr(1 + (x >> 12  & 0xf) * 2) & 3;
        f ^= 0x000f_4d5a_u32.wrapping_shr(1 + (x >> 16  & 0xf) * 2) & 3;
        ((0xe8a7_u32 >> f) & 1) as u8
    }
}

/// Parité d'un mot 32 bits (XOR de tous les bits).
#[inline]
pub fn parity32(x: u32) -> u8 {
    let mut p = x;
    p ^= p >> 16;
    p ^= p >> 8;
    p ^= p >> 4;
    p ^= p >> 2;
    p ^= p >> 1;
    (p & 1) as u8
}

/// Parité d'un byte.
#[inline]
pub fn parity_byte(b: u8) -> u8 {
    let mut p = b;
    p ^= p >> 4;
    p ^= p >> 2;
    p ^= p >> 1;
    p & 1
}

// PRNG carte MIFARE Classic — LFSR 32 bits (libnfc/mfoc) :
// feedback = bit0 ^ bit2 ^ bit3 ^ bit5 ; x_new = (x >> 1) | (feedback << 31).

/// Un pas du PRNG MIFARE Classic.
#[inline]
pub fn prng_successor(x: u32) -> u32 {
    let feedback = (x ^ (x >> 2) ^ (x >> 3) ^ (x >> 5)) & 1;
    (x >> 1) | (feedback << 31)
}

/// Avance le PRNG de `n` pas.
pub fn prng_advance(state: u32, n: u32) -> u32 {
    let mut s = state;
    for _ in 0..n {
        s = prng_successor(s);
    }
    s
}

/// Vérifie si `nt2 = prng_advance(nt1, steps ± tolerance)`.
pub fn prng_is_successor(nt1: u32, nt2: u32, steps: u32, tolerance: u32) -> bool {
    let lo = steps.saturating_sub(tolerance);
    let hi = steps + tolerance;
    for n in lo..=hi {
        if prng_advance(nt1, n) == nt2 {
            return true;
        }
    }
    false
}

/// Déchiffre NT2 chiffré obtenu lors d'une nested auth.
/// `uid` : UID 4 octets de la carte (nécessaire pour init Crypto1).
pub fn decrypt_nested_nt(enc_nt2: u32, uid: u32, nt1: u32, key: u64) -> u32 {
    let mut c1 = Crypto1::init_auth(key, uid, nt1);
    // Avance de 64 bits : NR (32) + AR (32).
    let _ = c1.keystream_word(); // KS1 (NR mask)
    let _ = c1.keystream_word(); // KS2 (AR mask)
    // NT2 est livré après AT (32 bits supplémentaires).
    let ks3 = c1.keystream_word();
    enc_nt2 ^ ks3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parity32() {
        assert_eq!(parity32(0), 0);
        assert_eq!(parity32(1), 1);
        assert_eq!(parity32(0b11), 0);
        assert_eq!(parity32(0b111), 1);
        assert_eq!(parity32(0xFFFF_FFFF), 0);
    }

    #[test]
    fn test_prng_advance() {
        let nt0 = 0xAB12_CD34_u32;
        let nt1 = prng_advance(nt0, 1);
        let nt2 = prng_advance(nt0, 2);
        assert_ne!(nt1, nt0);
        assert_ne!(nt2, nt1);
        // Cohérence : avancer de 1 depuis nt1 == avancer de 2 depuis nt0.
        assert_eq!(prng_advance(nt1, 1), nt2);
        assert_ne!(nt1, 0u32);
    }

    #[test]
    fn test_crypto1_key_load_nonzero() {
        // Après chargement d'une clé non-nulle, l'état doit être non-nul.
        let key = 0xA0A1_A2A3_A4A5_u64;
        let s = Crypto1::new(key);
        assert!(s.odd != 0 || s.even != 0);
    }

    #[test]
    fn test_crypto1_filter_determinism() {
        // Le filtre est une fonction pure — mêmes entrées = même sortie.
        let key = 0xFFFF_FFFF_FFFF_u64;
        let uid = 0x1122_3344_u32;
        let nt  = 0xABCD_EF01_u32;
        let mut c1a = Crypto1::init_auth(key, uid, nt);
        let mut c1b = Crypto1::init_auth(key, uid, nt);
        for _ in 0..64 {
            assert_eq!(c1a.step(0, false), c1b.step(0, false));
        }
    }

    #[test]
    fn test_crypto1_keystream_nonzero() {
        // Avec une clé réelle et uid/nt non nuls, le keystream ne doit pas être tout-zéro.
        let key = 0xA0A1_A2A3_A4A5_u64;
        let uid = 0x6263_6465_u32;
        let nt  = 0x9E98_A333_u32;
        let mut c1 = Crypto1::init_auth(key, uid, nt);
        let ks = c1.keystream_word();
        // Probabilité que ks == 0 par hasard : 1/2^32 — si ça arrive le cipher est cassé.
        assert_ne!(ks, 0);
    }
}
