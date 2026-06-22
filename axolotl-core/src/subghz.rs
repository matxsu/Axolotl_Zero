//! Sub-GHz : parsing des fichiers `.sub` (format Flipper Zero) et encodage des
//! protocoles en une **liste de timings canonique**.
//!
//! Pourquoi ce module vit dans `axolotl-core` (donc testable sur PC, sans
//! matériel) : toute la logique « protocole → durées » est de la manipulation
//! d'octets/durées. Le firmware (`subghz.rs`) ne fait qu'émettre cette liste de
//! timings sur le CC1101 (RMT pour du fidèle, FIFO pour de l'approximatif).
//!
//! ## Représentation canonique des timings
//! Un signal OOK est une suite de durées en µs, convention Flipper RAW :
//!   - valeur **positive** = porteuse active (tone),
//!   - valeur **négative** = silence.
//! Exactement le format `RAW_Data:` des fichiers `.sub`, ce qui rend le RAW
//! triviale à rejouer et l'encodage de protocole comparable au RAW capturé.

use core::fmt;

/// Erreur de parsing/encodage `.sub`.
#[derive(Debug, PartialEq)]
pub enum SubError {
    /// Champ obligatoire absent (`Frequency`, `Protocol`, …).
    MissingField(&'static str),
    /// Valeur numérique non parsable.
    BadNumber(&'static str),
    /// Protocole connu mais non encodable (rolling code, etc.).
    Unsupported(&'static str),
}

impl fmt::Display for SubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubError::MissingField(s) => write!(f, "champ manquant: {s}"),
            SubError::BadNumber(s) => write!(f, "nombre invalide: {s}"),
            SubError::Unsupported(s) => write!(f, "protocole non supporté: {s}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, SubError>;

/// Preset CC1101 référencé par le `.sub` (= jeu de registres modulation/BW/débit).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Preset {
    /// OOK/ASK, BW 650 kHz — le cas ultra-majoritaire des télécommandes.
    Ook650Async,
    /// OOK/ASK, BW 270 kHz.
    Ook270Async,
    /// 2-FSK, déviation 2.38 kHz.
    Fsk238Async,
    /// 2-FSK, déviation 47.6 kHz.
    Fsk476Async,
    /// Preset custom (table de registres dans le fichier) — non interprété ici.
    Custom,
}

impl Preset {
    fn from_str(s: &str) -> Preset {
        match s {
            "FuriHalSubGhzPresetOok650Async" => Preset::Ook650Async,
            "FuriHalSubGhzPresetOok270Async" => Preset::Ook270Async,
            "FuriHalSubGhzPreset2FSKDev238Async" => Preset::Fsk238Async,
            "FuriHalSubGhzPreset2FSKDev476Async" => Preset::Fsk476Async,
            _ => Preset::Custom,
        }
    }

    /// True si le preset est de l'OOK (rejouable en FIFO sans GDO0).
    pub fn is_ook(self) -> bool {
        matches!(self, Preset::Ook650Async | Preset::Ook270Async)
    }
}

/// Protocole décodé du `.sub`.
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    /// Capture brute : la liste de timings est déjà dans le fichier.
    Raw { timings: Vec<i32> },
    /// Princeton (code fixe 24 bits, le plus courant pour portails/garages).
    Princeton { key: u64, bits: u8, te_us: u32 },
    /// Protocole reconnu mais pas (encore) encodable côté Axolotl.
    Unsupported(String),
}

/// Un fichier `.sub` parsé.
#[derive(Debug, Clone, PartialEq)]
pub struct SubFile {
    pub frequency_hz: u32,
    pub preset: Preset,
    pub protocol: Protocol,
}

impl SubFile {
    /// Parse le contenu texte d'un fichier `.sub`.
    ///
    /// Tolérant : ignore les lignes inconnues, accepte les `RAW_Data:` sur
    /// plusieurs lignes (le Flipper découpe les longues captures).
    pub fn parse(text: &str) -> Result<SubFile> {
        let mut frequency: Option<u32> = None;
        let mut preset = Preset::Ook650Async;
        let mut proto_name: Option<String> = None;
        let mut bit: Option<u8> = None;
        let mut te: Option<u32> = None;
        let mut key: Option<u64> = None;
        let mut raw: Vec<i32> = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            let Some((tag, val)) = line.split_once(':') else {
                continue;
            };
            let val = val.trim();
            match tag.trim() {
                "Frequency" => {
                    frequency = Some(val.parse().map_err(|_| SubError::BadNumber("Frequency"))?)
                }
                "Preset" => preset = Preset::from_str(val),
                "Protocol" => proto_name = Some(val.to_string()),
                "Bit" => bit = Some(val.parse().map_err(|_| SubError::BadNumber("Bit"))?),
                "TE" => te = Some(val.parse().map_err(|_| SubError::BadNumber("TE"))?),
                "Key" => key = Some(parse_hex_u64(val)?),
                "RAW_Data" => {
                    for tok in val.split_whitespace() {
                        raw.push(tok.parse().map_err(|_| SubError::BadNumber("RAW_Data"))?);
                    }
                }
                _ => {} // Version, Filetype, Guard_time, Repeat, … : ignorés
            }
        }

        let frequency_hz = frequency.ok_or(SubError::MissingField("Frequency"))?;
        let proto_name = proto_name.ok_or(SubError::MissingField("Protocol"))?;

        let protocol = match proto_name.as_str() {
            "RAW" | "BinRAW" => Protocol::Raw { timings: raw },
            "Princeton" => Protocol::Princeton {
                key: key.ok_or(SubError::MissingField("Key"))?,
                bits: bit.unwrap_or(24),
                // TE par défaut Princeton ≈ 390 µs si absent.
                te_us: te.unwrap_or(390),
            },
            other => Protocol::Unsupported(other.to_string()),
        };

        Ok(SubFile {
            frequency_hz,
            preset,
            protocol,
        })
    }

    /// Convertit le protocole en liste de timings canonique prête à émettre.
    ///
    /// `repeat` ne s'applique qu'aux protocoles décodés (le RAW contient déjà
    /// ses répétitions). Erreur si le protocole n'est pas encodable.
    pub fn to_timings(&self, repeat: u8) -> Result<Vec<i32>> {
        match &self.protocol {
            Protocol::Raw { timings } => Ok(timings.clone()),
            Protocol::Princeton { key, bits, te_us } => {
                Ok(encode_princeton(*key, *bits, *te_us, repeat.max(1)))
            }
            Protocol::Unsupported(_) => Err(SubError::Unsupported("replay")),
        }
    }
}

/// Encode un code Princeton en timings µs (convention +tone / −silence).
///
/// Princeton (cf. datasheet PT2262 / décodage Flipper) :
///   - bit `1` : tone long (3·te) puis silence court (te),
///   - bit `0` : tone court (te) puis silence long (3·te),
///   - stop : tone court (te) puis long silence de garde (≈ 30·te).
/// Les bits sont émis du MSB au LSB sur `bits` bits.
pub fn encode_princeton(key: u64, bits: u8, te_us: u32, repeat: u8) -> Vec<i32> {
    let te = te_us as i32;
    let long = 3 * te;
    let mut out = Vec::with_capacity((bits as usize * 2 + 2) * repeat as usize);
    for _ in 0..repeat {
        for i in (0..bits).rev() {
            if (key >> i) & 1 == 1 {
                out.push(long); // tone long
                out.push(-te); // silence court
            } else {
                out.push(te); // tone court
                out.push(-long); // silence long
            }
        }
        // Bit de stop + silence de garde (sépare les répétitions).
        out.push(te);
        out.push(-30 * te);
    }
    out
}

/// Parse une suite d'octets hexa séparés par des espaces ("00 52 81 1C") en u64
/// big-endian (les octets de poids fort en premier).
fn parse_hex_u64(s: &str) -> Result<u64> {
    let mut v: u64 = 0;
    for tok in s.split_whitespace() {
        let byte = u8::from_str_radix(tok, 16).map_err(|_| SubError::BadNumber("Key"))?;
        v = (v << 8) | byte as u64;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINCETON_SUB: &str = "Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: Princeton
Bit: 24
Key: 00 00 00 00 00 52 81 1C
TE: 154";

    const RAW_SUB: &str = "Filetype: Flipper SubGhz RAW File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: RAW
RAW_Data: 133 -4806 163 -468 453 -166
RAW_Data: 123 -500 437 -200";

    #[test]
    fn parse_princeton_fields() {
        let s = SubFile::parse(PRINCETON_SUB).unwrap();
        assert_eq!(s.frequency_hz, 433_920_000);
        assert_eq!(s.preset, Preset::Ook650Async);
        assert_eq!(
            s.protocol,
            Protocol::Princeton {
                key: 0x52811C,
                bits: 24,
                te_us: 154,
            }
        );
    }

    #[test]
    fn parse_raw_accumulates_multiline() {
        let s = SubFile::parse(RAW_SUB).unwrap();
        assert_eq!(
            s.protocol,
            Protocol::Raw {
                timings: vec![133, -4806, 163, -468, 453, -166, 123, -500, 437, -200],
            }
        );
    }

    #[test]
    fn princeton_encodes_msb_first() {
        // Key 0x52811C / 24 bits = 0101 0010 1000 0001 0001 1100.
        // 1er bit (MSB) = 0 → [te, -3te] ; 2e bit = 1 → [3te, -te].
        let t = encode_princeton(0x52811C, 24, 154, 1);
        assert_eq!(&t[0..4], &[154, -462, 462, -154]);
        // 24 bits × 2 + stop(2) = 50 éléments.
        assert_eq!(t.len(), 50);
        // Stop : tone court + long silence de garde.
        assert_eq!(&t[48..50], &[154, -30 * 154]);
    }

    #[test]
    fn princeton_repeat_multiplies() {
        let one = encode_princeton(0x52811C, 24, 154, 1).len();
        let three = encode_princeton(0x52811C, 24, 154, 3).len();
        assert_eq!(three, one * 3);
    }

    #[test]
    fn raw_to_timings_passthrough() {
        let s = SubFile::parse(RAW_SUB).unwrap();
        assert_eq!(s.to_timings(5).unwrap(), vec![
            133, -4806, 163, -468, 453, -166, 123, -500, 437, -200
        ]);
    }

    #[test]
    fn rolling_code_unsupported_for_replay() {
        let sub = "Frequency: 433920000\nProtocol: KeeLoq\nBit: 64\nKey: 00 11 22 33 44 55 66 77";
        let s = SubFile::parse(sub).unwrap();
        assert_eq!(s.protocol, Protocol::Unsupported("KeeLoq".to_string()));
        assert_eq!(s.to_timings(1), Err(SubError::Unsupported("replay")));
    }

    #[test]
    fn missing_frequency_errors() {
        let sub = "Protocol: RAW\nRAW_Data: 100 -100";
        assert_eq!(SubFile::parse(sub), Err(SubError::MissingField("Frequency")));
    }
}
