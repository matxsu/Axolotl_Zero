//! BadUSB via clavier HID **Bluetooth LE** (`esp32-nimble`).
//!
//! Porté depuis `feature/wifi_attacks:src/badusb.rs`. Adaptation menu : le
//! bouton retour (`back`) permet de quitter l'écran d'attente/payload.
//!
//! NOTE : c'est un clavier **BLE** (appairage « Axolotl Keyboard »), pas de
//! l'USB HID natif OTG visé à terme par le CDC — le BLE est le premier jet
//! fonctionnel. Layout clavier **AZERTY (FR)**.

use esp32_nimble::{
    enums::*, hid::*, utilities::mutex::Mutex, BLEAdvertisementData, BLECharacteristic, BLEDevice, BLEHIDDevice,
    BLEServer,
};
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use std::sync::Arc;
use log::info;

const KEYBOARD_ID: u8 = 0x01;
const MEDIA_KEYS_ID: u8 = 0x02;

const HID_REPORT_DESCRIPTOR: &[u8] = hid!(
    (USAGE_PAGE, 0x01),
    (USAGE, 0x06),
    (COLLECTION, 0x01),
    (REPORT_ID, KEYBOARD_ID),
    (USAGE_PAGE, 0x07),
    (USAGE_MINIMUM, 0xE0),
    (USAGE_MAXIMUM, 0xE7),
    (LOGICAL_MINIMUM, 0x00),
    (LOGICAL_MAXIMUM, 0x01),
    (REPORT_SIZE, 0x01),
    (REPORT_COUNT, 0x08),
    (HIDINPUT, 0x02),
    (REPORT_COUNT, 0x01),
    (REPORT_SIZE, 0x08),
    (HIDINPUT, 0x01),
    (REPORT_COUNT, 0x05),
    (REPORT_SIZE, 0x01),
    (USAGE_PAGE, 0x08),
    (USAGE_MINIMUM, 0x01),
    (USAGE_MAXIMUM, 0x05),
    (HIDOUTPUT, 0x02),
    (REPORT_COUNT, 0x01),
    (REPORT_SIZE, 0x03),
    (HIDOUTPUT, 0x01),
    (REPORT_COUNT, 0x06),
    (REPORT_SIZE, 0x08),
    (LOGICAL_MINIMUM, 0x00),
    (LOGICAL_MAXIMUM, 0x65),
    (USAGE_PAGE, 0x07),
    (USAGE_MINIMUM, 0x00),
    (USAGE_MAXIMUM, 0x65),
    (HIDINPUT, 0x00),
    (END_COLLECTION),
);

const SHIFT: u8 = 0x80;
const ALTGR: u8 = 0x40;

// Table AZERTY (FR) : index = code ASCII, valeur = scancode HID (+ SHIFT ou +ALTGR si besoin)
const ASCII_MAP: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0-7
    0x2a, 0x2b, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, // 8 BS, 9 TAB, 10 LF
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16-23
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24-31
    0x2c, 0x38, 0x20, 0x20 | ALTGR, 0x30, 0x34 | SHIFT, 0x1e, 0x21, // 32 SP ! " # $ % & '
    0x22, 0x2d, 0x31 | SHIFT, 0x2e | SHIFT, 0x10, 0x23, 0x36 | SHIFT, 0x37 | SHIFT, // 40 ( ) * + , - . /
    0x27 | SHIFT, 0x1e | SHIFT, 0x1f | SHIFT, 0x20 | SHIFT, 0x21 | SHIFT, 0x22 | SHIFT, 0x23 | SHIFT, 0x24 | SHIFT, // 48 0-7
    0x25 | SHIFT, 0x26 | SHIFT, 0x37 | SHIFT, 0x36, 0x64, 0x2e, 0x64 | SHIFT, 0x37 | SHIFT, // 56 8 9 : ; < = > ?
    0x27, 0x14 | SHIFT, 0x05 | SHIFT, 0x06 | SHIFT, 0x07 | SHIFT, 0x08 | SHIFT, 0x09 | SHIFT, 0x0a | SHIFT, // 64 @ A B C D E F G
    0x0b | SHIFT, 0x0c | SHIFT, 0x0d | SHIFT, 0x0e | SHIFT, 0x0f | SHIFT, 0x33 | SHIFT, 0x11 | SHIFT, 0x12 | SHIFT, // 72 H I J K L M N O
    0x13 | SHIFT, 0x04 | SHIFT, 0x15 | SHIFT, 0x16 | SHIFT, 0x17 | SHIFT, 0x18 | SHIFT, 0x19 | SHIFT, 0x1d | SHIFT, // 80 P Q R S T U V W
    0x1b | SHIFT, 0x1c | SHIFT, 0x1a | SHIFT, 0x22 | ALTGR, 0x25 | ALTGR, 0x2d | ALTGR, 0x00, 0x25 | SHIFT, // 88 X Y Z [ \ ] ^ _
    0x00, 0x14, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, // 96 ` a b c d e f g
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x33, 0x11, 0x12, // 104 h i j k l m n o
    0x13, 0x04, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1d, // 112 p q r s t u v w
    0x1b, 0x1c, 0x1a, 0x21 | ALTGR, 0x23 | ALTGR, 0x2e | ALTGR, 0x1f | ALTGR, 0x00, // 120 x y z { | } ~
];

struct KeyReport {
    modifiers: u8,
    reserved: u8,
    keys: [u8; 6],
}

impl KeyReport {
    fn as_bytes(&self) -> [u8; 8] {
        [
            self.modifiers,
            self.reserved,
            self.keys[0],
            self.keys[1],
            self.keys[2],
            self.keys[3],
            self.keys[4],
            self.keys[5],
        ]
    }
}

pub struct Keyboard {
    server: &'static mut BLEServer,
    input_keyboard: Arc<Mutex<BLECharacteristic>>,
    // Conservés pour garder les caractéristiques HID vivantes côté GATT même si
    // on ne lit/écrit que `input_keyboard` (sinon `dead_code` sous -D warnings).
    #[allow(dead_code)]
    output_keyboard: Arc<Mutex<BLECharacteristic>>,
    #[allow(dead_code)]
    input_media_keys: Arc<Mutex<BLECharacteristic>>,
    key_report: KeyReport,
}

impl Keyboard {
    fn new() -> anyhow::Result<Self> {
        let device = BLEDevice::take();
        device
            .security()
            .set_auth(AuthReq::all())
            .set_io_cap(SecurityIOCap::NoInputNoOutput)
            .resolve_rpa();

        let server = device.get_server();
        let mut hid = BLEHIDDevice::new(server);

        let input_keyboard = hid.input_report(KEYBOARD_ID);
        let output_keyboard = hid.output_report(KEYBOARD_ID);
        let input_media_keys = hid.input_report(MEDIA_KEYS_ID);

        hid.manufacturer("Axolotl");
        hid.pnp(0x02, 0x05ac, 0x820a, 0x0210);
        hid.hid_info(0x00, 0x01);
        hid.report_map(HID_REPORT_DESCRIPTOR);
        hid.set_battery_level(100);

        let ble_advertising = device.get_advertising();
        ble_advertising.lock().scan_response(false).set_data(
            BLEAdvertisementData::new()
                .name("Axolotl Keyboard")
                .appearance(0x03C1)
                .add_service_uuid(hid.hid_service().lock().uuid()),
        )?;
        ble_advertising.lock().start()?;

        Ok(Self {
            server,
            input_keyboard,
            output_keyboard,
            input_media_keys,
            key_report: KeyReport { modifiers: 0, reserved: 0, keys: [0; 6] },
        })
    }

    fn connected(&self) -> bool {
        self.server.connected_count() > 0
    }

    fn write(&mut self, text: &str) {
        for ch in text.as_bytes() {
            // Garde : ASCII_MAP fait 128 entrées. Un octet ≥128 (accent dans un
            // payload) provoquerait un index out-of-bounds → on l'ignore.
            let c = *ch as usize;
            if c < ASCII_MAP.len() && ASCII_MAP[c] != 0 {
                self.press(*ch);
                self.release();
            }
        }
    }

    fn press(&mut self, ch: u8) {
        let mut key = ASCII_MAP[ch as usize];
        self.key_report.modifiers = 0;
        if (key & SHIFT) > 0 {
            self.key_report.modifiers |= 0x02;
            key &= !SHIFT;
        }
        if (key & ALTGR) > 0 {
            self.key_report.modifiers |= 0x40;
            key &= !ALTGR;
        }
        self.key_report.keys[0] = key;
        self.send_report(&self.key_report);
    }

    // Presse une touche (scancode brut) avec un modifier (ex: GUI=0x08 pour Win)
    fn press_combo(&mut self, modifier: u8, key: u8) {
        self.key_report.modifiers = modifier;
        self.key_report.keys[0] = key;
        self.send_report(&self.key_report);
        self.release();
    }

    fn release(&mut self) {
        self.key_report.modifiers = 0;
        self.key_report.keys.fill(0);
        self.send_report(&self.key_report);
    }

    fn send_report(&self, keys: &KeyReport) {
        let bytes = keys.as_bytes();
        self.input_keyboard.lock().set_value(&bytes).notify();
        esp_idf_svc::hal::delay::Ets::delay_ms(7);
    }

    /// Interprète un script **DuckyScript** (sous-ensemble) et le tape.
    /// Commandes : `REM`, `DELAY ms`, `DEFAULTDELAY ms`, `STRING txt`,
    /// `STRINGLN txt`, touches nommées (`ENTER`, `TAB`, `GUI r`, `CTRL ALT DEL`,
    /// `F1`..`F12`, flèches…). `back` interrompt entre deux commandes.
    fn run_ducky(&mut self, script: &str, back: &PinDriver<'_, Input>) {
        use esp_idf_svc::hal::delay::FreeRtos;
        let mut default_delay = 0u32;
        for raw in script.lines() {
            if back.is_low() {
                info!("BadUSB: payload interrompu (retour)");
                return;
            }
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let (cmd, arg) = match line.split_once(char::is_whitespace) {
                Some((c, a)) => (c, a.trim_start()),
                None => (line, ""),
            };
            match cmd.to_ascii_uppercase().as_str() {
                "REM" => {}
                "DELAY" => {
                    if let Ok(ms) = arg.trim().parse::<u32>() {
                        FreeRtos::delay_ms(ms);
                    }
                }
                "DEFAULTDELAY" | "DEFAULT_DELAY" => {
                    default_delay = arg.trim().parse::<u32>().unwrap_or(0);
                }
                "STRING" => self.write(arg),
                "STRINGLN" => {
                    self.write(arg);
                    self.press_combo(0, 0x28); // ENTER
                }
                // Tout le reste = touche(s) : ENTER, GUI r, CTRL ALT DEL, F5…
                _ => self.exec_combo(line),
            }
            if default_delay > 0 {
                FreeRtos::delay_ms(default_delay);
            }
        }
    }

    /// Exécute une ligne « touches » : accumule les modificateurs (GUI/CTRL/ALT/
    /// SHIFT) et presse la touche finale (touche nommée ou caractère unique).
    fn exec_combo(&mut self, line: &str) {
        let mut mods = 0u8;
        let mut key = 0u8;
        for tok in line.split_whitespace() {
            if let Some(m) = modifier_for(tok) {
                mods |= m;
            } else if let Some(k) = keycode_for(tok) {
                key = k;
            } else if tok.len() == 1 {
                let c = tok.as_bytes()[0] as usize;
                if c < ASCII_MAP.len() {
                    key = ASCII_MAP[c] & !(SHIFT | ALTGR);
                }
            }
        }
        if mods != 0 || key != 0 {
            self.press_combo(mods, key);
        }
    }
}

/// Bit de modificateur HID pour un mot-clé DuckyScript (sinon `None`).
fn modifier_for(tok: &str) -> Option<u8> {
    match tok.to_ascii_uppercase().as_str() {
        "GUI" | "WINDOWS" | "WIN" | "META" | "COMMAND" => Some(0x08),
        "CTRL" | "CONTROL" => Some(0x01),
        "SHIFT" => Some(0x02),
        "ALT" | "OPTION" => Some(0x04),
        _ => None,
    }
}

/// Scancode HID d'une touche nommée DuckyScript (sinon `None`).
fn keycode_for(tok: &str) -> Option<u8> {
    let up = tok.to_ascii_uppercase();
    // F1..F12
    if let Some(n) = up.strip_prefix('F').and_then(|s| s.parse::<u8>().ok()) {
        if (1..=12).contains(&n) {
            return Some(0x3a + (n - 1));
        }
    }
    let code = match up.as_str() {
        "ENTER" | "RETURN" => 0x28,
        "ESC" | "ESCAPE" => 0x29,
        "BACKSPACE" | "BACK" => 0x2a,
        "TAB" => 0x2b,
        "SPACE" => 0x2c,
        "CAPSLOCK" => 0x39,
        "INSERT" => 0x49,
        "HOME" => 0x4a,
        "PAGEUP" => 0x4b,
        "DELETE" | "DEL" => 0x4c,
        "END" => 0x4d,
        "PAGEDOWN" => 0x4e,
        "RIGHT" | "RIGHTARROW" => 0x4f,
        "LEFT" | "LEFTARROW" => 0x50,
        "DOWN" | "DOWNARROW" => 0x51,
        "UP" | "UPARROW" => 0x52,
        _ => return None,
    };
    Some(code)
}

/// Crée le clavier BLE et le renvoie (le menu peut afficher un écran avant de
/// lancer le payload).
pub fn make_keyboard() -> anyhow::Result<Keyboard> {
    Keyboard::new()
}

/// Répertoire des payloads DuckyScript sur la SD.
pub const PAYLOADS_DIR: &str = "/sdcard/payloads";

/// Liste les payloads `.txt` disponibles dans [`PAYLOADS_DIR`], triés.
pub fn list_payloads() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(PAYLOADS_DIR) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter(|e| e.path().extension().map(|x| x.eq_ignore_ascii_case("txt")).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Chemin complet d'un payload.
pub fn payload_path(name: &str) -> String {
    format!("{PAYLOADS_DIR}/{name}")
}

/// Attend l'appairage puis exécute le `script` DuckyScript une fois. `back`
/// (bouton gauche) quitte l'écran et **libère le BLE** (RAM rendue au Wi-Fi).
pub fn run_payload(mut keyboard: Keyboard, script: &str, back: &PinDriver<'_, Input>) {
    use esp_idf_svc::hal::delay::FreeRtos;
    let mut deja_tape = false;
    loop {
        if back.is_low() {
            break;
        }
        if keyboard.connected() {
            if !deja_tape {
                info!("BadUSB: connecté — exécution du payload");
                keyboard.run_ducky(script, back);
                info!("BadUSB: payload terminé");
                deja_tape = true;
            }
        } else {
            deja_tape = false;
        }
        FreeRtos::delay_ms(500);
    }

    // Libère le contrôleur BLE + NimBLE (~100 KB) avant de rendre la main.
    // Indispensable : sans ça, le singleton BLEDevice garde la RAM et le Wi-Fi
    // relancé ensuite échoue en ESP_ERR_NO_MEM (crash observé sur matériel).
    // On drop d'abord le clavier (ses handles GATT) puis on deinit le stack.
    drop(keyboard);
    if let Err(e) = BLEDevice::deinit() {
        log::warn!("BadUSB: deinit BLE KO: {:?}", e);
    } else {
        log::info!("BadUSB: BLE deinit (RAM liberee)");
    }
}
