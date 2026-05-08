use esp_idf_hal::prelude::*;
use esp_idf_sys as _;

mod badusb;

fn main() -> anyhow::Result<()> {
    // Patch des liens ESP-IDF (nécessaire au démarrage)
    esp_idf_sys::link_patches();
    
    // Initialisation des périphériques
    let peripherals = Peripherals::take().unwrap();
    
    // Initialisation du logger
    esp_idf_svc::log::EspLogger::initialize_default();
    
    log::info!("=== Axolotl Zero - BadUSB Module ===");
    log::info!("Firmware démarrage...");
    
    // Exécution du module BadUSB (uniquement en lab autorisé!)
    if let Err(e) = badusb::run_badusb_demo() {
        log::error!("Erreur BadUSB: {:?}", e);
    }
    
    // Boucle infinie pour maintenir le programme actif
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}