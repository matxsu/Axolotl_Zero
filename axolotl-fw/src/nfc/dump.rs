/// Dump complet d'une carte MIFARE Classic 1K (64 blocs × 16 bytes)
pub struct MifareDump {
    pub blocks: [[u8; 16]; 64],
    pub readable: [bool; 64],
}

impl MifareDump {
    pub fn new() -> Self {
        Self {
            blocks: [[0u8; 16]; 64],
            readable: [false; 64],
        }
    }

    pub fn print_log(&self) {
        let readable_count = self.readable.iter().filter(|&&r| r).count();
        log::info!("=== MIFARE Dump : {}/64 blocs lisibles ===", readable_count);
        for block in 0..64usize {
            if self.readable[block] {
                let d = &self.blocks[block];
                log::info!(
                    "Bloc {:02}: {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X} \
                     {:02X}{:02X}{:02X}{:02X} {:02X}{:02X}{:02X}{:02X}",
                    block,
                    d[0], d[1], d[2], d[3],
                    d[4], d[5], d[6], d[7],
                    d[8], d[9], d[10], d[11],
                    d[12], d[13], d[14], d[15]
                );
            } else {
                log::info!("Bloc {:02}: -- non lisible --", block);
            }
        }
    }
}
