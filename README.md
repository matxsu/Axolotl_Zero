# Axolotl Zero

**Axolotl Zero** is a compact, open-source penetration testing device built around the ESP32-S3. It combines a high-resolution color display, tactile buttons, and a suite of wireless and radio frequency tools into a pocket-sized form factor.

## Features

- **Display**: 1.54" 240x240 Color TFT LCD
- **Processor**: ESP32-S3 (Dual-Core Xtensa LX7)    
- **Connectivity**:
  - Wi-Fi 4 (2.4 GHz)
  - Bluetooth 5 (LE)
- **Radio Frequency**:
  - Sub-GHz ISM Band (433 MHz) for RFID/NFC and custom protocols
- **Storage**: SPI Flash (16MB)
- **User Interface**:
  - 5-way Tactile Navigation Pad

## Getting Started

### Prerequisites

- Rust Toolchain (stable or nightly)
- `espflash` for flashing and monitoring
- `cargo-espflash` for easier flashing

### Installation

1. **Install `cargo-espflash`**:
   ```bash
   cargo install cargo-espflash
   ```

2. **Verify connection**:
      ```bash
   ls /dev/ttyACM*   
   ```

3. **Build and Flash**:


   ```bash
   cargo espflash flash --monitor
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.