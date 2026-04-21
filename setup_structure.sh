#!/bin/bash
# ══════════════════════════════════════════════════════════
# Axolotl Zero — Script de restructuration du projet
# À exécuter une seule fois depuis la racine du repo
# Usage : bash setup_structure.sh
# ══════════════════════════════════════════════════════════

set -e

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo ".")"
FW_SRC="$REPO_ROOT/axolotl-fw/src"

echo "══════════════════════════════════════════════"
echo "  Axolotl Zero — Restructuration du projet"
echo "══════════════════════════════════════════════"
echo ""
echo "Repo root : $REPO_ROOT"
echo "Firmware  : $FW_SRC"
echo ""

# ── Vérification ──
if [ ! -f "$FW_SRC/main.rs" ]; then
    echo "ERREUR : main.rs introuvable dans $FW_SRC"
    echo "Assurez-vous d'exécuter ce script depuis la racine du repo."
    exit 1
fi

# ── 1. Créer l'arborescence firmware ──
echo "[1/7] Création de l'arborescence modules..."
mkdir -p "$FW_SRC/drivers"
mkdir -p "$FW_SRC/nfc"
mkdir -p "$FW_SRC/wifi"
mkdir -p "$FW_SRC/bad_usb"
mkdir -p "$FW_SRC/sub_ghz"
mkdir -p "$FW_SRC/ui/screens"

# ── 2. Déplacer les fichiers existants ──
echo "[2/7] Déplacement des fichiers existants..."

if [ -f "$FW_SRC/nfc.rs" ] && [ ! -f "$FW_SRC/drivers/pn532.rs" ]; then
    cp "$FW_SRC/nfc.rs" "$FW_SRC/drivers/pn532.rs"
    echo "  nfc.rs → drivers/pn532.rs (copié, original conservé pour compatibilité)"
fi

if [ -f "$FW_SRC/storage.rs" ] && [ ! -f "$FW_SRC/drivers/sdcard.rs" ]; then
    cp "$FW_SRC/storage.rs" "$FW_SRC/drivers/sdcard.rs"
    echo "  storage.rs → drivers/sdcard.rs (copié, original conservé pour compatibilité)"
fi

# ── 3. Créer les mod.rs ──
echo "[3/7] Création des mod.rs..."

# drivers/mod.rs
cat > "$FW_SRC/drivers/mod.rs" << 'EOF'
pub mod pn532;
pub mod sdcard;
// pub mod buttons;
// pub mod display;
// pub mod cc1101;
EOF

# nfc/mod.rs
cat > "$FW_SRC/nfc/mod.rs" << 'EOF'
// pub mod mifare;
// pub mod attacks;
// pub mod keys;
// pub mod dump;

// TODO: Re-export high-level NFC API here
// pub use mifare::{MifareKey, MifareDump};
EOF

# wifi/mod.rs
cat > "$FW_SRC/wifi/mod.rs" << 'EOF'
// Module Wi-Fi — stub
// TODO: Implement scan, deauth, evil twin

pub fn placeholder() {
    log::info!("Wi-Fi module: not implemented yet");
}
EOF

# bad_usb/mod.rs
cat > "$FW_SRC/bad_usb/mod.rs" << 'EOF'
// Module BadUSB — stub
// TODO: Implement HID keyboard, DuckyScript parser

pub fn placeholder() {
    log::info!("BadUSB module: not implemented yet");
}
EOF

# sub_ghz/mod.rs
cat > "$FW_SRC/sub_ghz/mod.rs" << 'EOF'
// Module Sub-GHz (CC1101) — stub
// TODO: Implement SPI driver, capture, replay

pub fn placeholder() {
    log::info!("Sub-GHz module: not implemented yet");
}
EOF

# ui/mod.rs
cat > "$FW_SRC/ui/mod.rs" << 'EOF'
pub mod screens;
// pub mod menu;
// pub mod theme;
EOF

# ui/screens/mod.rs
cat > "$FW_SRC/ui/screens/mod.rs" << 'EOF'
// pub mod nfc;
// pub mod wifi;
// pub mod bad_usb;
// pub mod sub_ghz;
// pub mod storage;
EOF

# ── 4. Créer les fichiers stubs vides ──
echo "[4/7] Création des fichiers stubs..."
for f in drivers/buttons.rs drivers/display.rs drivers/cc1101.rs \
         nfc/mifare.rs nfc/attacks.rs nfc/keys.rs nfc/dump.rs \
         ui/theme.rs ui/menu.rs \
         ui/screens/nfc.rs ui/screens/wifi.rs ui/screens/bad_usb.rs \
         ui/screens/sub_ghz.rs ui/screens/storage.rs; do
    if [ ! -f "$FW_SRC/$f" ]; then
        echo "// TODO: implement" > "$FW_SRC/$f"
    fi
done

# ── 5. Créer le dossier docs ──
echo "[5/7] Création du dossier docs..."
mkdir -p "$REPO_ROOT/docs/features"
mkdir -p "$REPO_ROOT/docs/hardware"

# Créer des placeholders
for f in docs/features/nfc-rfid.md docs/features/wifi.md \
         docs/features/bad-usb.md docs/features/sub-ghz.md; do
    if [ ! -f "$REPO_ROOT/$f" ]; then
        echo "# $(basename $f .md | tr '-' ' ' | sed 's/.*/\u&/')" > "$REPO_ROOT/$f"
        echo "" >> "$REPO_ROOT/$f"
        echo "> TODO: Detailed feature specification" >> "$REPO_ROOT/$f"
    fi
done

# ── 6. Mettre à jour .vscode ──
echo "[6/7] Mise à jour de la config VSCode..."
mkdir -p "$REPO_ROOT/.vscode"

cat > "$REPO_ROOT/.vscode/settings.json" << 'VSEOF'
{
    "editor.formatOnSave": true,
    "editor.rulers": [100],
    "editor.tabSize": 4,
    "editor.insertSpaces": true,
    "rust-analyzer.cargo.target": "xtensa-esp32s3-espidf",
    "rust-analyzer.check.command": "check",
    "rust-analyzer.check.allTargets": false,
    "rust-analyzer.cargo.buildScripts.enable": true,
    "rust-analyzer.procMacro.enable": true,
    "rust-analyzer.linkedProjects": [
        "axolotl-fw/Cargo.toml"
    ],
    "files.watcherExclude": {
        "**/target/**": true,
        "**/.embuild/**": true
    },
    "files.exclude": {
        "**/target": true,
        "**/.embuild": true
    },
    "todo-tree.general.tags": ["TODO", "FIXME", "HACK", "XXX"],
    "files.associations": {
        "*.toml": "toml",
        "sdkconfig.defaults": "properties"
    }
}
VSEOF

cat > "$REPO_ROOT/.vscode/extensions.json" << 'VSEOF'
{
    "recommendations": [
        "rust-lang.rust-analyzer",
        "tamasfe.even-better-toml",
        "usernameheo.errorlens",
        "eamodio.gitlens",
        "serayuzgur.crates",
        "gruntfuggly.todo-tree",
        "ms-vscode.vscode-serial-monitor"
    ]
}
VSEOF

# ── 7. Résumé ──
echo "[7/7] Terminé !"
echo ""
echo "══════════════════════════════════════════════"
echo "  Structure créée avec succès"
echo "══════════════════════════════════════════════"
echo ""
echo "Arborescence :"
find "$FW_SRC" -type f -name "*.rs" | sort | sed "s|$REPO_ROOT/||"
echo ""
echo "Prochaines étapes :"
echo "  1. Mettre à jour main.rs pour utiliser les nouveaux modules"
echo "  2. cargo check  (vérifier que tout compile)"
echo "  3. git add -A && git commit -m 'refactor: restructure project modules'"
echo "  4. git push origin feature/rfid_attacks"
echo ""
echo "IMPORTANT : nfc.rs et storage.rs originaux sont conservés."
echo "Une fois que main.rs utilise drivers::pn532 et drivers::sdcard,"
echo "vous pourrez supprimer les anciens fichiers."