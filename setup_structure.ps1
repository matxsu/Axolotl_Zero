# ══════════════════════════════════════════════════════════
# Axolotl Zero — Script de restructuration (PowerShell)
# Usage : .\setup_structure.ps1
# Exécuter depuis la racine du repo Axolotl_Zero
# ══════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

$REPO_ROOT = Get-Location
$FW_SRC = Join-Path $REPO_ROOT "axolotl-fw\src"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Axolotl Zero - Restructuration du projet" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repo root : $REPO_ROOT"
Write-Host "Firmware  : $FW_SRC"
Write-Host ""

# Verification
if (-not (Test-Path "$FW_SRC\main.rs")) {
    Write-Host "ERREUR : main.rs introuvable dans $FW_SRC" -ForegroundColor Red
    Write-Host "Assurez-vous d'executer ce script depuis la racine du repo."
    exit 1
}

# ── 1. Creer l'arborescence ──
Write-Host "[1/7] Creation de l'arborescence modules..." -ForegroundColor Yellow
$dirs = @(
    "$FW_SRC\drivers",
    "$FW_SRC\nfc",
    "$FW_SRC\wifi",
    "$FW_SRC\bad_usb",
    "$FW_SRC\sub_ghz",
    "$FW_SRC\ui\screens"
)
foreach ($d in $dirs) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

# ── 2. Copier les fichiers existants ──
Write-Host "[2/7] Copie des fichiers existants..." -ForegroundColor Yellow

if ((Test-Path "$FW_SRC\nfc.rs") -and -not (Test-Path "$FW_SRC\drivers\pn532.rs")) {
    Copy-Item "$FW_SRC\nfc.rs" "$FW_SRC\drivers\pn532.rs"
    Write-Host "  nfc.rs -> drivers/pn532.rs"
}

if ((Test-Path "$FW_SRC\storage.rs") -and -not (Test-Path "$FW_SRC\drivers\sdcard.rs")) {
    Copy-Item "$FW_SRC\storage.rs" "$FW_SRC\drivers\sdcard.rs"
    Write-Host "  storage.rs -> drivers/sdcard.rs"
}

# ── 3. Creer les mod.rs ──
Write-Host "[3/7] Creation des mod.rs..." -ForegroundColor Yellow

@"
pub mod pn532;
pub mod sdcard;
// pub mod buttons;
// pub mod display;
// pub mod cc1101;
"@ | Set-Content "$FW_SRC\drivers\mod.rs" -Encoding UTF8

@"
// pub mod mifare;
// pub mod attacks;
// pub mod keys;
// pub mod dump;

// TODO: Re-export high-level NFC API here
"@ | Set-Content "$FW_SRC\nfc\mod.rs" -Encoding UTF8

@"
// Module Wi-Fi - stub
// TODO: Implement scan, deauth, evil twin

pub fn placeholder() {
    log::info!("Wi-Fi module: not implemented yet");
}
"@ | Set-Content "$FW_SRC\wifi\mod.rs" -Encoding UTF8

@"
// Module BadUSB - stub
// TODO: Implement HID keyboard, DuckyScript parser

pub fn placeholder() {
    log::info!("BadUSB module: not implemented yet");
}
"@ | Set-Content "$FW_SRC\bad_usb\mod.rs" -Encoding UTF8

@"
// Module Sub-GHz (CC1101) - stub
// TODO: Implement SPI driver, capture, replay

pub fn placeholder() {
    log::info!("Sub-GHz module: not implemented yet");
}
"@ | Set-Content "$FW_SRC\sub_ghz\mod.rs" -Encoding UTF8

@"
pub mod screens;
// pub mod menu;
// pub mod theme;
"@ | Set-Content "$FW_SRC\ui\mod.rs" -Encoding UTF8

@"
// pub mod nfc;
// pub mod wifi;
// pub mod bad_usb;
// pub mod sub_ghz;
// pub mod storage;
"@ | Set-Content "$FW_SRC\ui\screens\mod.rs" -Encoding UTF8

# ── 4. Creer les fichiers stubs ──
Write-Host "[4/7] Creation des fichiers stubs..." -ForegroundColor Yellow
$stubs = @(
    "drivers\buttons.rs", "drivers\display.rs", "drivers\cc1101.rs",
    "nfc\mifare.rs", "nfc\attacks.rs", "nfc\keys.rs", "nfc\dump.rs",
    "ui\theme.rs", "ui\menu.rs",
    "ui\screens\nfc.rs", "ui\screens\wifi.rs", "ui\screens\bad_usb.rs",
    "ui\screens\sub_ghz.rs", "ui\screens\storage.rs"
)
foreach ($f in $stubs) {
    $path = Join-Path $FW_SRC $f
    if (-not (Test-Path $path)) {
        "// TODO: implement" | Set-Content $path -Encoding UTF8
    }
}

# ── 5. Creer le dossier docs ──
Write-Host "[5/7] Creation du dossier docs..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path "$REPO_ROOT\docs\features" -Force | Out-Null
New-Item -ItemType Directory -Path "$REPO_ROOT\docs\hardware" -Force | Out-Null

$features = @{
    "docs\features\nfc-rfid.md" = "# NFC / RFID`n`n> TODO: Detailed feature specification"
    "docs\features\wifi.md" = "# Wi-Fi`n`n> TODO: Detailed feature specification"
    "docs\features\bad-usb.md" = "# BadUSB`n`n> TODO: Detailed feature specification"
    "docs\features\sub-ghz.md" = "# Sub-GHz`n`n> TODO: Detailed feature specification"
}
foreach ($kv in $features.GetEnumerator()) {
    $path = Join-Path $REPO_ROOT $kv.Key
    if (-not (Test-Path $path)) {
        $kv.Value | Set-Content $path -Encoding UTF8
    }
}

# ── 6. Mettre a jour .vscode ──
Write-Host "[6/7] Mise a jour de la config VSCode..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path "$REPO_ROOT\.vscode" -Force | Out-Null

@'
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
'@ | Set-Content "$REPO_ROOT\.vscode\settings.json" -Encoding UTF8

@'
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
'@ | Set-Content "$REPO_ROOT\.vscode\extensions.json" -Encoding UTF8

# Supprimer les vieux fichiers C/C++
$oldFiles = @("$REPO_ROOT\.vscode\c_cpp_properties.json", "$REPO_ROOT\.vscode\launch.json")
foreach ($f in $oldFiles) {
    if (Test-Path $f) {
        Remove-Item $f
        Write-Host "  Supprime : $f" -ForegroundColor DarkGray
    }
}

# ── 7. Resume ──
Write-Host ""
Write-Host "[7/7] Termine !" -ForegroundColor Green
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Structure creee avec succes" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Arborescence creee :" -ForegroundColor White
Get-ChildItem -Path $FW_SRC -Recurse -Filter "*.rs" | ForEach-Object {
    $rel = $_.FullName.Replace($REPO_ROOT.Path + "\", "")
    Write-Host "  $rel"
}
Write-Host ""
Write-Host "Prochaines etapes :" -ForegroundColor Yellow
Write-Host "  1. Installer les extensions VSCode :" -ForegroundColor White
Write-Host '     code --install-extension rust-lang.rust-analyzer' -ForegroundColor DarkGray
Write-Host '     code --install-extension tamasfe.even-better-toml' -ForegroundColor DarkGray
Write-Host '     code --install-extension usernameheo.errorlens' -ForegroundColor DarkGray
Write-Host '     code --install-extension eamodio.gitlens' -ForegroundColor DarkGray
Write-Host '     code --install-extension serayuzgur.crates' -ForegroundColor DarkGray
Write-Host ""
Write-Host "  2. Verifier la compilation :" -ForegroundColor White
Write-Host '     cd axolotl-fw' -ForegroundColor DarkGray
Write-Host '     cargo check' -ForegroundColor DarkGray
Write-Host ""
Write-Host "  3. Commiter :" -ForegroundColor White
Write-Host '     git add -A' -ForegroundColor DarkGray
Write-Host '     git commit -m "refactor: restructure project into modules"' -ForegroundColor DarkGray
Write-Host '     git push origin feature/rfid_attacks' -ForegroundColor DarkGray
Write-Host ""
Write-Host "NOTE : nfc.rs et storage.rs originaux sont conserves." -ForegroundColor DarkYellow
Write-Host "Supprimez-les apres avoir mis a jour main.rs." -ForegroundColor DarkYellow