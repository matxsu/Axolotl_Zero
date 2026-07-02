# Outils Axolotl Zero — portails captifs SD

Cadre : projet pédagogique ESGI, démos en labo sur du matériel appartenant à
l'équipe. L'evil-twin sert des pages statiques et capture le POST — l'ESP32 ne
fait **pas** tourner de PHP.

## Format des portails sur la carte SD

```
/sdcard/
├── portals/
│   ├── generic/      index.html   ← exemple fourni (axolotl-fw/portals/generic/)
│   ├── google/       index.html
│   └── facebook/     index.html
└── loot/
    └── creds.csv     ← rempli par le firmware : timestamp,ssid,email,password
```

- Un **dossier par site** sous `/sdcard/portals/`. Le nom du dossier = ce qui
  s'affiche dans le menu « Evil twin → choix du portail ».
- Chaque dossier contient au minimum **`index.html`**.
- Le `<form>` doit **POST vers `/login`** avec des champs nommés **exactement**
  `email` et `password` (c'est ce que lit le handler Rust). Voir l'exemple
  `axolotl-fw/portals/generic/index.html`.

## Générer des portails depuis zphisher

```bash
# 1. Récupérer le fork Evil_Rogue_AP (templates zphisher dans zphisher/.sites/)
git clone https://github.com/matxsu/Evil_Rogue_AP

# 2. Convertir vers le format SD (monte ta SD d'abord)
tools/zphisher_to_sd.sh ~/Evil_Rogue_AP/zphisher/.sites  /run/media/$USER/AXOLOTL/portals

# 3. Vérifier chaque index.html : form action="/login" method="POST",
#    champs name="email" / name="password" (le script fait le gros du travail,
#    mais les templates zphisher varient — ajuste si besoin).
```

Le script réécrit l'`action`/`method` du formulaire, renomme les champs courants
(`username`, `user`, `pass`, `passwd`…) en `email`/`password`, et copie **tous**
les assets (images, css, js, sous-dossiers) récursivement.

Côté firmware, l'evil-twin sert `index.html` **et** ces assets (handler `/*`
depuis `/sdcard/portals/<site>/`) → fonds, logos et styles locaux s'affichent.
Seuls les assets servis par CDN externe ne chargent pas hors-ligne. Le handler
`/login` accepte aussi bien `email` que `username`.

## Payloads BadUSB (DuckyScript sur SD)

```
/sdcard/payloads/
├── demo_message.txt      ← exemples fournis (axolotl-fw/payloads/)
├── demo_open_url.txt
└── <tes_payloads>.txt    ← tes payloads de labo
```

Un fichier `.txt` = un payload **DuckyScript**. Menu **BadUSB → choisir un
payload**, puis appairer « Axolotl Keyboard » en Bluetooth ; le device tape le
script. Sous-ensemble supporté :

| Commande | Effet |
|---|---|
| `REM ...` | commentaire |
| `DELAY ms` | pause |
| `DEFAULTDELAY ms` | pause entre chaque commande |
| `STRING txt` | tape `txt` |
| `STRINGLN txt` | tape `txt` + Entrée |
| `ENTER TAB SPACE ESC BACKSPACE DELETE HOME END PAGEUP PAGEDOWN` | touches |
| `UP DOWN LEFT RIGHT` `F1`..`F12` `CAPSLOCK` | touches |
| `GUI/WIN/CTRL/ALT/SHIFT [touche]` | combos (ex. `GUI r`, `CTRL ALT DELETE`) |

Layout clavier **AZERTY (FR)**. Cadre labo/pédagogique : le device n'est qu'un
vecteur de frappe HID — le contenu des payloads relève de ta responsabilité et
doit rester dans le périmètre autorisé (matériel de l'équipe, démos ESGI).

## Sur le device

Menu **WiFi Tools → Evil twin** : choisir le réseau à cloner (SSID repris tel
quel, AP ouverte), puis le portail à servir. Les identifiants saisis par la
victime sont loggés en série **et** ajoutés à `/sdcard/loot/creds.csv`,
consultables via **WiFi Tools → Creds captures**.
