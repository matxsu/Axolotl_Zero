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
# 1. Récupérer zphisher (templates dans .sites/)
git clone https://github.com/htr-tech/zphisher

# 2. Convertir vers le format SD (monte ta SD d'abord)
tools/zphisher_to_sd.sh ~/zphisher/.sites  /run/media/$USER/AXOLOTL/portals

# 3. Vérifier chaque index.html : form action="/login" method="POST",
#    champs name="email" / name="password" (le script fait le gros du travail,
#    mais les templates zphisher varient — ajuste si besoin).
```

Le script réécrit l'`action`/`method` du formulaire et renomme les champs
courants (`username`, `user`, `pass`, `passwd`…) en `email`/`password`, et copie
les assets locaux. Les CSS/JS servis par CDN peuvent ne pas charger hors-ligne :
le formulaire de login, lui, fonctionne.

## Sur le device

Menu **WiFi Tools → Evil twin** : choisir le réseau à cloner (SSID repris tel
quel, AP ouverte), puis le portail à servir. Les identifiants saisis par la
victime sont loggés en série **et** ajoutés à `/sdcard/loot/creds.csv`,
consultables via **WiFi Tools → Creds captures**.
