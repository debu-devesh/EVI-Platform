#!/bin/bash
set -e

mkdir -p /persist/data/uploaded_ufdrs /persist/profile_pictures

[ -f /persist/sessions.db ] || touch /persist/sessions.db
[ -f /persist/evi_scan.db ] || touch /persist/evi_scan.db

# ln -sfn will nest a symlink inside an existing real directory instead of
# replacing it. Remove non-symlink destinations first.
link_persist() {
  local target="$1"
  local dest="$2"
  if [ -e "$dest" ] && [ ! -L "$dest" ]; then
    rm -rf "$dest"
  fi
  ln -sfn "$target" "$dest"
}

link_persist /persist/data /app/FORENSIC/data
link_persist /persist/sessions.db /app/FORENSIC/sessions.db
link_persist /persist/evi_scan.db /app/Authentication/evi_scan.db
link_persist /persist/profile_pictures /app/FORENSIC/static/profile_pictures

if [ -f /persist/.encryption_key ]; then
  link_persist /persist/.encryption_key /app/FORENSIC/.encryption_key
fi

exec python FORENSIC/web_interface.py
