#!/bin/bash
# Turn the local tor service on or off for domin's Tor route. Runs as root:
#   tor-switch.sh apply     read /var/lib/domin/tor.request (domin-tor.path), then set that state
#   tor-switch.sh on|off    set it directly
#   tor-switch.sh keep      install.sh: re-apply the saved state (default off: installed, not started)
# The state is kept in /var/lib/domin/tor.state ("on" or "off"), readable by the app.
# /var/lib/domin belongs to the app user: read only regular files (no symlinks), one word, and write the state
# through a fresh mktemp file + rename, never through a fixed name the app could plant.
set -euo pipefail
DIR=/var/lib/domin
REQ=$DIR/tor.request STATE=$DIR/tor.state
word() { [ -f "$1" ] && [ ! -L "$1" ] && head -c 8 "$1" | tr -cd 'a-z' || true; }
want=${1:?apply|on|off|keep}
case $want in
  apply) want=$(word "$REQ"); rm -f "$REQ" ;;
  keep) want=$(word "$STATE"); [ -n "$want" ] || want=off ;;
esac
case $want in
  on) systemctl enable -q --now tor ;;
  off) systemctl disable -q --now tor 2>/dev/null || true ;;
  *) echo "tor-switch: on or off, not '$want'" >&2; exit 2 ;;
esac
tmp=$(mktemp "$DIR/.tor.state.XXXXXX")
printf '%s\n' "$want" > "$tmp"
chmod 644 "$tmp"
mv -f "$tmp" "$STATE"
echo "tor: $want ($(systemctl is-active tor || true))"
