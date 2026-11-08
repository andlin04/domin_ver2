#!/bin/bash
# Mullvad split tunnel for domin's routed scans (Settings > Routes: a Mullvad route), as root:
#
#   bash deploy/mullvad-tunnel.sh up       bring the tunnel up (or re-apply it) with the saved credentials
#   bash deploy/mullvad-tunnel.sh down     stop it, and drop the service drop-ins this script wrote
#   bash deploy/mullvad-tunnel.sh status   interface, relay and whether Mullvad's in-tunnel SOCKS5 answers
#   bash deploy/mullvad-tunnel.sh apply    what domin-mullvad.service runs when the page saves: up, or down when no
#                                          credentials are saved
#   bash deploy/mullvad-tunnel.sh allow    only the service drop-ins (Tor without Mullvad needs 127.0.0.1)
#
# WireGuard interface "mullvad" (wg-quick@mullvad) with AllowedIPs = 10.64.0.0/10 only: just Mullvad-internal traffic
# (the relays' SOCKS5 proxies) goes through it. No DNS change, no default route; everything else stays as it is.
#
# Credentials, first found:
#   1. the domin database (Settings > Routes): a WireGuard private key with its tunnel address (used as they
#      are: no key generation, no API call), or an account number; optional entry country
#   2. /etc/domin/mullvad-account (account number only; owner root, mode 0600 or 0400)
# With an account number only, a key is generated once (/etc/wireguard/mullvad.key) and registered with Mullvad.
#
# Mullvad API, checked 2026-11-08 against mullvad/mullvad-wg.sh (main branch):
#   key registration: POST https://api.mullvad.net/wg  account=<number>&pubkey=<public key>  -> the tunnel address(es)
#   relay list:       https://api.mullvad.net/www/relays/all/  (type wireguard, active, ipv4_addr_in, pubkey)
# The account number goes to curl on stdin, never on a command line; neither it nor the private key is printed.
#
# Writes /etc/systemd/system/{domin-worker,domin}.service.d/20-routes.conf (IPAddressAllow=10.64.0.0/10, and
# 127.0.0.1/32 for a local tor client): the services refuse every non-public address otherwise. A status line for the
# Routes page goes to $DATA/mullvad.status (no secrets).
set -Eeuo pipefail
umask 077

CMD=${1:-status}
DATA=/var/lib/domin
APP=/opt/domin
DB=$(sed -n 's/^DOMIN_DB=//p' /etc/domin.env 2>/dev/null | tail -1)
DB=${DB:-$DATA/domin.db}
ACCOUNT_FILE=${MULLVAD_ACCOUNT_FILE:-/etc/domin/mullvad-account}
WG=/etc/wireguard
CONF=$WG/mullvad.conf
KEY_FILE=$WG/mullvad.key            # generated key (account number mode)
REG_FILE=$WG/mullvad.registered     # "<account sha256> <public key> <address>" of the last registration
STATUS=$DATA/mullvad.status
REQUEST=$DATA/mullvad.request
IN_TUNNEL=10.64.0.1
STEP=start

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

status_file() {  # ok(true|false) message: the page's "last apply" line
  [ -d "$DATA" ] || return 0
  python3 -c 'import json, sys, datetime
print(json.dumps({"at": datetime.datetime.now().isoformat(timespec="seconds"), "ok": sys.argv[1] == "true",
                  "message": sys.argv[2][:300]}))' "$1" "$2" > "$STATUS.tmp"
  chmod 644 "$STATUS.tmp"
  chown domin:domin "$STATUS.tmp" 2>/dev/null || true
  mv -f "$STATUS.tmp" "$STATUS"
}
fail() { echo "mullvad: $1" >&2; status_file false "$1"; exit 1; }
trap 'status_file false "failed at: $STEP"' ERR

load_credentials() {  # sets ACCOUNT, PRIV, ADDRESS, ENTRY; prints nothing
  ACCOUNT= PRIV= ADDRESS= ENTRY=
  if [ -f "$DB" ] && [ -x "$APP/venv/bin/python" ]; then
    # as the service user: a WAL database's -shm/-wal files must stay owned by domin; SELECT only
    mapfile -t CREDS < <(runuser -u domin -- "$APP/venv/bin/python" - "$DB" <<'EOF'
import json, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
row = c.execute("SELECT value FROM kv WHERE key = 'mullvad_tunnel'").fetchone()
cfg = json.loads(row[0]) if row else {}
for k in ("account", "private_key", "address", "entry"):
    print(str(cfg.get(k) or "").strip())
EOF
)
    ACCOUNT=${CREDS[0]:-} PRIV=${CREDS[1]:-} ADDRESS=${CREDS[2]:-} ENTRY=${CREDS[3]:-}
  fi
  if [ -z "$ACCOUNT" ] && [ -z "$PRIV" ] && [ -f "$ACCOUNT_FILE" ]; then
    read -r owner mode < <(stat -c '%U %a' "$ACCOUNT_FILE")
    [ "$owner" = root ] && { [ "$mode" = 600 ] || [ "$mode" = 400 ]; } ||
      fail "$ACCOUNT_FILE must be owned by root with mode 0600 or 0400 (is $owner $mode)"
    ACCOUNT=$(tr -d ' \n' < "$ACCOUNT_FILE")
  fi
  ENTRY=${MULLVAD_COUNTRY:-$ENTRY}
  [ -z "$ACCOUNT" ] || [[ "$ACCOUNT" =~ ^[0-9]{16}$ ]] || fail "the account number is not 16 digits"
  [ -z "$PRIV" ] || [[ "$PRIV" =~ ^[A-Za-z0-9+/]{43}=$ ]] || fail "the private key is not a WireGuard key"
  [ -z "$ENTRY" ] || [[ "$ENTRY" =~ ^[a-z]{2}$ ]] || fail "the entry country is not a two-letter code"
  return 0
}

register() {  # account number mode: a key of our own, registered once per account; sets PRIV and ADDRESS
  STEP="key"
  [ -s "$KEY_FILE" ] || { wg genkey > "$KEY_FILE.new" && chmod 600 "$KEY_FILE.new" && mv "$KEY_FILE.new" "$KEY_FILE"; }
  PRIV=$(cat "$KEY_FILE")
  local pub sum reg
  pub=$(wg pubkey < "$KEY_FILE")
  sum=$(printf %s "$ACCOUNT" | sha256sum | cut -d' ' -f1)
  if [ -s "$REG_FILE" ]; then
    read -r rsum rpub raddr < "$REG_FILE"
    if [ "$rsum" = "$sum" ] && [ "$rpub" = "$pub" ]; then ADDRESS=$raddr; return 0; fi
  fi
  STEP="key registration with Mullvad"
  reg=$(printf 'account=%s' "$ACCOUNT" | curl -sSL --max-time 30 https://api.mullvad.net/wg -d @- \
          --data-urlencode "pubkey=$pub") || fail "key registration: the Mullvad API did not answer"
  [[ "$reg" =~ ^[0-9a-f:/.,]+$ ]] || fail "key registration refused: ${reg:0:120}"
  ADDRESS=$reg
  echo "$sum $pub $ADDRESS" > "$REG_FILE"
  chmod 600 "$REG_FILE"
}

pick_relay() {  # sets R_HOST, R_IP, R_PUB: a random active WireGuard relay (in ENTRY when set)
  STEP="relay list"
  local line
  line=$(curl -fsSL --max-time 30 https://api.mullvad.net/www/relays/all/ | python3 -c 'import json, random, sys
cc = sys.argv[1]
rs = [r for r in json.load(sys.stdin) if r.get("type") == "wireguard" and r.get("active") and r.get("ipv4_addr_in")
      and r.get("pubkey") and (not cc or r.get("country_code") == cc)]
r = random.choice(rs) if rs else None
print(" ".join((r["hostname"], r["ipv4_addr_in"], r["pubkey"])) if r else "")' "$ENTRY") ||
    fail "cannot fetch the Mullvad relay list"
  read -r R_HOST R_IP R_PUB <<< "$line"
  [ -n "${R_HOST:-}" ] || fail "no active WireGuard relay${ENTRY:+ in $ENTRY}"
  [[ "$R_HOST" =~ ^[a-z0-9-]+$ && "$R_IP" =~ ^[0-9.]+$ && "$R_PUB" =~ ^[A-Za-z0-9+/]{43}=$ ]] ||
    fail "unexpected relay list entry"
}

dropins() {  # write | remove: the services' IPAddressAllow for the tunnel and a local tor client
  local changed=0 unit dir file want
  for unit in domin-worker domin; do
    dir=/etc/systemd/system/$unit.service.d file=/etc/systemd/system/$unit.service.d/20-routes.conf
    if [ "$1" = write ]; then
      want="# domin mullvad-tunnel.sh: the Mullvad relays' SOCKS5 (10.64.0.0/10) and a local tor client"
      want+=$'\n[Service]\nIPAddressAllow=10.64.0.0/10 127.0.0.1/32'
      if [ "$(cat "$file" 2>/dev/null)" != "$want" ]; then
        install -d -m 755 "$dir"
        printf '%s\n' "$want" > "$file"
        chmod 644 "$file"
        changed=1
      fi
    elif [ -f "$file" ]; then
      rm -f "$file"
      changed=1
    fi
  done
  if [ "$changed" = 1 ]; then
    systemctl daemon-reload
    # a restart fails the scans running now ("worker restarted"); only when the drop-in changed
    for unit in domin-worker domin; do
      ! systemctl is-active -q "$unit" || systemctl restart "$unit"
    done
    echo "service drop-ins: $1 done; domin and domin-worker restarted"
  fi
}

socks_up() {  # Mullvad's in-tunnel SOCKS5 accepts a TCP connect
  python3 -c 'import socket, sys
socket.create_connection((sys.argv[1], 1080), timeout=5).close()' "$IN_TUNNEL" 2>/dev/null
}

up() {
  STEP="packages"
  for b in wg wg-quick curl python3; do command -v "$b" >/dev/null || fail "$b is missing (apt install wireguard-tools curl python3)"; done
  load_credentials
  if [ -n "$PRIV" ]; then
    [ -n "$ADDRESS" ] || fail "a private key needs its tunnel address (Settings > Routes)"
  elif [ -n "$ACCOUNT" ]; then
    register
  else
    fail "no Mullvad credentials (Settings > Routes, or $ACCOUNT_FILE)"
  fi
  ADDRESS=${ADDRESS%%,*}   # IPv4 only: the split tunnel carries 10.64.0.0/10
  [[ "$ADDRESS" =~ ^[0-9.]+/[0-9]+$ ]] || fail "unexpected tunnel address"
  pick_relay
  STEP="WireGuard config"
  install -d -m 700 "$WG"
  {
    echo "# domin mullvad-tunnel.sh: split tunnel, only Mullvad-internal addresses (relay SOCKS5 proxies)"
    echo "[Interface]"
    echo "PrivateKey = $PRIV"
    echo "Address = $ADDRESS"
    echo
    echo "[Peer]"
    echo "# $R_HOST"
    echo "PublicKey = $R_PUB"
    echo "Endpoint = $R_IP:51820"
    echo "AllowedIPs = 10.64.0.0/10"
    echo "PersistentKeepalive = 25"
  } > "$CONF.new"
  chmod 600 "$CONF.new"
  mv -f "$CONF.new" "$CONF"
  STEP="wg-quick@mullvad"
  systemctl enable -q wg-quick@mullvad
  systemctl restart wg-quick@mullvad
  STEP="service drop-ins"
  dropins write
  STEP="in-tunnel SOCKS5 check"
  for _ in 1 2 3 4 5; do socks_up && break; sleep 2; done
  socks_up || fail "tunnel to $R_HOST is up but $IN_TUNNEL:1080 does not answer"
  status_file true "tunnel up via $R_HOST ($ADDRESS); in-tunnel SOCKS5 answers"
  echo "mullvad: tunnel up via $R_HOST; $IN_TUNNEL:1080 answers"
}

down() {
  STEP="down"
  systemctl disable -q --now wg-quick@mullvad 2>/dev/null || true
  dropins remove
  status_file true "tunnel down"
  echo "mullvad: tunnel down (key and config kept in $WG)"
}

case "$CMD" in
  up) up ;;
  down) down ;;
  apply)
    rm -f "$REQUEST"   # first: the path unit must not start this again for the same request
    load_credentials
    if [ -n "$ACCOUNT$PRIV" ]; then up; else down; fi ;;
  allow) dropins write ;;
  status)
    if systemctl is-active -q wg-quick@mullvad; then
      echo "interface: up, relay $(sed -n 's/^# \([a-z0-9-]*\)$/\1/p' "$CONF" | tail -1)"
      echo "last handshake (epoch seconds): $(wg show mullvad latest-handshakes | awk '{print $2}')"
    else
      echo "interface: down"
    fi
    if socks_up; then echo "in-tunnel SOCKS5 $IN_TUNNEL:1080: answers"; else echo "in-tunnel SOCKS5 $IN_TUNNEL:1080: no answer"; fi ;;
  *) echo "usage: $0 up|down|status|apply|allow"; exit 2 ;;
esac
