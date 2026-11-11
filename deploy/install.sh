#!/bin/bash
# Install or update domin on a fresh VPS (Debian 12/13 or Ubuntu 24.04), as root, from a clone of this repo:
#
#   git clone https://github.com/andlin04/domin_ver2.git && cd domin_ver2
#   sudo bash deploy/install.sh --domain domin.example.com --email you@example.com [--history domin.db]
#
#   --domain D          public host name (DNS A/AAAA record must already point here)
#   --email E           for Let's Encrypt; without it the site is served on plain HTTP only
#   --history FILE      SQLite database with existing scan history (copy it here with scp first); loaded only when
#                       the server has no database yet, unless --replace-history (the old one is kept as .bak)
#   --no-worker         install the scan worker but don't start it (pages and tools only, no scans)
#   --firewall          enable ufw with SSH (22), HTTP and HTTPS only (on-prem: HTTP/HTTPS from --admin-sources)
#   --ssh-from CIDRS    with --firewall: SSH only from these networks (comma-separated; default any)
#   --admin-ip CIDRS    client addresses that get the admin page /admin (comma-separated); without it, and without
#                       DOMIN_ADMIN_IPS in /etc/domin.env, there is no admin page
#   --deny CIDRS        extra addresses the app and the scans may never connect to (e.g. your home or office), on top
#                       of the non-public ranges and this server's own addresses; kept for later runs
#   --alias A           extra host name for the same site (e.g. www.example.com)
#   --cloudflare        site is proxied by Cloudflare: take the client address from CF-Connecting-IP (Cloudflare's
#                       published ranges only), so rate limits apply per visitor; HTTPS can then stay at Cloudflare
#   --origin-cert DIR   with --cloudflare: HTTPS on 443 with a Cloudflare Origin CA certificate (DIR/origin.crt and
#                       DIR/origin.key) that only accepts Cloudflare's client certificate (Authenticated Origin
#                       Pulls); for SSL mode Full (strict). Port 80 keeps serving; close it in the firewall once
#                       Cloudflare connects on 443.
#
# On-prem (internal network, no public name needed), from an unpacked package or a clone:
#
#   sudo bash deploy/install.sh --internal [--domain scanner.example.lan] --scan-nets 10.0.0.0/8 --admin-user you
#
#   --internal          HTTPS on 443 with this host's own certificate (/etc/domin/tls.crt: self-signed until you
#                       replace it with one your CA signed from /etc/domin/tls.csr), port 80 redirects to it; no
#                       Let's Encrypt or Cloudflare. --domain defaults to `hostname -f`.
#   --admin-sources C   networks that may open the site at all (comma-separated CIDRs; default the private ranges;
#                       "any" = no limit)
#   --scan-nets CIDRS   private networks the scans may reach (the scan sandbox refuses every non-public address
#                       otherwise); this host's own addresses stay refused
#   --internal-zones Z  DNS zones scanned as internal (comma-separated, e.g. corp.example,home.arpa)
#   --internal-dns IPS  DNS servers for those zones
#   --raw / --no-raw    give the scan worker raw sockets for nmap SYN scans (CAP_NET_RAW/CAP_NET_ADMIN) or take them
#                       away; default off, kept on later runs
#   --admin-user NAME   create the first admin account; asks for its password (twice) on the terminal
#
# Components (public and on-prem):
#
#   --components LIST   inventory,posture (default: both, or what an earlier run kept in DOMIN_COMPONENTS)
#                       inventory: DNS inventory pages, the public scan API and scheduled refreshes
#                       posture:   security posture, CVEs, scans and schedules, nmap discovery; brings nmap, Tor,
#                                  wireguard-tools, the Tor/Mullvad helper units and (--raw) the raw-socket drop-in
#                       A run that adds a component installs it in place (the database is kept). A run without
#                       posture takes its system parts away (helper units and scripts, raw sockets; the packages and
#                       all data stay) and prints what it removed. Settings > Components turns installed ones off.
#
# Every option above is kept in /etc/domin.env: later runs need no options (`bash deploy/install.sh`).
# Behind an HTTP proxy: export https_proxy/http_proxy (and no_proxy) first; apt, pip and the downloads use them and
# they are written to /etc/domin.env for the app.
#
# Re-running updates the code and keeps the database, /etc/domin.env and the TLS certificate.
# AUTO_UPDATES=off: no automatic security updates (default: unattended-upgrades, unless apt has its own setup).
# Supported: Debian 13, Ubuntu 24.04 or newer (Python 3.12+).
set -euo pipefail

DOMAIN= ALIAS= EMAIL= HISTORY= REPLACE=0 WORKER=1 FIREWALL=0 CLOUDFLARE=0 ORIGIN= SSH_FROM= ADMIN_IP= DENY=
INTERNAL= SOURCES= SCAN_NETS= ZONES= ZONE_DNS= RAW= ADMIN_USER= COMPONENTS=
CIDRS='^[0-9A-Fa-f:.,/]*$'
while [ $# -gt 0 ]; do
  case "$1" in
    --components) COMPONENTS=$2; shift ;;
    --internal) INTERNAL=1 ;;
    --admin-sources) SOURCES=$2; shift ;;
    --scan-nets) SCAN_NETS=$2; shift ;;
    --internal-zones) ZONES=$2; shift ;;
    --internal-dns) ZONE_DNS=$2; shift ;;
    --raw) RAW=1 ;;
    --no-raw) RAW=0 ;;
    --admin-user) ADMIN_USER=$2; shift ;;
    --ssh-from) SSH_FROM=$2; shift ;;
    --admin-ip) ADMIN_IP=$2; shift ;;
    --deny) DENY=$2; shift ;;
    --domain) DOMAIN=$2; shift ;;
    --alias) ALIAS=$2; shift ;;
    --cloudflare) CLOUDFLARE=1 ;;
    --origin-cert) ORIGIN=$2; shift ;;
    --email) EMAIL=$2; shift ;;
    --history) HISTORY=$2; shift ;;
    --replace-history) REPLACE=1 ;;
    --no-worker) WORKER=0 ;;
    --firewall) FIREWALL=1 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
# Install mode: kept in /etc/domin.env, so a later run without options stays on-prem
envget() { [ -r /etc/domin.env ] && sed -n "s/^$1=//p" /etc/domin.env | tail -n1 || true; }
[ -n "$INTERNAL" ] || [ -n "$DOMAIN" ] || [ "$(envget DOMIN_INSTALL_MODE)" != internal ] || INTERNAL=1
if [ "$INTERNAL" = 1 ]; then
  [ -z "$EMAIL$ORIGIN" ] && [ "$CLOUDFLARE" = 0 ] || { echo "--internal: no --email, --cloudflare or --origin-cert"; exit 2; }
  DOMAIN=${DOMAIN:-$(envget DOMIN_HOSTNAME)}
  DOMAIN=${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}
  SOURCES=${SOURCES:-$(envget DOMIN_ADMIN_SOURCES)}
  SOURCES=${SOURCES:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10}
  [ "$SOURCES" = any ] || [[ "$SOURCES" =~ $CIDRS ]] || { echo "bad --admin-sources"; exit 2; }
else
  [ -z "$SOURCES$SCAN_NETS$ZONES$ZONE_DNS$RAW$ADMIN_USER" ] || \
    { echo "--admin-sources, --scan-nets, --internal-*, --raw, --admin-user need --internal"; exit 2; }
fi
# Components: --components, else the list an earlier run kept, else both; known names only, in a fixed order
COMPONENTS=${COMPONENTS:-$(envget DOMIN_COMPONENTS)}
COMPONENTS=${COMPONENTS:-inventory,posture}
[[ "$COMPONENTS" =~ ^[a-z,]+$ ]] || { echo "bad --components: inventory, posture or inventory,posture"; exit 2; }
for c in ${COMPONENTS//,/ }; do
  case $c in inventory|posture) ;; *) echo "bad --components: unknown '$c' (inventory, posture)"; exit 2 ;; esac
done
has() { [[ ",$COMPONENTS," == *",$1,"* ]]; }
COMPONENTS=$(for c in inventory posture; do if has $c; then printf '%s\n' $c; fi; done | paste -sd, -)
[ -n "$COMPONENTS" ] || { echo "bad --components: inventory, posture or inventory,posture"; exit 2; }
has posture || [ "$RAW" != 1 ] || { echo "--raw needs the posture component"; exit 2; }
[[ "$ZONES" =~ ^[A-Za-z0-9.,-]*$ ]] || { echo "bad --internal-zones"; exit 2; }
[[ "$ADMIN_USER" =~ ^[A-Za-z0-9._-]*$ ]] || { echo "bad --admin-user"; exit 2; }
for v in "$SCAN_NETS" "$ZONE_DNS"; do [[ "$v" =~ $CIDRS ]] || { echo "bad address list: $v"; exit 2; }; done
[ -n "$DOMAIN" ] || { echo "--domain is required"; exit 2; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad --domain"; exit 2; }
[[ "$ALIAS" =~ ^[A-Za-z0-9.-]*$ ]] || { echo "bad --alias"; exit 2; }
for v in "$SSH_FROM" "$ADMIN_IP" "$DENY"; do [[ "$v" =~ $CIDRS ]] || { echo "bad address list: $v"; exit 2; }; done
[ -z "$HISTORY" ] || [ -f "$HISTORY" ] || { echo "no such file: $HISTORY"; exit 2; }
if [ -n "$ORIGIN" ]; then
  [ "$CLOUDFLARE" = 1 ] && [ -z "$EMAIL" ] || { echo "--origin-cert needs --cloudflare and no --email"; exit 2; }
  [ -f "$ORIGIN/origin.crt" ] && [ -f "$ORIGIN/origin.key" ] || { echo "need $ORIGIN/origin.crt and origin.key"; exit 2; }
fi
SRC=$(cd "$(dirname "$0")/.." && pwd)
APP=/opt/domin DATA=/var/lib/domin

# HTTP proxy: from the environment (either case), else the one an earlier run kept in /etc/domin.env
http_proxy=${http_proxy:-${HTTP_PROXY:-$(envget HTTP_PROXY)}}
https_proxy=${https_proxy:-${HTTPS_PROXY:-$(envget HTTPS_PROXY)}}
no_proxy=${no_proxy:-${NO_PROXY:-$(envget NO_PROXY)}}
[ -z "$http_proxy$https_proxy" ] || no_proxy=${no_proxy:-127.0.0.1,localhost}
export http_proxy https_proxy no_proxy
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
# proxychains4: scan routes; wireguard-tools: the Mullvad tunnel (deploy/mullvad-tunnel.sh); tor: the Tor route
# (its default config: SOCKS5 on 127.0.0.1:9050; a host with proxy-only egress needs HTTPSProxy in /etc/tor/torrc)
# Tor is installed but off until an admin turns it on (Settings > Routes; tor-switch.sh keeps the choice). An
# install from before that switch with tor running keeps it on.
TOR_START=keep
[ -e /var/lib/domin/tor.state ] || {
  if [ -d /var/lib/domin ] && systemctl is-active -q tor 2>/dev/null; then TOR_START=on; else TOR_START=off; fi; }
apt-get install -y -q python3 python3-venv nginx rsync sqlite3 curl proxychains4 openssl >/dev/null
[ -z "$EMAIL" ] || apt-get install -y -q certbot python3-certbot-nginx >/dev/null
# posture: nmap (service fingerprints, discovery), wireguard-tools and tor (the routes above); openssl: the on-prem
# TLS certificate
! has posture || apt-get install -y -q nmap wireguard-tools tor >/dev/null
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' || \
  { echo "domin needs Python 3.12 or newer (Debian 13, Ubuntu 24.04); this host has $(python3 -V)"; exit 1; }
# Automatic security updates (unattended-upgrades, no automatic reboot), unless AUTO_UPDATES=off or the host already
# has an apt periodic setup of its own (kept as it is).
if [ "${AUTO_UPDATES:-on}" != off ] && [ ! -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
  apt-get install -y -q unattended-upgrades >/dev/null
  printf '%s\n' '// domin install.sh: daily package lists and security updates (AUTO_UPDATES=off: none)' \
    'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' \
    > /etc/apt/apt.conf.d/20auto-upgrades
  printf '%s\n' '// domin install.sh: no automatic reboot' 'Unattended-Upgrade::Automatic-Reboot "false";' \
    > /etc/apt/apt.conf.d/52domin-unattended
fi

id -u domin >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin domin
[ -d "$DATA" ] || install -d -o domin -g domin -m 700 "$DATA"
[ -d "$APP" ] || install -d -m 755 "$APP"
# Posture left out (--components inventory): its system parts go, with the scripts they ran; the database, the
# saved routes and the packages stay, so a later run with posture brings it back as it was.
POSTURE_FILES="tor-switch.sh mullvad-tunnel.sh domin-tor.path domin-tor.service domin-mullvad.path
  domin-mullvad.service worker-raw.conf"
if ! has posture; then
  GONE=
  for u in domin-tor domin-mullvad; do
    if [ -e "/etc/systemd/system/$u.path" ] || [ -e "/etc/systemd/system/$u.service" ]; then
      systemctl disable -q --now "$u.path" "$u.service" 2>/dev/null || true
      rm -f "/etc/systemd/system/$u.path" "/etc/systemd/system/$u.service"
      GONE="$GONE, $u units"
    fi
  done
  if [ -f "$APP/app/deploy/mullvad-tunnel.sh" ] && { systemctl is-active -q wg-quick@mullvad 2>/dev/null ||
       [ -e /etc/systemd/system/domin-worker.service.d/20-routes.conf ]; }; then
    bash "$APP/app/deploy/mullvad-tunnel.sh" down >/dev/null 2>&1 || true
    GONE="$GONE, Mullvad tunnel (stopped)"
  fi
  if [ -f "$APP/app/deploy/tor-switch.sh" ] && systemctl is-active -q tor 2>/dev/null; then
    bash "$APP/app/deploy/tor-switch.sh" off >/dev/null || true
    GONE="$GONE, tor (stopped)"
  fi
  if [ -e /etc/systemd/system/domin-worker.service.d/30-raw.conf ]; then
    rm -f /etc/systemd/system/domin-worker.service.d/30-raw.conf
    GONE="$GONE, worker raw sockets"
  fi
  if [ -n "$GONE" ]; then
    systemctl daemon-reload
    echo "posture removed: ${GONE#, }; kept: the database (scans, findings, schedules), nmap, tor, wireguard-tools"
  fi
fi
rsync -a --delete --exclude .git/ --exclude tests/ --exclude '*.db' "$SRC/" "$APP/app/"
if ! has posture; then for f in $POSTURE_FILES; do rm -f "$APP/app/deploy/$f"; done; fi
chown -R root:root "$APP/app"
chmod -R go-w "$APP/app"
chmod 755 "$APP/app"

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
# The tested versions (deploy/requirements.txt), not whatever is newest on PyPI at install time.
"$APP/venv/bin/pip" install -q --no-input --require-hashes -r "$APP/app/deploy/requirements.txt"
rm -f "$APP/requirements.txt"   # older installs wrote the unpinned list here

if [ ! -f /etc/domin.env ]; then
  ( umask 027; printf 'DOMIN_DB=%s/domin.db\nDOMIN_REFRESH_DAYS=0\nDOMIN_QUEUE_MAX=50\nDOMIN_LOOKUPS_PER_MINUTE=30\n' \
      "$DATA" > /etc/domin.env )
  chown root:domin /etc/domin.env
fi
# Two-factor encryption key (domin/secretbox.py): created once, never overwritten. Back it up apart from the
# database: a restored database without it needs every user's 2FA reset.
[ -d /etc/domin ] || install -d -m 755 /etc/domin
[ -s /etc/domin/totp.key ] || (umask 077; head -c 32 /dev/urandom | base64 | tr '+/' '-_' > /etc/domin/totp.key)
chown root:domin /etc/domin/totp.key && chmod 640 /etc/domin/totp.key
setenv() {  # KEY VALUE: replace or add one line of /etc/domin.env; other lines stay
  (umask 027; { grep -v "^$1=" /etc/domin.env || true; echo "$1=$2"; } > /etc/domin.env.new)
  chown root:domin /etc/domin.env.new && mv /etc/domin.env.new /etc/domin.env
}
# Admin page at /admin, served and linked only for DOMIN_ADMIN_IPS (comma-separated IPs/CIDRs; edit, then
# systemctl restart domin); everyone else gets 404. `python -m domin admin-password` sets its password.
[ -z "$ADMIN_IP" ] || setenv DOMIN_ADMIN_IPS "$ADMIN_IP"
setenv DOMIN_COMPONENTS "$COMPONENTS"   # what is installed; the app and update.sh read it
# --deny is kept in the env file (the app ignores it) so a later run without it keeps the list.
if [ -n "$DENY" ]; then setenv DOMIN_DENY_IPS "$DENY"
else DENY=$(sed -n 's/^DOMIN_DENY_IPS=//p' /etc/domin.env); fi
[[ "$DENY" =~ $CIDRS ]] || { echo "bad DOMIN_DENY_IPS in /etc/domin.env"; exit 2; }
# the proxy for the app's own lookups (crt.sh, RDAP, CVE feeds); empty values stay out of the file
for k in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
  lk=${k,,}
  [ -z "${!lk:-}" ] || setenv "$k" "${!lk}"
done
if [ "$INTERNAL" = 1 ]; then
  setenv DOMIN_INSTALL_MODE internal
  setenv DOMIN_HOSTNAME "$DOMAIN"
  setenv DOMIN_ADMIN_SOURCES "$SOURCES"
  [ -z "$SCAN_NETS" ] || setenv DOMIN_SCAN_NETS "$SCAN_NETS"
  [ -z "$ZONES" ] || setenv DOMIN_INTERNAL_ZONES "$ZONES"
  [ -z "$ZONE_DNS" ] || setenv DOMIN_INTERNAL_DNS "$ZONE_DNS"
  [ -z "$RAW" ] || setenv DOMIN_RAW_SCANS "$RAW"
  SCAN_NETS=$(envget DOMIN_SCAN_NETS) ZONE_DNS=$(envget DOMIN_INTERNAL_DNS) RAW=$(envget DOMIN_RAW_SCANS)
  for v in "$SCAN_NETS" "$ZONE_DNS"; do [[ "$v" =~ $CIDRS ]] || { echo "bad address list in /etc/domin.env"; exit 2; }; done
fi

if [ -n "$HISTORY" ]; then
  if [ -f "$DATA/domin.db" ] && [ "$REPLACE" = 0 ]; then
    echo "history: $DATA/domin.db exists, kept (use --replace-history to load $HISTORY)"
  else
    systemctl stop domin domin-worker 2>/dev/null || true
    [ -f "$DATA/domin.db" ] && mv "$DATA/domin.db" "$DATA/domin.db.bak"
    rm -f "$DATA/domin.db-wal" "$DATA/domin.db-shm"
    install -o domin -g domin -m 640 "$HISTORY" "$DATA/domin.db"
    echo "history: $(sqlite3 "$DATA/domin.db" 'SELECT COUNT(*) FROM scans') scans loaded"
  fi
fi

# Visitor countries for the admin page: DB-IP "IP to Country Lite" (CC BY 4.0, monthly; re-run to refresh).
# Only the country code of a visit is stored; skipped when the download fails.
GEO=$(mktemp --suffix=.csv.gz)
if curl -fsS -o "$GEO" "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).csv.gz"; then
  chmod 644 "$GEO"
  ( set -a; . /etc/domin.env; cd "$APP/app"; runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 "$APP/venv/bin/python" -m domin geoip "$GEO" )
else
  echo "geoip: download failed, admin statistics show no countries"
fi
rm -f "$GEO"

# amass for subdomain discovery (the old version's main source): v3.23.3 prints one host name per line.
# Pinned with the release's checksum; extracted with Python (no unzip needed).
AMASS_SHA=2b5afb8a567d9703dfb416099fb0452e2b4b4da5170f0b23cd3b812df2e9319c
if [ "$(/usr/local/bin/amass -version 2>&1)" != "v3.23.3" ]; then
  ZIP=$(mktemp --suffix=.zip)
  if curl -fsSL -o "$ZIP" https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_Linux_amd64.zip &&
     echo "$AMASS_SHA  $ZIP" | sha256sum -c --quiet; then
    python3 -c 'import sys, zipfile; open(sys.argv[2], "wb").write(zipfile.ZipFile(sys.argv[1]).read("amass_Linux_amd64/amass"))' \
      "$ZIP" /usr/local/bin/amass.new
    install -m 755 /usr/local/bin/amass.new /usr/local/bin/amass && rm -f /usr/local/bin/amass.new
  else
    echo "amass: download or checksum failed, scans use crt.sh and DNS only"
  fi
  rm -f "$ZIP"
fi

# A scanned domain's DNS decides where the scan tools connect: the kernel refuses every non-public address for the
# service and all its child processes, whatever they resolve.
NON_PUBLIC="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4 ::1/128 fc00::/7 fe80::/10 ff00::/8"
# Also this server's own public addresses (a scan must not reach its own SSH or admin page) and --deny.
OWN=$(ip -o addr show scope global | awk '{sub("/.*", "", $4); print $4}' | tr '\n' ' ')
DENY_MORE=$(echo $OWN ${DENY//,/ })   # an empty IPAddressDeny= line would clear the list above: only set if not empty
# Exceptions (drop-ins, rewritten each run): the HTTP proxy for both services; on-prem the worker also gets
# --scan-nets and the internal DNS servers. IPAddressAllow wins over IPAddressDeny whatever the prefix lengths, so
# this host's own addresses are cut out of the scan networks rather than relying on the deny list.
PROXY_IPS=$(for u in "$http_proxy" "$https_proxy"; do
  [ -z "$u" ] || getent ahosts "$(python3 -c 'import sys, urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname or "")' "$u")" || true
done | awk '{print $1}' | sort -u | tr '\n' ' ')
SCAN_ALLOW=
if [ "$INTERNAL" = 1 ] && [ -n "$SCAN_NETS$ZONE_DNS" ]; then
  SCAN_ALLOW=$(python3 - "$OWN" ${SCAN_NETS//,/ } ${ZONE_DNS//,/ } <<'PY'
import ipaddress
import sys

own = [ipaddress.ip_network(a) for a in sys.argv[1].split()]
out: set[str] = set()
for net in sys.argv[2:]:
    parts = [ipaddress.ip_network(net, strict=False)]
    for host in own:
        parts = [q for p in parts
                 for q in (p.address_exclude(host) if p.version == host.version and host.subnet_of(p) else [p])]
    out.update(str(p) for p in parts)
print(" ".join(sorted(out)))
PY
)
fi
dropin() {  # unit, file, content ("" removes the file)
  if [ -n "$3" ]; then mkdir -p "/etc/systemd/system/$1.service.d"; printf '%s\n' "$3" > "/etc/systemd/system/$1.service.d/$2"
  else rm -f "/etc/systemd/system/$1.service.d/$2"; fi
}
allow() { [ -z "$(echo $*)" ] || printf '%s\n' "# install.sh: written on each run" '[Service]' "IPAddressAllow=$(echo $*)"; }
dropin domin 10-install.conf "$(allow $PROXY_IPS)"
dropin domin-worker 10-install.conf "$(allow $PROXY_IPS $SCAN_ALLOW)"
# Raw sockets for nmap SYN scans (on-prem --raw); a public install leaves the file as it is
if [ "$INTERNAL" = 1 ] && has posture; then
  if [ "$RAW" = 1 ]; then dropin domin-worker 30-raw.conf "$(cat "$APP/app/deploy/worker-raw.conf")"
  else dropin domin-worker 30-raw.conf ""; fi
fi

unit() {  # name, description, command, memory limit, task limit, extra [Service] line
  cat > "/etc/systemd/system/$1.service" <<EOF
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
User=domin
Group=domin
WorkingDirectory=$APP/app
EnvironmentFile=/etc/domin.env
ExecStart=$3
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
IPAddressDeny=$NON_PUBLIC
${DENY_MORE:+IPAddressDeny=$DENY_MORE}
${6:-}
UMask=0077
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RemoveIPC=true
RestrictNamespaces=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
MemoryMax=$4
TasksMax=$5

[Install]
WantedBy=multi-user.target
EOF
}
# X-Real-IP from nginx is trusted from localhost only (domin/web.py client_ip); no --proxy-headers needed.
unit domin "domin web app" "$APP/venv/bin/uvicorn --factory domin.web:create_app --host 127.0.0.1 --port 8000 --workers 2 --no-access-log" 2G 200 "IPAddressAllow=localhost"  # nginx connects over loopback
unit domin-worker "domin scan worker" "$APP/venv/bin/python -m domin worker" 16G 2000

if [ "$INTERNAL" = 1 ]; then
  # On-prem TLS (as wg-admin): the key never leaves this host and only nginx's master process (root) reads it.
  # Self-signed (825 days) until /etc/domin/tls.crt is replaced with a certificate your CA signed from tls.csr
  # (left while the certificate is self-signed or has under 30 days left), then re-run install.sh (adds HSTS).
  [ -d /etc/domin ] || install -d -m 755 /etc/domin
  [ -f /etc/domin/tls.key ] || (umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out /etc/domin/tls.key 2>/dev/null)
  chown root:root /etc/domin/tls.key; chmod 600 /etc/domin/tls.key
  SAN="DNS:$DOMAIN${ALIAS:+,DNS:$ALIAS}"
  selfsigned() { [ "$(openssl x509 -noout -issuer -nameopt compat -in "$1" | sed 's/^issuer=//')" = \
                   "$(openssl x509 -noout -subject -nameopt compat -in "$1" | sed 's/^subject=//')" ]; }
  expiring() { ! openssl x509 -checkend $((30 * 86400)) -noout -in "$1" >/dev/null 2>&1; }
  if [ ! -f /etc/domin/tls.crt ] || { selfsigned /etc/domin/tls.crt && expiring /etc/domin/tls.crt; }; then
    openssl req -x509 -key /etc/domin/tls.key -subj "/CN=$DOMAIN" -days 825 -addext "subjectAltName=$SAN" \
      -out /etc/domin/tls.crt 2>/dev/null
  fi
  if selfsigned /etc/domin/tls.crt || expiring /etc/domin/tls.crt; then
    openssl req -new -key /etc/domin/tls.key -subj "/CN=$DOMAIN" -addext "subjectAltName=$SAN" \
      -out /etc/domin/tls.csr 2>/dev/null
  fi
  # Who may open the site at all (--admin-sources); "any" = no network limit, the sign-in alone governs /admin
  { echo "# install.sh --admin-sources (DOMIN_ADMIN_SOURCES in /etc/domin.env)"
    if [ "$SOURCES" != any ]; then
      echo "allow 127.0.0.1;"; echo "allow ::1;"   # this host's own checks
      for n in ${SOURCES//,/ }; do echo "allow $n;"; done; echo "deny all;"
    fi
  } > /etc/nginx/domin-sources.conf
  # nginx 1.25.1+ deprecates "listen ... http2" (Debian 13: 1.26); Ubuntu 24.04's 1.24 has only that form
  if dpkg --compare-versions "$(dpkg-query -W -f='${Version}' nginx)" ge 1.25.1; then H2L="" H2="http2 on;"; else H2L=" http2" H2=""; fi
  # HSTS only with a CA-signed certificate: on a self-signed one browsers would lock users out of the warning page.
  # Installed the CA certificate? Re-run install.sh to turn it on.
  HSTS=""; selfsigned /etc/domin/tls.crt || HSTS='add_header Strict-Transport-Security "max-age=31536000" always;'
  cat > /etc/nginx/sites-available/domin <<EOF
limit_req_zone \$binary_remote_addr zone=domin_api:10m rate=2r/s;
limit_req_zone \$binary_remote_addr zone=domin_pages:10m rate=10r/s;
limit_conn_zone \$binary_remote_addr zone=domin_conn:10m;
server {   # plain HTTP: only a redirect to HTTPS (the sign-in cookies are Secure)
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    include /etc/nginx/domin-sources.conf;
    location / { return 301 https://$DOMAIN\$request_uri; }
}
server {   # any name or address on this host: on-prem users often type the IP
    listen 443 ssl$H2L default_server;
    listen [::]:443 ssl$H2L default_server;
    $H2
    server_name $DOMAIN $ALIAS;
    ssl_certificate /etc/domin/tls.crt;
    ssl_certificate_key /etc/domin/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    $HSTS
    include /etc/nginx/domin-sources.conf;
    include /etc/nginx/domin-site.conf;
}
EOF
else
rm -f /etc/nginx/domin-sources.conf
cat > /etc/nginx/sites-available/domin <<EOF
limit_req_zone \$binary_remote_addr zone=domin_api:10m rate=2r/s;
limit_req_zone \$binary_remote_addr zone=domin_pages:10m rate=10r/s;
limit_conn_zone \$binary_remote_addr zone=domin_conn:10m;
server {   # unknown Host headers: close the connection (the app has no host check)
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN $ALIAS;
    include /etc/nginx/domin-site.conf;
}
EOF
if [ -n "$ORIGIN" ]; then
  # Cloudflare's client certificate for Authenticated Origin Pulls (public CA, same for every zone)
  AOP="$ORIGIN/cloudflare-aop-ca.pem"
  [ -s "$AOP" ] || curl -fsS -o "$AOP" https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem
  openssl x509 -in "$AOP" -noout -subject | grep -q "Origin Pull" || { echo "bad $AOP"; rm -f "$AOP"; exit 1; }
  cat >> /etc/nginx/sites-available/domin <<EOF
server {   # unknown names (SNI): refuse the TLS handshake
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
}
server {   # Cloudflare -> origin, SSL mode Full (strict); only Cloudflare's client certificate gets in
    listen 443 ssl http2;   # 'http2 on' needs nginx 1.25; Ubuntu 24.04 has 1.24
    listen [::]:443 ssl http2;
    server_name $DOMAIN $ALIAS;
    ssl_certificate $ORIGIN/origin.crt;
    ssl_certificate_key $ORIGIN/origin.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_client_certificate $AOP;
    ssl_verify_client on;
    add_header Strict-Transport-Security "max-age=31536000" always;   # browsers only reach it through Cloudflare's HTTPS
    include /etc/nginx/domin-site.conf;
}
EOF
fi
fi   # public mode
cat > /etc/nginx/domin-site.conf <<'EOF'
server_tokens off;
client_max_body_size 4k;   # the only request body is a domain name in JSON
large_client_header_buffers 4 8k;
client_body_timeout 10s;
client_header_timeout 10s;
limit_conn domin_conn 20;
include /etc/nginx/domin-site.d/*.conf;   # extra locations on this host (e.g. /3dtools/)
location = /admin/settings/csv-import {   # Settings > CSV import: the one large body (the app caps it at 200 MB)
    client_max_body_size 201m;
    client_body_timeout 60s;
    proxy_request_buffering off;   # streamed to the app, which writes it to /var/lib/domin
    limit_req zone=domin_pages burst=40 nodelay;
    include /etc/nginx/domin-proxy.conf;
}
location / {
    limit_req zone=domin_pages burst=40 nodelay;
    include /etc/nginx/domin-proxy.conf;
}
location /api/ {
    limit_req zone=domin_api burst=10 nodelay;
    include /etc/nginx/domin-proxy.conf;
}
EOF
cat > /etc/nginx/domin-proxy.conf <<'EOF'
proxy_pass http://127.0.0.1:8000;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 40s;
limit_req_status 429;
EOF
if [ "$CLOUDFLARE" = 1 ]; then   # $remote_addr (rate limits, X-Real-IP) becomes the visitor, not Cloudflare's edge
  CF=$(curl -fsS https://www.cloudflare.com/ips-v4; echo; curl -fsS https://www.cloudflare.com/ips-v6)
  { echo "# Cloudflare ranges from cloudflare.com/ips-v4 and ips-v6 (install.sh --cloudflare; re-run to refresh)"
    grep -E '^[0-9a-f:.]+/[0-9]+$' <<<"$CF" | sed 's/.*/set_real_ip_from &;/'
    echo "real_ip_header CF-Connecting-IP;"; } > /etc/nginx/conf.d/domin-cloudflare.conf
  [ "$(grep -c '^set_real_ip_from' /etc/nginx/conf.d/domin-cloudflare.conf)" -gt 5 ] || \
    { echo "cloudflare: range download failed"; rm -f /etc/nginx/conf.d/domin-cloudflare.conf; exit 1; }
else
  rm -f /etc/nginx/conf.d/domin-cloudflare.conf
fi
ln -sf /etc/nginx/sites-available/domin /etc/nginx/sites-enabled/domin
rm -f /etc/nginx/sites-enabled/default
nginx -t -q

if has posture; then
  # Mullvad tunnel settings saved on the Routes page (Settings): a root path unit runs mullvad-tunnel.sh apply
  install -m 644 "$APP/app/deploy/domin-mullvad.path" "$APP/app/deploy/domin-mullvad.service" /etc/systemd/system/
  # Tor on/off from the Routes page: a root path unit runs tor-switch.sh apply
  install -m 644 "$APP/app/deploy/domin-tor.path" "$APP/app/deploy/domin-tor.service" /etc/systemd/system/
fi
# Retired: the public database sync (replaced by Settings > CSV import). A host that had it loses its units, the
# copy inbox and its state files; nothing else on the host is touched.
if [ -e /etc/systemd/system/domin-public-sync.path ] || [ -e /etc/systemd/system/domin-public-sync.service ] ||
   [ -e /var/lib/domin-sync ]; then
  systemctl disable -q --now domin-public-sync.path domin-public-sync.service 2>/dev/null || true
  rm -f /etc/systemd/system/domin-public-sync.path /etc/systemd/system/domin-public-sync.service
  systemctl daemon-reload
  rm -rf /var/lib/domin-sync
  rm -f /var/lib/domin/public-sync.request /var/lib/domin/public-sync.status
  echo "public sync: removed (retired; Settings > CSV import replaces it)"
fi
if [ -f /etc/domin.env ] && grep -q '^DOMIN_PUBLIC_SYNC=' /etc/domin.env; then
  sed -i '/^DOMIN_PUBLIC_SYNC=/d' /etc/domin.env
fi

systemctl daemon-reload
if has posture; then
  systemctl enable -q --now domin-mullvad.path
  bash "$APP/app/deploy/tor-switch.sh" "$TOR_START" >/dev/null
  systemctl enable -q --now domin-tor.path
fi
systemctl enable -q domin
systemctl restart domin
if [ "$WORKER" = 1 ]; then systemctl enable -q domin-worker; systemctl restart domin-worker
else systemctl disable -q --now domin-worker 2>/dev/null || true; fi
# enable --now: a prior single-site uninstall.sh disabled+stopped nginx (empty sites-enabled); a bare
# `reload` would then fail under `set -e` and abort the reinstall with the public site down. Start+enable first.
systemctl enable -q --now nginx
systemctl reload nginx

if [ -n "$EMAIL" ]; then
  # certbot adds the 443 server, the HTTP -> HTTPS redirect and renewal (systemd timer)
  certbot --nginx -d "$DOMAIN" ${ALIAS:+-d "$ALIAS"} -m "$EMAIL" --agree-tos --redirect --non-interactive -q
  grep -q Strict-Transport-Security /etc/nginx/sites-available/domin || \
    sed -i '0,/listen 443 ssl;/s//listen 443 ssl;\n    add_header Strict-Transport-Security "max-age=31536000" always;/' \
      /etc/nginx/sites-available/domin
  nginx -t -q && systemctl reload nginx
fi

if [ "$FIREWALL" = 1 ]; then
  apt-get install -y -q ufw >/dev/null
  # --ssh-from is kept for later runs (an update without it must not open SSH to everyone)
  if [ -n "$SSH_FROM" ]; then setenv DOMIN_SSH_FROM "$SSH_FROM"; else SSH_FROM=$(envget DOMIN_SSH_FROM); fi
  # the 22/80/443 rules are this script's: drop the old ones (highest number first), then add the current lists
  for n in $(ufw status numbered | sed -n 's/^\[ *\([0-9]*\)\] \(22\|80\|443\|80,443\)\/tcp .*/\1/p' | sort -rn); do
    ufw --force delete "$n" >/dev/null
  done
  if [ -n "$SSH_FROM" ]; then
    for net in ${SSH_FROM//,/ }; do ufw allow from "$net" to any port 22 proto tcp >/dev/null; done
  else
    ufw allow 22/tcp >/dev/null
  fi
  if [ "$INTERNAL" = 1 ] && [ "$SOURCES" != any ]; then   # on-prem: the web ports only from --admin-sources
    for net in ${SOURCES//,/ }; do ufw allow from "$net" to any port 80,443 proto tcp >/dev/null; done
  else
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
  fi
  ufw --force enable >/dev/null
fi

for _ in $(seq 20); do curl -fs -o /dev/null http://127.0.0.1:8000/healthz && break; sleep 1; done
CLI="cd $APP/app && set -a && . /etc/domin.env && runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 $APP/venv/bin/python -m domin"
if [ "$INTERNAL" = 1 ]; then
  for _ in $(seq 10); do   # nginx reloads its workers in the background
    CODE=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" || true)
    [ "$CODE" = 200 ] && break; sleep 1
  done
  echo "domin: web $(systemctl is-active domin), worker $(systemctl is-active domin-worker || true), HTTPS $CODE," \
    "TLS $(selfsigned /etc/domin/tls.crt && echo "self-signed (CA request: /etc/domin/tls.csr)" || echo "CA-signed")"
  if [ -n "$ADMIN_USER" ]; then
    if ( eval "$CLI user-list" ) | cut -f1 | grep -qx "$ADMIN_USER"; then
      echo "admin user $ADMIN_USER exists (new password: $CLI user-passwd $ADMIN_USER)"
    elif [ -t 0 ]; then   # asks for the password twice (the installer's operator is that admin: --own)
      ( eval "$CLI user-add $ADMIN_USER --role admin --own" ) || echo "admin user not created; run: $CLI user-add $ADMIN_USER --role admin --own"
    else
      echo "no terminal for the password; create the admin with: $CLI user-add $ADMIN_USER --role admin --own"
    fi
  fi
  echo "site: https://$DOMAIN/ (sign-in /admin) for $SOURCES; users: $CLI user-add NAME --role admin|power, user-grant NAME DOMAIN viewer|admin"
else
echo "domin: web $(systemctl is-active domin), worker $(systemctl is-active domin-worker || true)," \
  "HTTP $(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" http://127.0.0.1/)"
echo "admin page: https://$DOMAIN/admin for DOMIN_ADMIN_IPS in /etc/domin.env (HTTPS only; set its password:" \
  "$CLI admin-password)"
fi
