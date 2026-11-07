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
#   --firewall          enable ufw with SSH (22), HTTP and HTTPS only
#   --alias A           extra host name for the same site (e.g. www.example.com)
#   --cloudflare        site is proxied by Cloudflare: take the client address from CF-Connecting-IP (Cloudflare's
#                       published ranges only), so rate limits apply per visitor; HTTPS can then stay at Cloudflare
#   --origin-cert DIR   with --cloudflare: HTTPS on 443 with a Cloudflare Origin CA certificate (DIR/origin.crt and
#                       DIR/origin.key) that only accepts Cloudflare's client certificate (Authenticated Origin
#                       Pulls); for SSL mode Full (strict). Port 80 keeps serving; close it in the firewall once
#                       Cloudflare connects on 443.
#
# Re-running updates the code and keeps the database, /etc/domin.env and the TLS certificate.
set -euo pipefail

DOMAIN= ALIAS= EMAIL= HISTORY= REPLACE=0 WORKER=1 FIREWALL=0 CLOUDFLARE=0 ORIGIN=
while [ $# -gt 0 ]; do
  case "$1" in
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
[ -n "$DOMAIN" ] || { echo "--domain is required"; exit 2; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "bad --domain"; exit 2; }
[[ "$ALIAS" =~ ^[A-Za-z0-9.-]*$ ]] || { echo "bad --alias"; exit 2; }
[ -z "$HISTORY" ] || [ -f "$HISTORY" ] || { echo "no such file: $HISTORY"; exit 2; }
if [ -n "$ORIGIN" ]; then
  [ "$CLOUDFLARE" = 1 ] && [ -z "$EMAIL" ] || { echo "--origin-cert needs --cloudflare and no --email"; exit 2; }
  [ -f "$ORIGIN/origin.crt" ] && [ -f "$ORIGIN/origin.key" ] || { echo "need $ORIGIN/origin.crt and origin.key"; exit 2; }
fi
SRC=$(cd "$(dirname "$0")/.." && pwd)
APP=/opt/domin DATA=/var/lib/domin

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv nginx rsync sqlite3 curl >/dev/null
[ -z "$EMAIL" ] || apt-get install -y -q certbot python3-certbot-nginx >/dev/null

id -u domin >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin domin
[ -d "$DATA" ] || install -d -o domin -g domin -m 700 "$DATA"
[ -d "$APP" ] || install -d -m 755 "$APP"
rsync -a --delete --exclude .git/ --exclude tests/ --exclude '*.db' "$SRC/" "$APP/app/"
chown -R root:root "$APP/app"
chmod 755 "$APP/app"

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
python3 -c 'import tomllib, sys; [print(d) for d in tomllib.load(open(sys.argv[1], "rb"))["project"]["dependencies"]]' \
  "$APP/app/pyproject.toml" > "$APP/requirements.txt"
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

if [ ! -f /etc/domin.env ]; then
  ( umask 027; printf 'DOMIN_DB=%s/domin.db\nDOMIN_REFRESH_DAYS=0\nDOMIN_QUEUE_MAX=50\nDOMIN_LOOKUPS_PER_MINUTE=30\n' \
      "$DATA" > /etc/domin.env )
  chown root:domin /etc/domin.env
fi
# Admin page at /admin, served and linked only for these client addresses (comma-separated IPs/CIDRs; edit, then
# systemctl restart domin); everyone else gets 404. `python -m domin admin-password` sets its password.
grep -q '^DOMIN_ADMIN_IPS=' /etc/domin.env || echo "DOMIN_ADMIN_IPS=203.0.113.10" >> /etc/domin.env

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
  ( set -a; . /etc/domin.env; cd "$APP/app"; runuser -u domin -- "$APP/venv/bin/python" -m domin geoip "$GEO" )
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

unit() {  # name, description, command, extra [Service] line
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
${4:-}

[Install]
WantedBy=multi-user.target
EOF
}
# X-Real-IP from nginx is trusted from localhost only (domin/web.py client_ip); no --proxy-headers needed.
unit domin "domin web app" "$APP/venv/bin/uvicorn --factory domin.web:create_app --host 127.0.0.1 --port 8000 --workers 2 --no-access-log" "IPAddressAllow=localhost"  # nginx connects over loopback
unit domin-worker "domin scan worker" "$APP/venv/bin/python -m domin worker"

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
    include /etc/nginx/domin-site.conf;
}
EOF
fi
cat > /etc/nginx/domin-site.conf <<'EOF'
server_tokens off;
client_max_body_size 4k;   # the only request body is a domain name in JSON
large_client_header_buffers 4 8k;
client_body_timeout 10s;
client_header_timeout 10s;
limit_conn domin_conn 20;
include /etc/nginx/domin-site.d/*.conf;   # extra locations on this host (e.g. /3dtools/)
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

systemctl daemon-reload
systemctl enable -q domin
systemctl restart domin
if [ "$WORKER" = 1 ]; then systemctl enable -q domin-worker; systemctl restart domin-worker
else systemctl disable -q --now domin-worker 2>/dev/null || true; fi
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
  ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
  ufw --force enable >/dev/null
fi

for _ in $(seq 20); do curl -fs -o /dev/null http://127.0.0.1:8000/healthz && break; sleep 1; done
echo "domin: web $(systemctl is-active domin), worker $(systemctl is-active domin-worker || true)," \
  "HTTP $(curl -s -o /dev/null -w '%{http_code}' -H "Host: $DOMAIN" http://127.0.0.1/)"
echo "admin page: https://$DOMAIN/admin for DOMIN_ADMIN_IPS in /etc/domin.env (HTTPS only; set its password:" \
  "cd $APP/app && set -a && . /etc/domin.env && runuser -u domin -- $APP/venv/bin/python -m domin admin-password)"
