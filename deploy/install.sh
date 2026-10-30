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
#
# Re-running updates the code and keeps the database, /etc/domin.env and the TLS certificate.
set -euo pipefail

DOMAIN= EMAIL= HISTORY= REPLACE=0 WORKER=1 FIREWALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN=$2; shift ;;
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
[ -z "$HISTORY" ] || [ -f "$HISTORY" ] || { echo "no such file: $HISTORY"; exit 2; }
SRC=$(cd "$(dirname "$0")/.." && pwd)
APP=/opt/domin DATA=/var/lib/domin

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv nginx rsync sqlite3 curl >/dev/null
[ -z "$EMAIL" ] || apt-get install -y -q certbot python3-certbot-nginx >/dev/null

id -u domin >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin domin
[ -d "$DATA" ] || install -d -o domin -g domin -m 750 "$DATA"
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
  ( umask 027; printf 'DOMIN_DB=%s/domin.db\nDOMIN_REFRESH_DAYS=0\n' "$DATA" > /etc/domin.env )
  chown root:domin /etc/domin.env
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

unit() {  # name, description, command
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

[Install]
WantedBy=multi-user.target
EOF
}
# X-Real-IP from nginx is trusted from localhost only (domin/web.py client_ip); no --proxy-headers needed.
unit domin "domin web app" "$APP/venv/bin/uvicorn --factory domin.web:create_app --host 127.0.0.1 --port 8000 --workers 2 --no-access-log"
unit domin-worker "domin scan worker" "$APP/venv/bin/python -m domin worker"

cat > /etc/nginx/sites-available/domin <<EOF
limit_req_zone \$binary_remote_addr zone=domin_api:10m rate=30r/m;
limit_req_zone \$binary_remote_addr zone=domin_pages:10m rate=10r/s;
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    server_tokens off;
    client_max_body_size 16k;
    location / {
        limit_req zone=domin_pages burst=40 nodelay;
        include /etc/nginx/domin-proxy.conf;
    }
    location /api/ {
        limit_req zone=domin_api burst=10 nodelay;
        include /etc/nginx/domin-proxy.conf;
    }
}
EOF
cat > /etc/nginx/domin-proxy.conf <<'EOF'
proxy_pass http://127.0.0.1:8000;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_read_timeout 60s;
limit_req_status 429;
EOF
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
  certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --redirect --non-interactive -q
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
