#!/bin/bash
# domin uninstall: removes what install.sh put on this host. Run as root:
#   bash uninstall.sh            keep the data (/var/lib/domin: the scan database; /etc/domin.env: settings;
#                                /etc/domin: the on-prem TLS key and certificate)
#   bash uninstall.sh --purge    also delete that data (every scan and setting; copy /var/lib/domin/domin.db first)
# Distribution packages (nginx, python3-venv, ...) and the Let's Encrypt certificate stay; remove them by hand if
# unused. Host-wide apt security updates (20auto-upgrades) and ufw rules are left as they are.
set -euo pipefail

purge=0
case ${1:-} in
  "") ;;
  --purge) purge=1 ;;
  *) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { echo "uninstall.sh: run as root" >&2; exit 1; }

# Services
systemctl disable -q --now domin domin-worker domin-mullvad.path domin-public-sync.path 2>/dev/null || true
rm -f /etc/systemd/system/domin.service /etc/systemd/system/domin-worker.service \
  /etc/systemd/system/domin-mullvad.path /etc/systemd/system/domin-mullvad.service \
  /etc/systemd/system/domin-public-sync.path /etc/systemd/system/domin-public-sync.service
# the Mullvad tunnel (wg-quick@mullvad, /etc/wireguard/mullvad.*) stays: deploy/mullvad-tunnel.sh down stops it
rm -rf /etc/systemd/system/domin.service.d /etc/systemd/system/domin-worker.service.d
systemctl daemon-reload

# nginx: the site plus the snippets install.sh wrote. The add-on directory domin-site.d/ (e.g. 3dtools) is left;
# it is removed only if it is now empty.
rm -f /etc/nginx/sites-enabled/domin /etc/nginx/sites-available/domin \
  /etc/nginx/domin-site.conf /etc/nginx/domin-proxy.conf /etc/nginx/conf.d/domin-cloudflare.conf \
  /etc/nginx/domin-sources.conf
rmdir --ignore-fail-on-non-empty /etc/nginx/domin-site.d 2>/dev/null || true
if systemctl is-active -q nginx; then
  if [ -z "$(ls -A /etc/nginx/sites-enabled 2>/dev/null)" ]; then systemctl disable -q --now nginx  # nothing else served
  else nginx -tq && systemctl reload nginx; fi
fi

# Application code and venv (never the data dir)
rm -rf /opt/domin
rm -f /etc/apt/apt.conf.d/52domin-unattended   # the no-reboot note; 20auto-upgrades is host-wide and stays

if [ "$purge" = 1 ]; then
  rm -rf /var/lib/domin /etc/domin   # /etc/domin: the on-prem TLS key and certificate
  rm -f /etc/domin.env
  id -u domin >/dev/null 2>&1 && userdel domin 2>/dev/null || true
  echo "domin removed, data deleted"
else
  echo "domin removed; data kept in /var/lib/domin, /etc/domin.env and /etc/domin (TLS) (reinstall: install.sh)"
fi
