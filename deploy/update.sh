#!/bin/bash
# Code-only update in place: reads a tar of domin/ and deploy/ on stdin, copies the files that differ and restarts
# only what they need, so a web-only change never interrupts running scans.
#   web app (domin)        any changed file under domin/
#   worker (domin-worker)  a changed file the worker runs: anything under domin/ except templates/, static/ and
#                          web.py (an interrupted posture scan goes back to the queue and starts over)
# deploy/ files take effect without a restart (scripts) or need install.sh (unit files, dependencies).
# Usage, from a checkout:  git archive HEAD domin deploy | ssh <host> 'sudo bash /opt/domin/app/deploy/update.sh'
#   or with a file:        sudo bash update.sh FILE.tar   (FILE.tar.sha256 next to it is checked when present)
#   or a known checksum:   ... | sudo bash update.sh --sha256 HEX
# The archive may hold only regular files and directories under domin/ and deploy/: links, devices and other entry
# types, absolute paths and .. are refused before anything is extracted. Afterwards the code belongs to root and is
# not writable for group or others; bytecode caches are removed (the services cannot write new ones).
set -euo pipefail
APP=${DOMIN_APP:-/opt/domin/app}
NEW=$(mktemp -d)
trap 'rm -rf "$NEW"' EXIT
ARC=$NEW/update.tar
mkdir "$NEW/files"

SUM=
if [ "${1:-}" = --sha256 ]; then
  SUM=${2:-}
  [[ "$SUM" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "update: --sha256 needs a 64-digit hex checksum" >&2; exit 2; }
  cat > "$ARC"
elif [ -n "${1:-}" ]; then
  cp -- "$1" "$ARC"
  if [ -f "$1.sha256" ]; then
    SUM=$(awk 'NR == 1 {print $1}' "$1.sha256")
    [[ "$SUM" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "update: $1.sha256 holds no checksum" >&2; exit 2; }
  fi
else
  cat > "$ARC"
fi
if [ -n "$SUM" ]; then
  echo "$SUM  $ARC" | sha256sum -c --quiet - || { echo "update: checksum mismatch, nothing changed" >&2; exit 1; }
  echo "checksum: OK"
fi

# entry types from the verbose listing (first character: - file, d directory; l h c b p and others are refused)
tar -tvf "$ARC" > "$NEW/types"
tar -tf "$ARC" > "$NEW/names"
bad_type=$(awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" && n++ < 5' "$NEW/types")
if [ -n "$bad_type" ]; then
  printf 'update: refused, the archive holds links, devices or other special entries:\n%s\n' "$bad_type" >&2
  exit 1
fi
bad_name=$(awk '!/^(domin|deploy)(\/|$)/ || /(^|\/)\.\.(\/|$)/ { if (n++ < 5) print }' "$NEW/names")
if [ -n "$bad_name" ]; then
  printf 'update: refused, entries outside domin/ and deploy/:\n%s\n' "$bad_name" >&2
  exit 1
fi
tar -x -m --no-same-owner --no-same-permissions -C "$NEW/files" -f "$ARC"

changed=$(cd "$NEW/files" && find . -type f | sed 's|^\./||' | sort | while read -r f; do
  cmp -s "$f" "$APP/$f" || echo "$f"
done)
if [ -z "$changed" ]; then
  echo "update: nothing changed"
else
  printf 'changed: %s\n' $changed
  cp -a "$NEW/files"/* "$APP"/   # the entries, not "$NEW/files"/. : that would give $APP the temp dir's mode 700
fi
# Bytecode caches: the services cannot write them (read-only code), so any present came from a CLI run as the app
# user or belong to a removed module; drop them all. Then the code is root's and read-only for everyone else.
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +
chown -R root:root "$APP"
chmod -R go-w "$APP"
[ -n "$changed" ] || exit 0

# Proxy settings for pip from /etc/domin.env, parsed as KEY=VALUE (never run as shell code)
proxy_env() {
  local k v ok='^[]A-Za-z0-9.,:/@%_+=*[-]*$'   # URL and host-list characters (] first, - last: literals)
  [ -r /etc/domin.env ] || return 0
  while IFS='=' read -r k v; do
    case $k in https_proxy|http_proxy|no_proxy|HTTPS_PROXY|HTTP_PROXY|NO_PROXY) ;; *) continue ;; esac
    v=${v%$'\r'}
    if [[ "$v" =~ ^\"(.*)\"$ ]] || [[ "$v" =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
    if [[ ! "$v" =~ $ok ]]; then
      echo "update: $k in /etc/domin.env has unexpected characters; ignored" >&2
      continue
    fi
    export "$k=$v"
  done < /etc/domin.env
}
# new or raised dependencies first, so the restarted services find them
if printf '%s\n' "$changed" | grep -qx 'deploy/requirements.txt'; then
  ( proxy_env
    "${APP%/app}/venv/bin/pip" install -q --no-input --require-hashes -r "$APP/deploy/requirements.txt" )
  echo "dependencies: installed from deploy/requirements.txt (hashes checked)"
fi

# files a release dropped (cp above only adds and replaces)
rm -f "$APP/domin/publicsync.py" "$APP/deploy/public-sync.sh" "$APP/deploy/domin-public-sync.path" \
  "$APP/deploy/domin-public-sync.service"
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
web=$(printf '%s\n' "$changed" | grep '^domin/' || true)
worker=$(printf '%s\n' "$web" | grep -Ev '^domin/(templates|static)/|^domin/web\.py$' || true)
if [ -n "$web" ]; then
  systemctl restart domin
  echo "web: restarted ($(systemctl is-active domin))"
else
  echo "web: unchanged, left running"
fi
if [ -n "$worker" ] && systemctl is-enabled -q domin-worker 2>/dev/null; then
  systemctl restart domin-worker
  echo "worker: restarted ($(systemctl is-active domin-worker)); running posture scans requeued"
else
  echo "worker: left running"
fi
