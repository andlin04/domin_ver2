#!/bin/bash
# Code-only update in place: reads a tar of domin/ and deploy/ on stdin, copies the files that differ and restarts
# only what they need, so a web-only change never interrupts running scans.
#   web app (domin)        any changed file under domin/
#   worker (domin-worker)  a changed file the worker runs: anything under domin/ except templates/, static/ and
#                          web.py (an interrupted posture scan goes back to the queue and starts over)
# deploy/ files take effect without a restart (scripts) or need install.sh (unit files, dependencies).
# Usage, from a checkout:  git archive HEAD domin deploy | ssh <host> 'sudo bash /opt/domin/app/deploy/update.sh'
set -euo pipefail
APP=${DOMIN_APP:-/opt/domin/app}
NEW=$(mktemp -d)
trap 'rm -rf "$NEW"' EXIT
tar -x -m -C "$NEW"

changed=$(cd "$NEW" && find . -type f | sed 's|^\./||' | sort | while read -r f; do
  cmp -s "$f" "$APP/$f" || echo "$f"
done)
if [ -z "$changed" ]; then
  echo "update: nothing changed"
  exit 0
fi
printf 'changed: %s\n' $changed
cp -a "$NEW"/* "$APP"/   # the entries, not "$NEW"/. : that would give $APP the temp dir's mode 700

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
