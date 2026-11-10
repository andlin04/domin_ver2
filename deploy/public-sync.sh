#!/bin/bash
# domin: a copy of the public server's database for a staging instance (Settings > Public database).
#   bash deploy/public-sync.sh receive   read a zstd-compressed domin.db on stdin and keep it as the newest copy
#   bash deploy/public-sync.sh import    import the newest copy (domin-public-sync.service, started by the Sync button)
#
# receive is meant as the forced command of one SSH key in root's authorized_keys, for the host that holds the
# public server's nightly backup, e.g.:
#   from="<backup host>",command="/bin/bash /opt/domin/app/deploy/public-sync.sh receive",restrict ssh-ed25519 AAAA...
# and on that host, after each backup: tar -xOf <backup> domin.db | zstd -q -c | ssh -i <key> root@<this host>
# Only the database is sent (never the backup's domin.env). The copy is checked before it replaces the last one.
#
# import writes $DATA/public-sync.status (no secrets): {at, ok, message, copy} for the page, and restarts domin so
# its cached figures follow the new data. The worker is not restarted: queued jobs are not touched.
set -uo pipefail
APP=/opt/domin DATA=/var/lib/domin INBOX=/var/lib/domin-sync
COPY=$INBOX/public.db.zst
STATUS=$DATA/public-sync.status
MAX_BYTES=$((8 * 1024 * 1024 * 1024))   # a decompressed copy larger than this is refused

status_file() {  # ok(true|false) message
  # $DATA belongs to the app user: root writes only through a fresh mktemp file (never a fixed name it could plant)
  local tmp; tmp=$(mktemp "$DATA/.public-sync.status.XXXXXX") || return 1
  python3 -c 'import json, sys, os, datetime
copy = sys.argv[3]
when = datetime.datetime.fromtimestamp(os.path.getmtime(copy)).strftime("%Y-%m-%d %H:%M") if os.path.exists(copy) else ""
print(json.dumps({"at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), "ok": sys.argv[1] == "true",
                  "message": sys.argv[2][:300], "copy": when}))' "$1" "$2" "$COPY" > "$tmp" &&
    chown domin:domin "$tmp" && chmod 640 "$tmp" && mv -f "$tmp" "$STATUS"
}

case "${1:-}" in
  receive)
    [ -d "$INBOX" ] || install -d -m 700 "$INBOX"   # this script's own directory, created once
    part=$INBOX/.partial
    head -c "$MAX_BYTES" > "$part" || { rm -f "$part"; echo "receive: read failed" >&2; exit 1; }
    zstd -q -t "$part" || { rm -f "$part"; echo "receive: not a zstd stream" >&2; exit 1; }
    [ "$(zstd -q -d -c "$part" | head -c 15)" = "SQLite format 3" ] ||
      { rm -f "$part"; echo "receive: not an SQLite database" >&2; exit 1; }
    mv "$part" "$COPY"
    echo "received $(stat -c %s "$COPY") bytes"
    ;;
  import)
    rm -f "$DATA/public-sync.request"
    [ -s "$COPY" ] || { status_file false "No copy of the public database has reached this host yet."; exit 0; }
    work=$(mktemp "$DATA/.public-import.XXXXXX") || { status_file false "No room for the import."; exit 1; }
    if ! zstd -q -d -c "$COPY" | head -c "$MAX_BYTES" > "$work"; then
      rm -f "$work"; status_file false "The copy could not be unpacked."; exit 1
    fi
    chown domin:domin "$work"
    if out=$(cd "$APP/app" && set -a && . /etc/domin.env && set +a &&
             runuser -u domin -- "$APP/venv/bin/python" -m domin import-public "$work" 2>&1); then
      rm -f "$work" "$work-wal" "$work-shm"
      systemctl restart domin
      status_file true "Imported."
    else
      rm -f "$work" "$work-wal" "$work-shm"
      status_file false "Import failed: $(printf '%s' "$out" | tail -n 1)"
      exit 1
    fi
    ;;
  *)
    echo "usage: $0 receive|import" >&2; exit 2
    ;;
esac
