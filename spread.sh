#!/bin/bash
# Pull a WordPress target list from Google Drive and spread it over the fleet.
#
#   ./spread.sh <drive-link-or-id>            # download, shard, deploy (default)
#   ./spread.sh <drive-link-or-id> --fetch    # download only, no deploy
#   ./spread.sh --local lists/foo.txt         # deploy an already-downloaded file
#
# The file is cached by Drive id under lists/, deduplicated and validated
# before anything touches a worker. Sharding, restart and progress handling are
# deploy.sh's job: this script only resolves the list.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
LISTS="$HERE/lists"
FLEET_FILE="${FLEET_FILE:-$HERE/fleet.txt}"
DEPLOY="$HERE/deploy.sh"
DRIVE_HOST="https://drive.usercontent.google.com/download"

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

drive_id() {
    # Accepts a bare id or any drive.google.com/file/d/<id>/... link.
    local in="$1" id
    id=$(printf '%s' "$in" | sed -n 's#.*/file/d/\([A-Za-z0-9_-]\{10,\}\).*#\1#p')
    [ -n "$id" ] || id=$(printf '%s' "$in" | sed -n 's#.*[?&]id=\([A-Za-z0-9_-]\{10,\}\).*#\1#p')
    [ -n "$id" ] || id=$(printf '%s' "$in" | grep -E '^[A-Za-z0-9_-]{20,}$')
    printf '%s' "$id"
}

fetch() {
    local src="$1" id dest tmp
    id=$(drive_id "$src")
    if [ -z "$id" ]; then
        echo "not a Drive link or id: $src" >&2
        return 1
    fi
    mkdir -p "$LISTS"
    dest="$LISTS/$id.txt"
    tmp="$dest.part"

    if command -v gdown >/dev/null 2>&1; then
        gdown --quiet -O "$tmp" "$id" || true
    fi
    if [ ! -s "$tmp" ]; then
        # confirm=t skips the virus-scan interstitial for large files.
        curl -fsSL --retry 3 --retry-delay 3 -o "$tmp" "$DRIVE_HOST?id=$id&export=download&confirm=t" || {
            echo "download failed: $id" >&2
            rm -f "$tmp"
            return 1
        }
    fi

    if head -c 512 "$tmp" | grep -qi '<!DOCTYPE html>\|<html'; then
        echo "Drive returned an HTML page, not a list: $id" >&2
        rm -f "$tmp"
        return 1
    fi

    # Normalise: strip CR, trim blanks, drop comments, dedupe, keep scheme.
    tr -d '\r' < "$tmp" | sed 's/[[:space:]]*$//' | grep -Ev '^[[:space:]]*(#|$)' \
        | awk '!seen[tolower($0)]++' > "$dest.norm"
    mv -f "$dest.norm" "$dest"
    rm -f "$tmp"
    printf '%s\n' "$dest"
}

validate() {
    local f="$1" n bad
    n=$(wc -l < "$f")
    bad=$(grep -civ '^https\?://' "$f" || true)
    if [ "$n" -lt 10 ]; then
        echo "suspicious list: only $n lines in $f" >&2
        return 1
    fi
    [ "$bad" -gt 0 ] && echo "warning: $bad lines do not start with http(s)://"
    echo "$n"
}

LOCAL=""
DEPLOY_NOW=1
case "${1:-}" in
    -h|--help|'') usage 0 ;;
    --local)
        LOCAL="${2:?path}"
        [ -r "$LOCAL" ] || { echo "cannot read $LOCAL" >&2; exit 1; }
        ;;
    *)
        SRC="$1"
        [ "${2:-}" = "--fetch" ] && DEPLOY_NOW=0
        ;;
esac

[ -r "$FLEET_FILE" ] || { echo "fleet file missing: $FLEET_FILE" >&2; exit 1; }
[ -x "$DEPLOY" ] || { echo "deploy.sh not executable: $DEPLOY" >&2; exit 1; }

if [ -z "$LOCAL" ]; then
    echo "fetching list from Drive"
    LOCAL=$(fetch "$SRC") || exit 1
fi

N=$(validate "$LOCAL") || exit 1
echo "list ready: $LOCAL ($N sites)"
[ "$DEPLOY_NOW" -eq 1 ] || exit 0

LOCAL_SITES="$LOCAL" LOCAL_PASS="${LOCAL_PASS:-$HERE/pass.txt}" FLEET_FILE="$FLEET_FILE" exec "$DEPLOY"
