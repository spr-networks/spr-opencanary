#!/bin/bash
# Command-line alternative to installing through SPR's Plugins page.
set -euo pipefail
cd "$(dirname "$0")"

echo "Please enter your SPR path (/home/spr/super/)"
read -r SUPERDIR
SUPERDIR="${SUPERDIR:-/home/spr/super/}"
export SUPERDIR

echo "Please enter your SPR API token:"
read -r SPR_API_TOKEN
if [ -z "$SPR_API_TOKEN" ]; then
  echo "Need an API token; generate one on SPR's Auth Keys page."
  exit 1
fi

CONFIG_DIR="$SUPERDIR/configs/plugins/spr-opencanary"
STATE_DIR="$SUPERDIR/state/plugins/spr-opencanary"
mkdir -p "$CONFIG_DIR" "$STATE_DIR"
printf '%s' "$SPR_API_TOKEN" > "$CONFIG_DIR/api-token"
chmod 600 "$CONFIG_DIR/api-token"

docker compose build
docker compose up -d

CANARY_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' spr-opencanary)
curl --fail-with-body "http://127.0.0.1/firewall/custom_interface" \
  -H "Authorization: Bearer ${SPR_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  -X PUT \
  --data-raw "{\"RuleName\":\"Plugin-spr-opencanary\",\"SrcIP\":\"${CANARY_IP}\",\"Interface\":\"spr-opencanary\",\"Policies\":[\"lan\",\"wan\",\"dns\"],\"Groups\":[],\"Tags\":[]}"

echo
echo "[+] OpenCanary is listening at ${CANARY_IP}."
echo "    Open Plugins -> spr-opencanary to tune decoys and notifications."
