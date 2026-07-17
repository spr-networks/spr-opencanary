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

KRUN_MAC="02:53:50:52:4b:0d"
KRUN_TAP="kopencanary0"
curl --fail-with-body --silent --show-error "http://127.0.0.1/device?identity=${KRUN_MAC}" \
  -H "Authorization: Bearer ${SPR_API_TOKEN}" -H "Content-Type: application/json" \
  -X PUT --data-raw "{\"MAC\":\"${KRUN_MAC}\",\"Name\":\"spr-opencanary\",\"Policies\":[\"lan\",\"wan\",\"dns\"],\"Groups\":[]}" >/dev/null
if ! sudo nft get element inet filter dhcp_access "{ \"${KRUN_TAP}\" . ${KRUN_MAC} }" >/dev/null 2>&1; then
  sudo nft add element inet filter dhcp_access "{ \"${KRUN_TAP}\" . ${KRUN_MAC} : accept }"
fi

docker compose -f docker-compose-krun.yml build
docker compose -f docker-compose-krun.yml up -d

CANARY_IP=
for _ in $(seq 1 30); do
  CANARY_IP="$(jq -r --arg mac "$KRUN_MAC" '.[$mac].RecentIP // empty' "$SUPERDIR/state/public/devices-public.json")"
  [ -n "$CANARY_IP" ] && break
  sleep 1
done
[ -n "$CANARY_IP" ] || { echo "spr-opencanary did not obtain an SPR DHCP lease" >&2; exit 1; }
curl --fail-with-body "http://127.0.0.1/firewall/custom_interface" \
  -H "Authorization: Bearer ${SPR_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  -X PUT \
  --data-raw "{\"RuleName\":\"Plugin-spr-opencanary\",\"SrcIP\":\"${CANARY_IP}\",\"Interface\":\"${KRUN_TAP}\",\"Policies\":[\"lan\",\"wan\",\"dns\"],\"Groups\":[],\"Tags\":[]}"

echo
echo "[+] OpenCanary is listening at ${CANARY_IP}."
echo "    Open Plugins -> spr-opencanary to tune decoys and notifications."
