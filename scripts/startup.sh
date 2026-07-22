#!/bin/bash
set -euo pipefail
umask 007

mkdir -p /state/plugins/spr-opencanary /etc/opencanaryd
CANARY_IP="$(ip -4 -o addr show dev eth0 scope global | awk 'NR == 1 { split($4, a, "/"); print a[1] }')"
if [ -z "$CANARY_IP" ]; then
    echo "spr-opencanary has no DHCP address on eth0" >&2
    exit 1
fi
export CANARY_IP
exec /spr_opencanary_plugin
