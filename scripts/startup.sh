#!/bin/bash
set -euo pipefail
umask 007

mkdir -p /state/plugins/spr-opencanary /etc/opencanaryd
exec /spr_opencanary_plugin
