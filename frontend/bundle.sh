#!/bin/bash
set -euo pipefail
GENERATE_SOURCEMAP=false npx craco build

OUTFILE=build/index.html
sed 's/<\/head><body>.*//g; s/.*<head><script>/<script>/g' build/index.html > build/script.html
printf '%s\n' '<!doctype html><html lang="en"><head></head>' > "$OUTFILE"
printf '%s\n' '<body><noscript>You need JavaScript enabled to manage OpenCanary.</noscript><div id="root"></div></body>' >> "$OUTFILE"
sed -n '1,$p' build/script.html >> "$OUTFILE"
printf '%s\n' '</html>' >> "$OUTFILE"
rm -f build/script.html
