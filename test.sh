#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/5] Validating plugin manifest"
jq -e '
  .Name == "spr-opencanary" and
  .Runtime == "kvm" and
  .HasUI == true and .HasTopology == true and
  .NetworkCapabilities.Policies == ["lan", "wan", "dns"]
' plugin.json >/dev/null

echo "[2/5] Validating shell scripts"
bash -n install.sh build_docker_compose.sh test.sh scripts/startup.sh

echo "[3/5] Testing Go control plane"
(cd code && go test ./... && go vet ./...)

echo "[4/5] Building UI"
(cd frontend && \
  yarn install --frozen-lockfile --network-timeout 86400000 && \
  CI=true yarn test --watchAll=false --runInBand && \
  yarn bundle)

echo "[5/5] Validating Compose"
SUPERDIR=/tmp/spr-opencanary-test/ docker compose config --quiet
SUPERDIR=/tmp/spr-opencanary-test/ docker compose -f docker-compose-kvm.yml config --quiet

echo "All checks passed."
