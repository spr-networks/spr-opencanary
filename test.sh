#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/6] Validating plugin manifest"
jq -e '
  .Name == "spr-opencanary" and
  .Runtime == "kvm" and
  .HasUI == true and .HasTopology == true and
  .NetworkCapabilities.Interface == "spr-opencanary" and
  .NetworkCapabilities.DeviceMAC == "02:53:50:52:4b:0d" and
  .NetworkCapabilities.Policies == ["wan", "dns"]
' plugin.json >/dev/null

echo "[2/6] Validating shell scripts"
bash -n build_docker_compose.sh test.sh scripts/startup.sh

echo "[3/6] Testing Go control plane"
(cd code && go test ./... && go vet ./...)

echo "[4/6] Testing webhook filtering"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[5/6] Building UI"
(cd frontend && \
  yarn install --frozen-lockfile --network-timeout 86400000 && \
  CI=true yarn test --watchAll=false --runInBand && \
  yarn bundle)

echo "[6/6] Validating Compose"
SUPERDIR=/tmp/spr-opencanary-test/ docker compose config --quiet
SUPERDIR=/tmp/spr-opencanary-test/ docker compose -f docker-compose-kvm.yml config --quiet
if SUPERDIR=/tmp/spr-opencanary-test/ docker compose -f docker-compose-kvm.yml config --format json | grep -q 'krun.net_mac'; then
  echo "KVM Compose must not assign the manager-owned device MAC" >&2
  exit 1
fi

echo "All checks passed."
