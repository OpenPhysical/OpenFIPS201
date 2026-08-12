#!/usr/bin/env bash
# Install (if needed) and provision an OpenFIPS201 ZMQ emulator from a GSA ICAM card folder.
#
# Usage:
#   tools/provision-icam.sh /path/to/46_Golden_FIPS_201-2_PIV
#   tools/provision-icam.sh /path/to/46_Golden_FIPS_201-2_PIV zmq:tcp://127.0.0.1:5555
#   CAP=build/matrix/standard-CS2-attestation/bin/OpenFIPS201-....cap tools/provision-icam.sh ...
#
# Prerequisites:
#   - ant -f build/build.xml tool-compile
#   - emulator already serving:
#       java -cp "build/tool-bin:tools/jcard-v26.08.10.jar:build/lib/*" \
#         dev.mistial.tools.openfips201.OpenFips201Tool emulator serve
#
# The jCardEngine emulator registers the applet class but does not make it selectable until a GP
# INSTALL (for install and make selectable). This script performs that install with --skip-load
# (no CAP transfer) when a CAP path is available for metadata, then loads ICAM content over SCP03.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ICAM_DIR="${1:-}"
TARGET="${2:-zmq:tcp://127.0.0.1:5555}"
SCP_KEY="${SCP_KEY:-404142434445464748494A4B4C4D4E4F}"

if [[ -z "${ICAM_DIR}" ]]; then
  cat <<EOF
Usage: $0 <icam-card-folder> [target]

  icam-card-folder  Path to a GSA ICAM card-builder directory, e.g.
                    .../ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV
  target            zmq:tcp://host:port (default) or pcsc:<reader>

Environment:
  CAP       Path to OpenFIPS201 .cap (used for GP install metadata; default: newest under build/)
  SCP_KEY   SCP03 master key hex (default: GlobalPlatform test key)
  SKIP_INSTALL=1  Skip the applet install step
EOF
  exit 2
fi

if [[ ! -d "${ICAM_DIR}" ]]; then
  echo "ICAM folder not found: ${ICAM_DIR}" >&2
  exit 1
fi

CP="${ROOT}/build/tool-bin:${ROOT}/tools/jcard-v26.08.10.jar"
if [[ -d "${ROOT}/build/lib" ]]; then
  for jar in "${ROOT}/build/lib"/*.jar; do
    CP="${CP}:${jar}"
  done
fi

if [[ ! -d "${ROOT}/build/tool-bin" ]]; then
  echo "tool-bin missing; run: ant -f build/build.xml tool-compile" >&2
  exit 1
fi

TOOL=(java -cp "${CP}" dev.mistial.tools.openfips201.OpenFips201Tool)

if [[ "${SKIP_INSTALL:-0}" != "1" ]]; then
  if [[ -z "${CAP:-}" ]]; then
    CAP="$(find "${ROOT}/build" -name 'OpenFIPS201-*.cap' 2>/dev/null | head -1 || true)"
  fi
  if [[ -n "${CAP}" && -f "${CAP}" ]]; then
    echo "Installing applet (skip-load) from ${CAP} onto ${TARGET}..."
    "${TOOL[@]}" applet install \
      --cap "${CAP}" \
      --skip-load \
      --target "${TARGET}" \
      --scp-key "${SCP_KEY}" || {
        echo "Note: install failed (applet may already be installed); continuing to provision." >&2
      }
  else
    echo "No CAP found; skipping install. Set CAP=... if the applet is not yet selectable." >&2
  fi
fi

echo "Provisioning ICAM folder ${ICAM_DIR} onto ${TARGET}..."
exec "${TOOL[@]}" provision \
  --icam "${ICAM_DIR}" \
  --target "${TARGET}" \
  --scp-key "${SCP_KEY}"
