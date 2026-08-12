#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE_NAME="install_SP800_73_4_tester_5.0.1_20200212-0308_enc.zip"
ARCHIVE_URL="https://csrc.nist.gov/CSRC/media/Projects/NIST-Personal-Identity-Verification-Program/documents/${ARCHIVE_NAME}"
LOCAL_DIR="${SCRIPT_DIR}/local"
DOWNLOAD_DIR="${LOCAL_DIR}/downloads"
RUNNER_DIR="${LOCAL_DIR}/runner"
INSTALL_DIR="${LOCAL_DIR}/install"
ARCHIVE_PATH="${DOWNLOAD_DIR}/${ARCHIVE_NAME}"
INNER_ZIP="${RUNNER_DIR}/install_SP800_73_4_tester_5.0.1_20200212-0308.zip"
INSTALL_JAR="${RUNNER_DIR}/install_SP800_73_4_tester.jar"
INSTALL_OPTIONS="${RUNNER_DIR}/install-options.properties"
RUNNER_MAIN_JAR="${INSTALL_DIR}/TestRunnerFiles/jars/TestRunner-5.0.1.jar"

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required tool not found: $1" >&2
    exit 1
  fi
}

need_tool curl
need_tool java
need_tool unzip

mkdir -p "${DOWNLOAD_DIR}" "${RUNNER_DIR}" "${INSTALL_DIR}"

if [ ! -s "${ARCHIVE_PATH}" ]; then
  echo "Downloading NIST PIV Test Runner archive:"
  echo "  ${ARCHIVE_URL}"
  curl --fail --location --output "${ARCHIVE_PATH}" "${ARCHIVE_URL}"
else
  echo "Using existing archive:"
  echo "  ${ARCHIVE_PATH}"
fi

if [ ! -s "${INNER_ZIP}" ]; then
  if [ ! -t 0 ]; then
    echo "error: extraction requires an interactive terminal for the NIST archive password" >&2
    echo "The password is intentionally not stored in this repository or passed on the command line." >&2
    exit 1
  fi

  echo "Extracting encrypted archive into:"
  echo "  ${RUNNER_DIR}"
  echo "When prompted, enter the NIST-provided archive password."
  unzip "${ARCHIVE_PATH}" -d "${RUNNER_DIR}"
else
  echo "Using existing extracted package:"
  echo "  ${INNER_ZIP}"
fi

if [ ! -s "${INSTALL_JAR}" ]; then
  echo "Extracting installer jar:"
  echo "  ${INSTALL_JAR}"
  unzip -n "${INNER_ZIP}" -d "${RUNNER_DIR}"
else
  echo "Using existing installer jar:"
  echo "  ${INSTALL_JAR}"
fi

if [ ! -s "${RUNNER_MAIN_JAR}" ]; then
  cat > "${INSTALL_OPTIONS}" <<EOF
#PIV Test Runner 5.0.1 - 20200212-0308

#TargetPanel_3
INSTALL_PATH=${INSTALL_DIR}
EOF

  echo "Installing NIST PIV Test Runner into:"
  echo "  ${INSTALL_DIR}"
  java -jar "${INSTALL_JAR}" -options "${INSTALL_OPTIONS}"
else
  echo "NIST PIV Test Runner is already installed:"
  echo "  ${INSTALL_DIR}"
fi

echo "Done. The runner files are local-only and ignored by git."
