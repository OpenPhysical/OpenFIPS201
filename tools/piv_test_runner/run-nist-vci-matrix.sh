#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$ROOT/tools/piv_test_runner/run-nist-harness.sh"
ICAM="$ROOT/test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV"
CONFIG="$ROOT/tools/piv_test_runner/config/OpenFIPS201.xml"
OUT="$ROOT/tools/piv_test_runner/piv_tests/vci-matrix"

if [[ ${1:-} == "--out" ]]; then
  [[ $# -eq 2 ]] || { echo "usage: $0 [--out DIR]" >&2; exit 2; }
  OUT=$2
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--out DIR]" >&2
  exit 2
fi

mkdir -p "$OUT"

run_suite() {
  local suite=$1
  local interface=$2
  local destination="$OUT/$suite-$interface"
  local log="$OUT/$suite-$interface.log"

  set +e
  "$HARNESS" \
    --fips \
    --config "$CONFIG" \
    --icam "$ICAM" \
    --provision \
    --vci "$suite" \
    --pairing-code 12345678 \
    --suite "card-$interface" \
    --out "$destination" >"$log" 2>&1
  local status=$?
  set -e

  [[ -f "$destination/nist-results.xml" ]] || {
    echo "$suite $interface did not produce nist-results.xml (exit $status)" >&2
    return 1
  }
}

failure_names() {
  sed -n 's/.*name="\([^"]*\)"><failure.*/\1/p' "$1" | LC_ALL=C sort
}

assert_failures() {
  local result=$1
  local expected=$2
  local actual
  actual="$(failure_names "$result")"
  if [[ "$actual" != "$expected" ]]; then
    echo "unexpected NIST classification in $result" >&2
    echo "expected failures:" >&2
    printf '%s\n' "$expected" >&2
    echo "actual failures:" >&2
    printf '%s\n' "$actual" >&2
    return 1
  fi
}

SM_FAILURE='GeneralAuthenticateCommand:3'
VC_FAILURES='ChangeReferenceDataCommand:4
GeneralAuthenticateCommand:4
PutDataCommand:4
ResetRetryCounterCommand:4'

for suite in cs2 cs7; do
  run_suite "$suite" secure_messaging
  assert_failures "$OUT/$suite-secure_messaging/nist-results.xml" "$SM_FAILURE"

  run_suite "$suite" virtual_contact
  assert_failures "$OUT/$suite-virtual_contact/nist-results.xml" "$VC_FAILURES"
done

echo "NIST VCI matrix matches the reviewed CS2/CS7 classification."
