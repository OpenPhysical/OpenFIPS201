#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$ROOT/tools/piv_test_runner/run-nist-harness.sh"
CARDS="$ROOT/test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects"
CONFIG="$ROOT/tools/piv_test_runner/config/OpenFIPS201.xml"
OUT="$ROOT/tools/piv_test_runner/piv_tests/data-model"
MODE=all
ICAM=""

usage() {
  echo "usage: $0 [--mode standard|fips|all] [--icam DIR] [--out DIR]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      MODE=$2
      shift 2
      ;;
    --icam)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      ICAM=$2
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      OUT=$2
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

case "$MODE" in
  standard|fips|all) ;;
  *) usage; exit 2 ;;
esac

STANDARD_CARDS=(
  01_Golden_PIV
  02_Golden_PIV-I
  37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64
  39_Golden_FIPS_201-2_Fed_PIV-I
  46_Golden_FIPS_201-2_PIV
  47_Golden_FIPS_201-2_PIV_SAN_Order
  54_Golden_FIPS_201-2_NFI_PIV-I
)

# These are the positive images whose algorithms and object policy can be
# provisioned by the FIPS build. The other positive images remain covered by
# the standard build instead of being silently treated as failed test cards.
FIPS_CARDS=(
  37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64
  46_Golden_FIPS_201-2_PIV
  47_Golden_FIPS_201-2_PIV_SAN_Order
)

SUITES=(
  CHECK_BER_TLV_conformance
  CHECK_certificate_profile
  CHECK_signed_data_elements
  CHECK_biometric_data
)

mkdir -p "$OUT"
SUMMARY="$OUT/summary.tsv"
printf 'mode\timage\tsuite\ttests\tfailures\tharness_exit\tresult\tlog\n' >"$SUMMARY"

total_tests=0
total_failures=0
infrastructure_failures=0

xml_count() {
  local attribute=$1
  local result=$2
  sed -n "s/.*${attribute}=\"\([0-9][0-9]*\)\".*/\1/p" "$result" | head -1
}

run_image() {
  local build_mode=$1
  local image=$2
  local image_dir=$3
  local suite destination log result status tests failures
  local fips_args=()

  if [[ "$build_mode" == fips ]]; then
    fips_args=(--fips)
  fi

  for suite in "${SUITES[@]}"; do
    destination="$OUT/$build_mode/$image/$suite"
    log="$OUT/$build_mode/$image/$suite.log"
    result="$destination/nist-results.xml"
    mkdir -p "$destination"

    echo "RUN $build_mode $image $suite"
    set +e
    "$HARNESS" "${fips_args[@]}" \
      --target emulator \
      --config "$CONFIG" \
      --icam "$image_dir" \
      --suite "$suite" \
      --out "$destination" >"$log" 2>&1
    status=$?
    set -e

    if [[ ! -f "$result" ]]; then
      printf '%s\t%s\t%s\t0\t0\t%s\t%s\t%s\n' \
        "$build_mode" "$image" "$suite" "$status" "MISSING_RESULT" "$log" >>"$SUMMARY"
      infrastructure_failures=$((infrastructure_failures + 1))
      continue
    fi

    tests="$(xml_count tests "$result")"
    failures="$(xml_count failures "$result")"
    [[ -n "$tests" ]] || tests=0
    [[ -n "$failures" ]] || failures=0
    total_tests=$((total_tests + tests))
    total_failures=$((total_failures + failures))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$build_mode" "$image" "$suite" "$tests" "$failures" "$status" "$result" "$log" >>"$SUMMARY"
  done
}

run_set() {
  local build_mode=$1
  shift
  local image
  for image in "$@"; do
    run_image "$build_mode" "$image" "$CARDS/$image"
  done
}

if [[ -n "$ICAM" ]]; then
  [[ -d "$ICAM" ]] || { echo "ICAM image not found: $ICAM" >&2; exit 2; }
  image_name="$(basename "$ICAM")"
  if [[ "$MODE" == all ]]; then
    run_image standard "$image_name" "$ICAM"
    run_image fips "$image_name" "$ICAM"
  else
    run_image "$MODE" "$image_name" "$ICAM"
  fi
else
  if [[ "$MODE" == standard || "$MODE" == all ]]; then
    run_set standard "${STANDARD_CARDS[@]}"
  fi
  if [[ "$MODE" == fips || "$MODE" == all ]]; then
    run_set fips "${FIPS_CARDS[@]}"
  fi
fi

echo "WROTE $SUMMARY"
echo "TOTAL tests=$total_tests failures=$total_failures infrastructure_failures=$infrastructure_failures"

if (( total_failures != 0 || infrastructure_failures != 0 )); then
  exit 1
fi
