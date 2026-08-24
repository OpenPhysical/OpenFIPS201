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

result_count() {
  local attribute=$1
  local result=$2
  sed -n "s/.*${attribute}=\"\([0-9][0-9]*\)\".*/\1/p" "$result" | head -n 1
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

assert_counts() {
  local result=$1
  local expected_tests=$2
  local expected_failures=$3
  local actual_tests actual_failures
  actual_tests="$(result_count tests "$result")"
  actual_failures="$(result_count failures "$result")"
  if [[ "$actual_tests" != "$expected_tests" || "$actual_failures" != "$expected_failures" ]]; then
    echo "unexpected JUnit counts in $result:" >&2
    echo "  expected tests=$expected_tests failures=$expected_failures" >&2
    echo "  actual tests=$actual_tests failures=$actual_failures" >&2
    return 1
  fi
}

assert_requirement_status() {
  local log=$1
  local requirement=$2
  local expected_status=$3
  local status_prefix=${4:-'Checking secure messaging status word: '}
  if ! awk \
    -v requirement="$requirement" \
    -v expected_status="$expected_status" \
    -v status_prefix="$status_prefix" '
    index($0, "Requirement ID: " requirement) { active = 1; next }
    active && index($0, "Requirement ID:") { exit }
    active && index($0, status_prefix expected_status) {
      found = 1
      exit
    }
    END { exit(found ? 0 : 1) }
  ' "$log"; then
    echo "expected protected status $expected_status for $requirement in $log" >&2
    return 1
  fi
}

assert_vci_clause_outcomes() {
  local log=$1
  local expected
  while IFS= read -r expected; do
    if ! grep -Fq "$expected" "$log"; then
      echo "missing required VCI clause evidence in $log:" >&2
      echo "  $expected" >&2
      return 1
    fi
  done <<'EOF'
C.2.2.4 - Step 3.1, Change PUK : false
C.2.2.4 - Step 3.2, Change PUK : false
C.2.2.4 - Step 3.3, Change PUK - incorrect length : false
C.3.1.4 - Put Data for CARD_CAPABILITY_CONTAINER - unauthenticated : false
C.3.1.4 - Put Data for CARD_HOLDER_FACIAL_IMAGE - unauthenticated : false
C.3.1.4 - Put Data for CARD_HOLDER_FINGERPRINTS - unauthenticated : false
C.3.1.4 - Put Data for CARD_HOLDER_UNIQUE_ID - unauthenticated : false
C.3.1.4 - Put Data for SECURITY_OBJECT - unauthenticated : false
C.3.1.4 - Put Data for DISCOVERY_OBJECT - unauthenticated : false
C.3.1.4 - Put Data for CARD_AUTHENTICATION - unauthenticated : false
C.3.1.4 - Put Data for DIGITAL_SIGNATURE - unauthenticated : false
C.3.1.4 - Put Data for KEY_MANAGEMENT - unauthenticated : false
C.3.1.4 - Put Data for PIV_AUTHENTICATION - unauthenticated : false
C.2.3.4 - Step 5 : false
EOF

  # SP 800-85A-4 C.2.2.4 requires each protected PUK attempt to fail. It does not
  # prescribe a status word. OpenFIPS201 documents 6A81 as its rejection status.
  assert_requirement_status "$log" 'C.2.2.4 - Step 3.1, Change PUK' 6a81
  assert_requirement_status "$log" 'C.2.2.4 - Step 3.2, Change PUK' 6a81
  assert_requirement_status "$log" 'C.2.2.4 - Step 3.3, Change PUK - incorrect length' 6a81

  # SP 800-85A-4 C.3.1.4 requires each PUT DATA attempt to "return an error status word."
  # SP 800-73-5 Part 2, Table 2 specifies 6A81 for a contactless command marked "No."
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for CARD_CAPABILITY_CONTAINER - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for CARD_HOLDER_FACIAL_IMAGE - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for CARD_HOLDER_FINGERPRINTS - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for CARD_HOLDER_UNIQUE_ID - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for SECURITY_OBJECT - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for DISCOVERY_OBJECT - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for CARD_AUTHENTICATION - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for DIGITAL_SIGNATURE - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for KEY_MANAGEMENT - unauthenticated' 6a81
  assert_requirement_status "$log" \
    'C.3.1.4 - Put Data for PIV_AUTHENTICATION - unauthenticated' 6a81
  assert_requirement_status "$log" 'C.2.3.4 - Step 5' 6a81
}

append_summary() {
  local suite=$1
  local interface=$2
  local runner_tests=$3
  local runner_failures=$4
  local assessed_accepted=$5
  local assessed_rejected=$6
  local basis=$7

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$suite" "$interface" "$runner_tests" "$runner_failures" \
    "$assessed_accepted" "$assessed_rejected" "$basis" >>"$SUMMARY"
}

SM_FAILURE=''
VC_FAILURES='ChangeReferenceDataCommand:4
PutDataCommand:4
ResetRetryCounterCommand:4'

SUMMARY="$OUT/summary.tsv"
printf 'suite\tinterface\trunner_tests\trunner_failures\tassessed_accepted\tassessed_rejected\tbasis\n' \
  >"$SUMMARY"

for suite in cs2 cs7; do
  run_suite "$suite" secure_messaging
  assert_counts "$OUT/$suite-secure_messaging/nist-results.xml" 7 0
  assert_failures "$OUT/$suite-secure_messaging/nist-results.xml" "$SM_FAILURE"
  append_summary "$suite" secure_messaging 7 0 7 0 direct

  run_suite "$suite" virtual_contact
  assert_counts "$OUT/$suite-virtual_contact/nist-results.xml" 7 3
  assert_failures "$OUT/$suite-virtual_contact/nist-results.xml" "$VC_FAILURES"
  assert_vci_clause_outcomes "$OUT/$suite-virtual_contact.log"
  append_summary "$suite" virtual_contact 7 3 7 0 clause-mapped
done

cat <<'EOF'
VCI clause assessment: CS2 14 accepted, CS7 14 accepted.

Runner XML for each cipher suite:

  * Secure messaging: 7 tests, 0 failures.
  * Virtual contact: 7 tests, 3 policy-rejection failures. The reported tests
    are ChangeReferenceDataCommand:4, PutDataCommand:4, and
    ResetRetryCounterCommand:4.

Controlling requirements:

  * SP 800-85A-4 C.2.2.4 requires the protected PUK attempts to fail.
    OpenFIPS201 returns 6A81; the assertion does not prescribe that status.
  * SP 800-85A-4 C.2.3.4 requires RESET RETRY COUNTER to return an error.
  * SP 800-85A-4 C.3.1.4 requires PUT DATA to return an error.
  * SP 800-73-5 Part 2, Table 2 specifies 6A81 for commands marked "No."

Specifications:
  https://doi.org/10.6028/NIST.SP.800-85A-4
  https://doi.org/10.6028/NIST.SP.800-73pt2-5

Test XML and logs are retained. See summary.tsv for both the runner counts and
the clause assessment.
EOF
