#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="$ROOT/tools/piv_test_runner/local/install"
NIST_JARS="$INSTALL_DIR/TestRunnerFiles/jars"
HARNESS_SRC="$ROOT/src/dev/mistial/tools/openfips201/nist"
HARNESS_CLASSES="$ROOT/tools/piv_test_runner/local/harness/classes"

if [[ ! -d "$NIST_JARS" ]]; then
  echo "NIST Test Runner is not installed. Run tools/piv_test_runner/setup-nist-tester.sh first." >&2
  exit 1
fi

sh "$ROOT/tools/ant/bin/ant" -f "$ROOT/build/build.xml" test-compile >/dev/null

mkdir -p "$HARNESS_CLASSES"

CP="$ROOT/build/test-bin"
CP="$CP:$ROOT/tools/sdk/gp211/gp211.jar"
CP="$CP:$ROOT/tools/jcardengine-26.06.04.jar"
CP="$CP:$ROOT/tools/globalplatformpro-26.06.04.jar"
CP="$CP:$ROOT/tools/apdu4j-core-26.06.04.jar"
CP="$CP:$ROOT/tools/capfile-26.05.15.jar"
CP="$CP:$ROOT/tools/tlv-26.06.04.jar"
CP="$CP:$ROOT/build/lib/*"
CP="$CP:$NIST_JARS/*"
COMPILE_CP="$CP:$ROOT/tools/sdk/jc310/lib/api_classic-3.0.5.jar"

javac -source 8 -target 8 -Xlint:-options -encoding UTF-8 -cp "$COMPILE_CP" -d "$HARNESS_CLASSES" \
  $(find "$HARNESS_SRC" -name '*.java' | sort)

java -cp "$HARNESS_CLASSES:$CP" dev.mistial.tools.openfips201.nist.NistHarnessMain "$@"
