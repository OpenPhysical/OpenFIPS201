#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="$ROOT/tools/piv_test_runner/local/install"
NIST_JARS="$INSTALL_DIR/TestRunnerFiles/jars"
HARNESS_SRC="$ROOT/src/dev/mistial/tools/openfips201/nist"
HARNESS_CLASSES="$ROOT/tools/piv_test_runner/local/harness/classes"
JCARD_JAR="$ROOT/tools/jcard-v26.07.13.jar"
JC_API_JAR="$ROOT/tools/sdk/jc310/lib/api_classic-3.0.5.jar"

if [[ ! -d "$NIST_JARS" ]]; then
  echo "NIST Test Runner is not installed. Run tools/piv_test_runner/setup-nist-tester.sh first." >&2
  exit 1
fi

if [[ ! -f "$JCARD_JAR" ]]; then
  echo "jCard engine jar not found: $JCARD_JAR" >&2
  exit 1
fi

# Compile the requested applet profile and shared test classes into build/test-bin.
fips_mode=false
for argument in "$@"; do
  if [ "$argument" = "--fips" ]; then
    fips_mode=true
  fi
done
if [ "$fips_mode" = true ]; then
  sh "$ROOT/tools/ant/bin/ant" -f "$ROOT/build/build.xml" \
    -Dfips.mode=true -Dfips.platform=test-jcard test-compile >/dev/null
else
  sh "$ROOT/tools/ant/bin/ant" -f "$ROOT/build/build.xml" test-compile >/dev/null
fi

mkdir -p "$HARNESS_CLASSES"

# Runtime classpath mirrors build.xml test.runtime.classpath:
# - preprocessed applet + test support classes
# - tool-bin host utilities (if present)
# - jcard-v fat jar (JavaCardEngine, apdu4j, capfile, GP runtime)
# - Ivy test deps
# - NIST Test Runner jars
#
# Do NOT put the GP export stub jar (tools/sdk/gp211/*.jar) on the runtime
# classpath; it shadows jCard's functional org.globalplatform implementation.
CP="$ROOT/build/test-bin"
if [[ -d "$ROOT/build/tool-bin" ]]; then
  CP="$CP:$ROOT/build/tool-bin"
fi
CP="$CP:$JCARD_JAR"
CP="$CP:$ROOT/build/lib/*"
CP="$CP:$NIST_JARS/*"

# Compile-time only: classic JC API for harness sources that reference AID, etc.
COMPILE_CP="$CP:$JC_API_JAR"

javac -source 8 -target 8 -Xlint:-options -encoding UTF-8 -cp "$COMPILE_CP" -d "$HARNESS_CLASSES" \
  $(find "$HARNESS_SRC" -name '*.java' | sort)

java -cp "$HARNESS_CLASSES:$CP" dev.mistial.tools.openfips201.nist.NistHarnessMain "$@"
