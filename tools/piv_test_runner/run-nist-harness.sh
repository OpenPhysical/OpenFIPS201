#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_DIR="$ROOT/tools/piv_test_runner/local/install"
NIST_JARS="$INSTALL_DIR/TestRunnerFiles/jars"
HARNESS_SRC="$ROOT/src/dev/mistial/tools/openfips201/nist"
HARNESS_CLASSES="$ROOT/tools/piv_test_runner/local/harness/classes"
NIST_COMPAT_JAR="$ROOT/tools/piv_test_runner/local/harness/nist-bc-compat.jar"
JCARD_JAR="$ROOT/tools/jcard-v26.08.10.jar"
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
vci_suite=CS2
previous=""
for argument in "$@"; do
  if [ "$argument" = "--fips" ]; then
    fips_mode=true
  elif [ "$previous" = "--vci" ]; then
    vci_suite="${argument^^}"
  fi
  previous="$argument"
done
if [ "$fips_mode" = true ]; then
  sh "$ROOT/tools/ant/bin/ant" -f "$ROOT/build/build.xml" \
    -Dfips.mode=true -Dfips.platform=test-jcard -Dvci.suite="$vci_suite" test-compile >/dev/null
else
  sh "$ROOT/tools/ant/bin/ant" -f "$ROOT/build/build.xml" \
    -Dvci.suite="$vci_suite" test-compile >/dev/null
fi

mkdir -p "$HARNESS_CLASSES"

# Runtime classpath mirrors build.xml test.runtime.classpath:
# - preprocessed applet + test support classes
# - tool-bin host utilities (if present)
# - jcard-v fat jar (JavaCardEngine, apdu4j, capfile, GP runtime)
# - NIST Test Runner jars
# - Ivy test deps not already supplied by NIST
#
# Do NOT put the GP export stub jar (tools/sdk/gp221/*.jar) on the runtime
# classpath; it shadows jCard's functional org.globalplatform implementation.
CP="$ROOT/build/test-bin"
if [[ -d "$ROOT/build/tool-bin" ]]; then
  CP="$CP:$ROOT/build/tool-bin"
fi
CP="$CP:$JCARD_JAR"
CP="$CP:$NIST_JARS/*"
CP="$CP:$ROOT/build/lib/*"

# Compile-time only: classic JC API for harness sources that reference AID, etc.
COMPILE_CP="$CP:$JC_API_JAR"

javac -source 8 -target 8 -Xlint:-options -encoding UTF-8 -cp "$COMPILE_CP" -d "$HARNESS_CLASSES" \
  $(find "$HARNESS_SRC" -name '*.java' | sort)

# NIST 5.0.1 calls a BouncyCastle 1.56 method removed by the current emulator dependency.
# Build a class-only overlay instead of loading two incompatible signed BC packages.
java -cp "$HARNESS_CLASSES:$CP" \
  dev.mistial.tools.openfips201.nist.NistCompatibilityPatcher \
  "$NIST_JARS/PIV_TestRunner_modules-5.0.1.jar" "$NIST_COMPAT_JAR"

java -cp "$NIST_COMPAT_JAR:$HARNESS_CLASSES:$CP" \
  dev.mistial.tools.openfips201.nist.NistHarnessMain "$@"
