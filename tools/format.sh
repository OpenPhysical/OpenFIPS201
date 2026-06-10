#!/bin/sh

echo Running Google Java Format
java -jar ./google-java-format-1.15.0-all-deps.jar -i \
  ../src/com/makina/security/openfips201/*.java \
  ../src/dev/mistial/tools/openfips201/attestation/*.java \
  ../src/dev/mistial/tool-tests/dev/mistial/tools/openfips201/attestation/*.java
