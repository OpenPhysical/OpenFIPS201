#!/bin/sh
set -eu

export LC_ALL=C
repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$repository/test-vectors/sp800-85b-personalization"
output_dir=${1:-"$repository/build/sp800-85b-personalization"}

mkdir -p "$output_dir"
sort "$source_dir/golden-input.properties" > "$output_dir/golden-input.properties"
cp "$source_dir/dmt-operator-manifest.tsv" "$output_dir/dmt-operator-manifest.tsv"

(
  cd "$output_dir"
  shasum -a 256 golden-input.properties dmt-operator-manifest.tsv > SHA256SUMS
)

printf '%s\n' "$output_dir"
