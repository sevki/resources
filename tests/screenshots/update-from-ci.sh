#!/bin/bash
#
# Replaces the golden images with the screenshots a CI run produced.
#
# The goldens are meant to match what the GitHub runner renders (text
# rasterization differs slightly between machines), so after an intentional
# UI change take them from CI instead of from `run.sh --update`:
#
#   tests/screenshots/update-from-ci.sh <run id>      # needs the gh CLI
#
# The run id is in the URL of the workflow run. The screenshots job uploads
# its screenshots even when the comparison fails.
set -euo pipefail

run="${1:?usage: $0 <workflow run id>}"
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gh run download "$run" --name screenshots --dir "$tmp"
for golden in "$here"/golden/*.png; do
    name="$(basename "$golden")"
    [[ -f "$tmp/$name" ]] || { echo "run has no $name" >&2; exit 1; }
    cp "$tmp/$name" "$golden"
    echo "updated $name"
done
