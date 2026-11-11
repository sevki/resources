#!/bin/bash
#
# CI helper: lets Resources build against the libadwaita 1.5 shipped by
# Ubuntu 24.04 so that unit tests and screenshot tests can run on plain
# GitHub runners. The code itself uses no API newer than 1.5; the official
# (Flatpak) build keeps the real libadwaita 1.8 requirement.
#
# This edits Cargo.toml and meson.build in the working tree. Never commit
# the result.
set -euo pipefail
cd "$(dirname "$0")/.."

sed -i 's/features = \["v1_8"\]/features = ["v1_5"]/' Cargo.toml
sed -i "s/version: '>= 1.8.0'/version: '>= 1.5.0'/" meson.build
grep -q 'v1_5' Cargo.toml && grep -q ">= 1.5.0" meson.build
