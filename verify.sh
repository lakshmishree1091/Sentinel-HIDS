#!/usr/bin/env bash
# verify.sh — check the tamper-evidence of the findings log.
#   ./verify.sh
# Exit 0 = intact, 1 = tampered, 2 = no log.
set -uo pipefail
HIDS_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export HIDS_HOME
source "$HIDS_HOME/lib/core.sh"
hids::init || exit 1
hids::load_config
hids::verify_chain