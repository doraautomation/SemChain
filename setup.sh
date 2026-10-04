#!/usr/bin/env bash
# One-time setup. Run from anywhere: bash scripts/setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

pip install -r requirements.txt

# Python used to build the BugsInPy test environments
uv python install 3.8

# BugsInPy metadata (bug.info, requirements.txt, run_test.sh for every bug)
if [ ! -d BugsInPy ]; then
    git clone https://github.com/soarsmu/BugsInPy.git BugsInPy
fi

echo "Setup done. Project clones and test environments are created on the first run."
