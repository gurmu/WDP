#!/usr/bin/env bash
# Install the tracked hooks into .git/hooks/.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
install -m 0755 "$repo/scripts/hooks/pre-commit" "$repo/.git/hooks/pre-commit"
echo "installed: .git/hooks/pre-commit"
