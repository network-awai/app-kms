#!/usr/bin/env bash
# JUN-1321: same steps as .github/workflows/ci.yml (job `test`), runnable by hand so the
# check does not depend on GitHub Actions. Needs node 22+ and npm.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../worker"
npm ci
npm run typecheck
npm test
echo "app-kms ci check passed"
