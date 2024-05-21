#!/bin/bash
set -euxo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/ext/"
VERSION="$(jq '.version' -r < manifest.json)"
DATE="$(date '+%Y-%m-%dT%H%M%S')"
NAME="verifyct_${VERSION}_${DATE}"
zip -r "../build/${NAME}.xpi" .