#!/bin/sh
set -eu
cd backend
if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed; CI runs it"; fi
cd ../frontend
npm audit --audit-level=high
cd ..
if command -v trivy >/dev/null 2>&1; then trivy fs --skip-dirs frontend/node_modules --skip-dirs frontend/dist --severity HIGH,CRITICAL --exit-code 1 .; else echo "trivy not installed; CI runs it"; fi
