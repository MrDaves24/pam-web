#!/bin/sh
# Browser e2e : web/e2e/browser.mjs drives the page in headless Chrome (virtual authenticator) and pamtester, against
# the dev server. As root in mcr.microsoft.com/playwright:v1.63.0-noble (the same version as web/package.json's
# playwright), from the repo root, with web/node_modules installed and pam_web.so built (CI : by scripts/e2e.sh).
# Locally :
#   (cd web && __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=host.docker.internal npx react-router dev --host --port 5199) &
#   docker run --rm -v "$PWD:/src" -w /src/pam rust:1.98-bookworm sh -c \
#     'apt-get update -qq && apt-get install -qq -y libpam0g-dev > /dev/null && CARGO_TARGET_DIR=target/linux cargo build --release'
#   docker run --rm -v "$PWD:/src:ro" -w /src -e SERVER=http://host.docker.internal:5199 \
#     -e CARGO_TARGET_DIR=pam/target/linux mcr.microsoft.com/playwright:v1.63.0-noble scripts/e2e-browser.sh
set -eu
SERVER=${SERVER:-http://localhost:5199}

apt-get update -qq && apt-get install -qq -y pamtester > /dev/null
cp "${CARGO_TARGET_DIR:-pam/target}/release/libpam.so" /tmp/pam_web.so
# localhost : web/e2e/browser.mjs forwards it to $SERVER (WebAuthn needs a secure context)
echo "auth required /tmp/pam_web.so http://localhost:5199/api/authorization/request" > /etc/pam.d/pamweb
# The config is written by the test : the page's own block, with the passkey it registers
mkdir -p /etc/pam_web

i=0
until curl -fs "$SERVER/api/health" > /dev/null 2>&1 || node -e "fetch('$SERVER/api/health').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"; do
  i=$((i + 1))
  [ $i -lt 120 ] || { echo "FAIL : server not reachable at $SERVER"; exit 1; }
  sleep 1
done

SERVER=$SERVER node web/e2e/browser.mjs
