#!/bin/sh
# End-to-end : the real pam_web.so in libpam (pamtester), against the dev server
# (in DEV every cookie is the test user). The browser is played with curl, the
# passkey with openssl. As root in a Debian container, from the repo root.
# Locally :
#   (cd web && __VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=host.docker.internal npx react-router dev --host --port 5199) &
#   docker run --rm -v "$PWD:/src:ro" -w /src -e SERVER=http://host.docker.internal:5199 \
#     -e CARGO_TARGET_DIR=/tmp/target rust:1.98-bookworm scripts/e2e.sh
set -eu
SERVER=${SERVER:-http://localhost:5199}
API=$SERVER/api/authorization
# The dev user and its request token (web/app/helpers/user.server.ts : the dev key is "dev")
USER_LINE="user dev $(printf dev | openssl dgst -sha256 -hmac dev | cut -d' ' -f2)"
# The passkeys' site : the PAM URL's host and origin
RP_ID=$(echo "$SERVER" | sed -E 's#^[a-z]+://([^:/]+).*#\1#')
ORIGIN=$SERVER

fail() {
  echo "FAIL : $*"
  exit 1
}

apt-get update -qq && apt-get install -qq -y libpam0g-dev pamtester curl jq > /dev/null
(cd pam && cargo build -q --release)
cp "${CARGO_TARGET_DIR:-pam/target}/release/libpam.so" /tmp/pam_web.so

# pam_web decides, except when it ignores (not enrolled) : then pam_permit
cat > /etc/pam.d/pamweb << PAM
auth [success=done ignore=ignore default=die] /tmp/pam_web.so $API/request
auth required pam_permit.so
PAM

# The passkey, and another one nobody enrolled
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/passkey.pem 2> /dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /tmp/other.pem 2> /dev/null
KEY="key es256 $(openssl pkey -in /tmp/passkey.pem -pubout -outform DER | openssl base64 -A) test key"
config() {
  printf '%s\n' "${USER_LINE:?}" "$@" > /etc/pam_web/root
  chmod 600 /etc/pam_web/root
}
mkdir -p /etc/pam_web
config "$KEY"

i=0
until curl -fs "$SERVER/api/health" > /dev/null; do
  i=$((i + 1))
  [ $i -lt 120 ] || fail "server not reachable at $SERVER"
  sleep 1
done

browser() { curl -fs -H 'Cookie: user=x' -H 'Content-Type: application/json' "$@"; }
# known=x never matches : answers right away with the pending requests
pending() { browser "$API/list?known=x" | jq length; }

b64() { openssl base64 -A; }
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# assertion KEY CODE [RP_ID [FLAGS]] : what the browser sends for $raw. FLAGS 5 =
# user present + verified.
assertion() {
  printf '%s\n%s\nallow' "$raw" "$2" | openssl dgst -sha256 -binary | b64url > /tmp/challenge
  printf '{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}' \
    "$(cat /tmp/challenge)" "$ORIGIN" > /tmp/client
  {
    printf '%s' "${3:-$RP_ID}" | openssl dgst -sha256 -binary
    printf "\\$(printf '%03o' "${4:-5}")\\000\\000\\000\\000"
  } > /tmp/authenticator
  {
    cat /tmp/authenticator
    openssl dgst -sha256 -binary /tmp/client
  } | openssl dgst -sha256 -sign "$1" > /tmp/signature
  printf '{"authenticator_data":"%s","client_data_json":"%s","signature":"%s"}' \
    "$(b64 < /tmp/authenticator)" "$(b64 < /tmp/client)" "$(b64 < /tmp/signature)"
}

# start USER : pamtester in the background, until its request reaches the
# browser. Sets $raw, $challenge, $code (read in the terminal) and $typed.
start() {
  stdbuf -oL pamtester pamweb "$1" authenticate > /tmp/out 2>&1 &
  pid=$!
  i=0
  until [ "$(pending)" -gt 0 ] && grep -qE 'code [0-9]{6}' /tmp/out; do
    i=$((i + 1))
    [ $i -lt 50 ] || fail "no request reached the browser : $(cat /tmp/out)"
    sleep 0.2
  done
  raw=$(browser "$API/list?known=x" | jq -r '.[0].raw')
  challenge=$(browser "$API/list?known=x" | jq -r '.[0].challenge')
  code=$(grep -oE 'code [0-9]{6}' /tmp/out | cut -d' ' -f2)
  if echo "$raw" | jq -e 'has("code")' > /dev/null; then
    typed=false
    [ "$(echo "$raw" | jq -r .code)" = "$code" ] || fail "terminal and browser codes differ"
  else
    typed=true
  fi
}
approve() { browser -X POST "$API/authorize/$challenge" -d "$1" > /dev/null; }
block() { browser -X POST "$API/block/$challenge" > /dev/null; }
# finish : pamtester's status
finish() {
  status=0
  wait $pid || status=$?
  return $status
}

# none USER : no request may reach the browser. pamtester's status.
none() {
  status=0
  pamtester pamweb "$1" authenticate > /tmp/out 2>&1 || status=$?
  [ "$(pending)" = 0 ] || fail "unexpected request"
  return $status
}

echo "--- approved, in both modes (typed : 1 in 3, random)"
shown=0 typed_seen=0 i=0
while [ $shown = 0 ] || [ $typed_seen = 0 ]; do
  i=$((i + 1))
  [ $i -le 40 ] || fail "only one mode in 40 requests"
  start root
  if $typed; then typed_seen=1; else shown=1; fi
  approve "$(assertion /tmp/passkey.pem "$code")"
  finish || fail "approved request rejected (typed : $typed) : $(cat /tmp/out)"
done
echo "$raw" | jq -e '.pam_user == "root" and .service == "pamweb" and .uid == 0 and .cmdline[0] == "pamtester"' > /dev/null ||
  fail "wrong context : $raw"

echo "--- wrong typed code"
i=0
while :; do
  i=$((i + 1))
  [ $i -le 40 ] || fail "no typed mode in 40 requests"
  start root
  $typed && break
  block
  finish || true
done
approve "$(assertion /tmp/passkey.pem "$(printf '%06d' $(((code + 1) % 1000000)))")"
! finish || fail "wrong typed code accepted"

echo "--- not enrolled passkey"
start root
approve "$(assertion /tmp/other.pem "$code")"
! finish || fail "other passkey accepted"

echo "--- signed for another site"
start root
approve "$(assertion /tmp/passkey.pem "$code" evil.example)"
! finish || fail "other site accepted"

echo "--- user not verified"
start root
approve "$(assertion /tmp/passkey.pem "$code" "$RP_ID" 1)"
! finish || fail "unverified user accepted"

echo "--- blocked"
start root
block
! finish || fail "blocked request accepted"

echo "--- not enrolled : ignored, the rest of the stack decides"
none nobody || fail "not enrolled user not ignored"

echo "--- wrong request token"
GOOD_LINE=$USER_LINE
USER_LINE="user dev $(printf other | openssl dgst -sha256 -hmac dev | cut -d' ' -f2)"
config "$KEY"
! none root || fail "wrong token accepted"
USER_LINE=$GOOD_LINE

echo "--- no key line"
config
! none root || fail "config without keys accepted"

echo "--- config readable by others"
config "$KEY"
chmod 644 /etc/pam_web/root
! none root || fail "insecure config accepted"

echo "--- invalid key"
config "key es256 AAAA"
! none root || fail "invalid key accepted"

echo "--- invalid config"
config "$KEY" "foo bar"
! none root || fail "invalid config accepted"

echo "OK"
