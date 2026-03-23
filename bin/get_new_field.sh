#!/bin/bash

# shellcheck disable=2154

. lib/env.sh

log "get_new_field"

# Perform operation and sync vault
function mkchange() {
    URL="${API}"/object/item/"${objectId}"

    if [ "${op}" == "remove" ]; then
	# Remove item
	curl -s "${URL}" \
	    | jq ".data | del(${jqItem})" \
	    | curl -s -H 'Content-Type: application/json' -T - "${URL}" \
	    | jq .success
    else
	# Update item
	curl -s "${URL}" \
	    | jq ".data | ${jqItem} |= \"$(cut -d: -f3 <<< "${new}")\"" \
	    | curl -s -H 'Content-Type: application/json' -T - "${URL}" \
	    | jq .success
    fi

    saveSync
}

# First dialog: prompt for new value or removal.
# All dynamic values (prompt text, field name) are passed as positional
# arguments to an AppleScript 'on run' handler — never interpolated into
# the script body — so a double-quote in either value cannot inject code.
function mkscript1() {
    local prompt="${1}"
    if [ "${editField}" == "password" ]; then
	new=$(2>&- osascript \
	    -e 'on run {prompt, field}' \
	    -e '  set dlg to display dialog prompt buttons {"OK", "Remove " & field, "Cancel"} default button "OK" default answer "" with title ("Change " & field) with hidden answer' \
	    -e '  return (button returned of dlg) & ":" & (text returned of dlg)' \
	    -e 'end run' \
	    -- "${prompt}" "${editField}")
    else
	new=$(2>&- osascript \
	    -e 'on run {prompt, field}' \
	    -e '  set dlg to display dialog prompt buttons {"OK", "Remove " & field, "Cancel"} default button "OK" default answer "" with title ("Change " & field)' \
	    -e '  return (button returned of dlg) & ":" & (text returned of dlg)' \
	    -e 'end run' \
	    -- "${prompt}" "${editField}")
    fi
}

# Second dialog: confirm field removal.
function mkscript2() {
    local prompt="${1}"
    yorn=$(2>&- osascript \
	-e 'on run {prompt, field}' \
	-e '  return button returned of (display dialog prompt buttons {"Cancel", "OK"} default button "Cancel" with title ("Remove " & field) with icon caution)' \
	-e 'end run' \
	-- "${prompt}" "${editField}")
}

# Third dialog: confirm new password entry.
function mkscript3() {
    local prompt="${1}"
    again=$(2>&- osascript \
	-e 'on run {prompt, field}' \
	-e '  set dlg to display dialog prompt buttons {"OK", "Cancel"} default button "OK" default answer "" with title ("Change " & field) with hidden answer' \
	-e '  return (button returned of dlg) & ":" & (text returned of dlg)' \
	-e 'end run' \
	-- "${prompt}" "${editField}")
}

# Get item path to edit
case "${editField}" in
    "username")
	jqItem=".login.username"
	;;
    "password")
	jqItem=".login.password"
	;;
    "generate")
	jqItem=".login.password"
	new="$(./bin/generate_password.sh)"
	mkchange
	exit 0
	;;
    "TOTP")
	jqItem=".login.totp"
	;;
    "name")
	jqItem=".name"
	;;
    *)
	osascript \
	    -e 'on run {f}' \
	    -e '  display notification ("Unknown field: " & f)' \
	    -e 'end run' \
	    -- "${editField}"
	exit 0
esac

# Prompt for new value (mkscript1 sets ${new} directly)
mkscript1 "Enter new ${editField}:"

# Exit if canceled or no entry
[ "${new}" == "" ] && exit 0
[ "${new}" == "button returned:OK, text returned:" ] && exit 0

# Confirm removal (mkscript2 sets ${yorn} directly)
if [[ "${new}" =~ "button returned:Remove" ]]; then
    mkscript2 "Are you sure you want to remove ${editField}?"

    # Exit if canceled
    [ "${yorn}" != "button returned:OK" ] && exit 0

    op="remove"
fi

# Confirm value if password and not removing (mkscript3 sets ${again} directly)
if [ "${editField}" == "Password" ] && [ "${op}" != "remove" ]; then
    mkscript3 "Confirm new password"

    # Exit if canceled
    [ "${again}" == "" ] && exit 0

    if [ "${new}" != "${again}" ]; then
	osascript -e 'display notification "Passwords do not match"'
	exit 0
    fi
fi

# Make the change
mkchange
