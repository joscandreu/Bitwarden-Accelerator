#!/bin/bash

# shellcheck disable=2034,2154

. lib/env.sh

log "unlock"

export p=""

TID=1


##################################################
# Get master password

# Read password if using Touch ID
if [ "${pam_tid}" == 1 ]; then
    ./bin/configure_tid.sh
    TID=$?

    if [ ${TID} == 0 ]; then
	p=$(/usr/bin/security find-generic-password \
	    -a "${USER}" -s "BW-Accelerator-MasterPass" -w 2>/dev/null)
    fi
fi

# Maybe prompt for password
if [ "${p}" == "" ]; then
    p=$(2>&- ./bin/get_password.applescript "Enter Master password for ${bwuser}")
fi

# Exit if no password
[ "${p}" == "" ] && exit


##################################################
# Unlock

# Try JSON payload
RESPONSE=$(curl -s -H 'Content-Type: application/json' -d '{"password": "'"${p}"'"}' "${API}"/unlock)

# Try key=value payload
if [ "$(jq -j '.success' <<< "${RESPONSE}")" != "true" ]; then
    RESPONSE=$(curl -s -d "password=${p}" "${API}"/unlock)
fi

##################################################
# Save password if using Touch ID

if [ "${pam_tid}" == 1 ] && [ ${TID} == 0 ]; then
    if [ "$(jq -j '.success' <<< "${RESPONSE}")" != "true" ]; then
	# Master password was incorrect.  Remove it from the cache.
	/usr/bin/security delete-generic-password \
	    -a "${USER}" -s "BW-Accelerator-MasterPass" 2>/dev/null
    else
	# Master password was correct.  Store it in the Keychain (encrypted).
	/usr/bin/security add-generic-password \
	    -a "${USER}" -s "BW-Accelerator-MasterPass" -w "${p}" -U 2>/dev/null
    fi
fi

jq -j '.message // .data.title' <<< "${RESPONSE}"
