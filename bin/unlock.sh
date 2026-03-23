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
	p=$(sudo -H sh -c 'cd ; cat bwpass.${SUDO_USER}')
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

# Build JSON payload safely — never interpolate ${p} into a string literal
JSON_PAYLOAD=$(jq -n --arg password "${p}" '{"password": $password}')

# Try JSON payload
RESPONSE=$(curl -s -H 'Content-Type: application/json' -d "${JSON_PAYLOAD}" "${API}"/unlock)

# Try key=value payload (URL-encode the password to prevent & injection)
if [ "$(jq -j '.success' <<< "${RESPONSE}")" != "true" ]; then
    ENC_PASS=$(python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read(), safe=''))" <<< "${p}")
    RESPONSE=$(curl -s -d "password=${ENC_PASS}" "${API}"/unlock)
fi

##################################################
# Save password if using Touch ID

if [ "${pam_tid}" == 1 ] && [ ${TID} == 0 ]; then
    if [ "$(jq -j '.success' <<< "${RESPONSE}")" != "true" ]; then
	# Master password was incorrect.  Remove it from the cache.
	sudo -H sh -c 'cd ; rm -f bwpass.${SUDO_USER}'
    else
	# Master password was correct.  Store it in the cache.
	sudo -H --preserve-env=p sh -c 'cd ; umask 077 ; echo "${p}" > bwpass.${SUDO_USER}'
    fi
fi

jq -j '.message // .data.title' <<< "${RESPONSE}"
