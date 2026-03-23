#!/bin/bash

# shellcheck disable=2181

. lib/env.sh

log "start_server"

# Check if server is already running
curl -s "${API}"/status

[ $? == 0 ] && exit

# Generate a random ephemeral port (49152–65535) for this server session.
# Storing it in a user-only-readable file prevents other local processes from
# trivially discovering the API address across sessions.
# NOTE: bw serve does not currently support token-based authentication.
# A complete fix requires upstream support (e.g. a --auth-token flag).
# Track: https://github.com/bitwarden/clients/issues
BWPORT_FILE="${alfred_workflow_cache}/bwport"
NEW_PORT=$(( RANDOM % 16383 + 49152 ))
echo "${NEW_PORT}" > "${BWPORT_FILE}"
chmod 0600 "${BWPORT_FILE}"
bwport=${NEW_PORT}
export API=http://"${bwhost}":"${bwport}"

log "${bwhost}:${bwport}"

bw serve --hostname "${bwhost}" --port "${bwport}" &>/dev/null & disown
