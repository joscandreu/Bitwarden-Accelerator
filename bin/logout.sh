#!/bin/bash

. lib/env.sh

log "logout"

./bin/stop_server.sh

"${BW_BIN}" --response logout | jq -j '.message // .data.title'
rm -f "${DATA_DIR}"/*
sudo -k
