# Security Audit: Bitwarden-Accelerator Alfred Workflow

**Date:** 2026-03-23
**Scope:** Full source code review with focus on password-manager attack surface

---

## Attack Surface Overview

This Alfred Workflow bridges the macOS Alfred launcher with the Bitwarden password manager via:
1. A local HTTP API (`bw serve`) running unauthenticated on localhost
2. Shell scripts that handle master password input, transmission, and caching
3. User-supplied strings embedded into JSON payloads, jq expressions, and AppleScript code
4. Browser URL extraction used for vault search and URI matching
5. A Touch ID integration that stores the master password on disk

The combination of credential handling, local API exposure, and heavy use of unescaped string interpolation creates a significant attack surface.

---

## Vulnerabilities

### [CRITICAL] CVE-Class: JSON Injection → Master Password Exposed

**File:** `bin/unlock.sh:40`

```bash
RESPONSE=$(curl -s -H 'Content-Type: application/json' \
    -d '{"password": "'"${p}"'"}' "${API}"/unlock)
```

The master password `${p}` is concatenated directly into a JSON string literal without
any escaping. A master password that contains `"` (e.g., `P@"ss"word`) breaks the JSON
structure, causing the unlock request to fail silently or send a malformed payload.

More critically, the password is also stored on disk in plaintext (see below). If
an attacker can read and modify `~/bwpass.${USER}`, they can inject arbitrary JSON
into the `/unlock` API call — for example, injecting additional fields or breaking
authentication logic.

**Impact:** Authentication bypass, malformed API calls, denial of service on unlock.

---

### [CRITICAL] CVE-Class: Plaintext Master Password Written to Disk

**File:** `bin/unlock.sh:56`

```bash
sudo -H --preserve-env=p sh -c 'cd ; umask 077 ; echo "${p}" > bwpass.${SUDO_USER}'
```

When Touch ID is enabled (`pam_tid=1`), the Bitwarden master password is written in
plaintext to `~/bwpass.<username>`. Although `umask 077` sets restrictive permissions,
this creates serious risks:

- Any root-privileged process (malware, compromised daemon) can read the file
- Disk forensics can recover the content after deletion (`echo` does not securely wipe)
- The password persists across reboots until it is actively removed
- A symlink placed at `~/bwpass.<username>` before the write could redirect the password
  to an attacker-controlled location (race condition / symlink attack)

The file is not removed on lock (`bin/lock.sh`) — only on logout (`bin/logout.sh`).
This means the plaintext password survives vault locks.

**Impact:** Full master password compromise for any process with root access or file system
access (backup, forensic tools, shared volume snapshots).

---

### [CRITICAL] CVE-Class: Unauthenticated Local HTTP API

**File:** `lib/env.sh:20`, `bin/start_server.sh:16`

```bash
bw serve --hostname "${bwhost}" --port "${bwport}" &>/dev/null & disown
export API=http://"${bwhost}":"${bwport}"
```

The Bitwarden API server runs on `http://localhost:8087` with **no authentication**.
While it binds to localhost by default, there is no token, session cookie, or any
credential required. Any local process running as **any user** can interact with the
unlocked vault:

```bash
# Any process on the same machine can do this while the vault is unlocked:
curl http://localhost:8087/list/object/items     # dump all vault items
curl http://localhost:8087/object/password/<id>  # retrieve any password
curl -X POST -d '{"name":"evil","login":{"password":"stolen"}}' \
     http://localhost:8087/object/item           # add arbitrary items
```

This is a design limitation of `bw serve` itself, but the workflow does nothing to
mitigate it (e.g., OS-level firewall rules, per-request secrets passed via headers).

**Impact:** Complete vault compromise by any co-resident process while the vault is
unlocked. On a shared or multi-user macOS system this includes other user accounts.

---

### [CRITICAL] CVE-Class: PATH Hijacking via Cache Directory

**File:** `lib/env.sh:10`

```bash
export PATH="${alfred_workflow_cache}":${PATH}
```

The Alfred workflow cache directory is prepended to `PATH`. This directory is
user-writable and stores cached vault data. Any process that can write a file named
`bw`, `curl`, or `jq` to that directory will have that binary executed instead of
the real one the next time the workflow runs.

Attack scenarios:
- Another Alfred workflow with write access to the cache path
- A malicious script exploiting a path traversal bug to write to the cache
- Temp-file races if the cache directory is world-writable

Note: `${alfred_workflow_cache}` is also **not** double-quoted inside `${PATH}`, so
a cache path containing spaces or shell metacharacters could further break PATH.

**Impact:** Arbitrary code execution as the user, full vault compromise via a fake `bw`
or `curl` binary.

---

### [HIGH] CVE-Class: JSON Injection via Unsanitized User Input

**File:** `bin/add_item.sh:61–67`

```bash
PAYLOAD='{ "type": 1, "name": "'"${SITE}"'"'
PAYLOAD+=',"login": {'
PAYLOAD+=' "username": "'"${USERNAME}"'"'
PAYLOAD+=',"password": "'"${PASSWORD}"'"'
PAYLOAD+=',"uris": [ { "match": null, "uri": "'"${URL}"'" } ]'
PAYLOAD+='} }'
```

All four user-supplied values — `SITE`, `USERNAME`, `PASSWORD`, and `URL` — are
embedded into a JSON payload using shell string concatenation with **no escaping**.
Any of these containing `"` will break the JSON structure.

For `PASSWORD`, a value like `secret", "type": 2, "notes": "injected` would:
1. Close the password field prematurely
2. Inject additional JSON fields
3. Potentially change the item type or add unexpected data to the vault

**Impact:** Vault data corruption, injection of arbitrary JSON fields into stored items,
potential for crafted entries that exploit downstream consumers.

---

### [HIGH] CVE-Class: jq Expression Injection via Browser URL

**File:** `bin/list_items.sh:73`

```bash
| jq '.[] | [ select(.variables.uris[] | test("'"${URL}"'"; "i")) ] | unique_by(.id)' \
```

The `URL` variable contains the hostname extracted from the active browser URL, which is
then embedded directly into a jq filter as a regex argument. No escaping is applied.

A browser URL with a hostname like `evil.com")) | @base64d | .` would inject arbitrary
jq expressions. While `@base64d` on a string literal would error, more subtle injections
(e.g., path expressions that leak data or crash jq) are feasible.

Example malicious hostname: `x")) | error("` — causes jq to abort with a custom error.

**Impact:** jq expression injection leading to unexpected behavior, potential data
exfiltration from the cached vault data file, workflow DoS.

---

### [HIGH] CVE-Class: jq Expression Injection via Item Field Edit

**File:** `bin/get_new_field.sh:22`

```bash
| jq ".data | ${jqItem} |= \"$(cut -d: -f3 <<< "${new}")\"" \
```

The user's new field value (`${new}`) has its third colon-delimited segment extracted
and then embedded **unescaped** into a jq filter expression as a quoted string argument.
The surrounding quotes only protect against simple injection — a value containing `\"`
would escape the inner quotes and inject jq code.

Similarly in `bin/set_uri.sh:37`:
```bash
| jq ".data | .login.uris |= ${NEW_ITEM}" \
```
`NEW_ITEM` is Ruby script output that gets embedded into a jq expression.

**Impact:** Arbitrary jq code execution, possible modification of vault item structure
beyond the intended field, data corruption.

---

### [HIGH] CVE-Class: AppleScript Injection via Workflow Variables

**File:** `bin/login.sh:49`, `bin/get_new_field.sh:80`, `bin/configure_tid.sh:67`

```bash
# login.sh:49
A=$(osascript -e 'display dialog "'"${dialog}"'" with icon caution \
    with title "'"${title}"'" buttons '"${buttons}"' default button "Fix"')

# get_new_field.sh:80
osascript -e 'display notification "Unknown field: '"${editField}"'"'

# configure_tid.sh:67
A=$(/usr/bin/osascript -e "display alert \"${MSG}\" as critical \
    buttons { \"Cancel\", \"OK\" } default button \"Cancel\"")
```

Variables are embedded directly into AppleScript expressions via shell string
concatenation. If any of the interpolated values (`dialog`, `title`, `editField`,
`MSG`) contain `"` (or `'` in the single-quoted versions), the AppleScript syntax
is broken and may be injectable.

For example, `editField='x" & (do shell script "malicious_cmd") & "'` would close
the AppleScript string and inject an arbitrary shell command via AppleScript's
`do shell script`.

Alfred workflow variables (`editField`, etc.) are set in `info.plist` and can be
influenced by Alfred's configuration UI, making this exploitable via a crafted
workflow distribution.

**Impact:** Arbitrary shell command execution via AppleScript injection.

---

### [HIGH] CVE-Class: Shell Code Injection via Sourced FETCH_FILE

**File:** `lib/utils.sh:48–59`

```bash
saveSelection() {
    cat > "${FETCH_FILE}" << EOF
LAST_FETCH=${NOW}
old_objectId=${objectId}
old_field=${field}
EOF
}

getSelection() {
    LAST_FETCH=0
    [ -f "${FETCH_FILE}" ] && . "${FETCH_FILE}"
}
```

The `FETCH_FILE` is created with unquoted `${objectId}` and `${field}` values, then
later **sourced** with `.`. If these variables contain shell metacharacters (spaces,
semicolons, newlines, backticks), the sourced file can execute arbitrary commands.

`${field}` is a workflow variable (e.g., `"password"`, `"username"`) but `${objectId}`
comes from vault item IDs. While Bitwarden uses UUIDs today, the workflow would be
vulnerable if ever used against a compromised/malicious vault server (see `serverUrl`
SSRF below).

**Impact:** Arbitrary shell code execution if `objectId` or `field` contain injected
content.

---

### [MEDIUM] CVE-Class: SSRF / Credential Phishing via `serverUrl`

**File:** `bin/login.sh:20`

```bash
bw config server "${serverUrl}" >& /dev/null
```

The Bitwarden server URL is taken directly from the Alfred workflow configuration
variable `serverUrl`. An attacker who can deliver a malicious Alfred workflow (e.g., via
workflow sharing platforms, supply chain attack, or social engineering) can redirect
all vault operations to an attacker-controlled server.

Combined with the password-based login method, this enables full credential harvesting:
the fake server receives the master password and any 2FA codes.

**Impact:** Full credential phishing on workflow installation or update.

---

### [MEDIUM] CVE-Class: Attachment Path Traversal

**File:** `bin/get_attachment.sh:13`

```bash
curl -s --output-dir "${downloadFolder}" -o "${attachmentName}" \
    "${API}/object/attachment/${attachmentId}?itemid=${id}"
```

`attachmentName` is sourced from vault item metadata (controlled by the vault server
or a malicious vault entry). curl's `-o` flag combined with `--output-dir` constructs
the final path as `downloadFolder/attachmentName`. If `attachmentName` contains `/`,
curl writes to a sub-path relative to `downloadFolder`, enabling path traversal.

Example: an attachment named `../../.ssh/authorized_keys` with an SSH public key
as content would write to `~/.ssh/authorized_keys`.

**Impact:** Arbitrary file write within reach of path traversal from the download folder.

---

### [MEDIUM] CVE-Class: Unquoted Variables in `FETCH_FILE` Heredoc

**File:** `lib/utils.sh:49–53`

```bash
cat > "${FETCH_FILE}" << EOF
LAST_FETCH=${NOW}
old_objectId=${objectId}
old_field=${field}
EOF
```

Using an unquoted heredoc delimiter (`EOF` vs `'EOF'`) causes bash to expand variables
and command substitutions inside the heredoc. A `$(...)` in `objectId` would execute
at write time. While the content then written to the file would be the output of that
substitution, any newlines in the substitution result would create additional lines in
the file — which are then executed when sourced.

---

### [MEDIUM] CVE-Class: Sensitive Data in Debug Log

**File:** `lib/env.sh:88–92`, `bin/get_attachment.sh:12`

```bash
log() {
    [ "${DEBUG}" != 1 ] && return
    echo "$(date): [$(basename "${BASH_SOURCE[1]}"):${BASH_LINENO[0]}] ${*}" >> "${LOG_FILE}"
}

# In get_attachment.sh:
log curl -s --output-dir "${downloadFolder}" -o "${attachmentName}" \
    "${API}/object/attachment/${attachmentId}?itemid=${id}"
```

When `DEBUG=1`, the full curl command including attachment IDs and item IDs is written
to the log file. The log resides in the Alfred workflow cache, which has no special
access controls. Sensitive vault identifiers could be harvested from the log.

Additionally, the `log()` function is called with `log "unlock"` in `bin/unlock.sh:7`
just before the master password is used — if future developers add password logging
here, it would immediately appear in the log file.

**Impact:** Vault metadata leakage, potential sensitive data in log files.

---

### [MEDIUM] CVE-Class: Race Condition on Password File Creation

**File:** `bin/unlock.sh:56`

```bash
sudo -H --preserve-env=p sh -c 'cd ; umask 077 ; echo "${p}" > bwpass.${SUDO_USER}'
```

The sequence is: (1) `cd` to home, (2) set `umask`, (3) redirect to file. The `>`
operator creates the file atomically with the umask applied — so on Linux/macOS this
is generally safe from TOCTOU attacks for the file creation itself.

However, if `~/bwpass.<username>` already exists as a symlink (planted by a local
attacker), `echo >` will follow the symlink and write the password to the symlink
target. The `sudo -H sh -c` runs as root, so a symlink pointing to any world-writable
path (or a privileged file) would write the master password there.

**Impact:** Password written to attacker-controlled file via symlink attack.

---

### [LOW] CVE-Class: Vault Status Written to Predictable File Without Integrity Check

**File:** `lib/status.sh:7`

```bash
curl -s "${API}"/status | jq .data.template > "${STATUS_FILE}"
```

The status file is world-readable (no special permissions set) and stored in a
predictable location. The workflow later sources decisions from this file (locked vs.
unlocked state). While direct exploitation is limited, manipulating this file could
confuse state-machine logic (e.g., spoofing an "unlocked" state).

---

### [LOW] CVE-Class: `$PATH` Not Quoted on Reassignment

**File:** `lib/env.sh:10`

```bash
export PATH="${alfred_workflow_cache}":${PATH}
```

The existing `${PATH}` is not double-quoted on the right-hand side. If the current
PATH contains spaces (unusual but possible), word splitting could corrupt it.

---

## Summary Table

| Severity | ID | File | Description |
|---|---|---|---|
| CRITICAL | 1 | `unlock.sh:40` | JSON injection via master password |
| CRITICAL | 2 | `unlock.sh:56` | Plaintext master password written to disk |
| CRITICAL | 3 | `env.sh:20`, `start_server.sh:16` | Unauthenticated local HTTP API |
| CRITICAL | 4 | `env.sh:10` | PATH hijacking via cache directory prepend |
| HIGH | 5 | `add_item.sh:61–67` | JSON injection via unsanitized user input |
| HIGH | 6 | `list_items.sh:73` | jq expression injection via browser URL |
| HIGH | 7 | `get_new_field.sh:22` | jq expression injection via field edit value |
| HIGH | 8 | `login.sh:49`, `get_new_field.sh:80` | AppleScript injection via workflow variables |
| HIGH | 9 | `utils.sh:48–59` | Shell code injection via sourced FETCH_FILE |
| MEDIUM | 10 | `login.sh:20` | SSRF / credential phishing via serverUrl |
| MEDIUM | 11 | `get_attachment.sh:13` | Attachment path traversal |
| MEDIUM | 12 | `utils.sh:49–53` | Unquoted heredoc variable expansion |
| MEDIUM | 13 | `env.sh:88–92` | Sensitive metadata in debug log |
| MEDIUM | 14 | `unlock.sh:56` | Symlink attack on password file creation |
| LOW | 15 | `status.sh:7` | Status file integrity / predictable location |
| LOW | 16 | `env.sh:10` | Unquoted PATH on reassignment |

---

## Recommended Fixes (High-Level)

1. **JSON construction:** Use `jq -n --arg key value '{"key": $key}'` instead of shell
   string interpolation to build JSON payloads. Never interpolate untrusted strings into
   JSON literals.

2. **Master password on disk:** Replace the plaintext file with macOS Keychain storage
   (`security add-generic-password`) which encrypts at rest and requires Touch ID
   authorization per-access without ever writing to disk.

3. **Local API authentication:** Generate a random token at server startup, store it
   in memory only, and pass it via the `Authorization` header on every API call.
   Alternatively, use a Unix domain socket instead of TCP.

4. **PATH manipulation:** Remove `alfred_workflow_cache` from PATH entirely. Use
   explicit full paths for all tool invocations (`/usr/bin/jq`, etc.).

5. **jq injection:** Pass user input as `--arg` parameters to jq rather than embedding
   in filter expressions. For browser URL regex: `jq --arg url "$URL" '... test($url)'`.

6. **AppleScript injection:** Escape or sanitize strings before embedding in AppleScript.
   Use `osascript` with separate `-e` arguments or pass data via environment variables
   read with `system attribute`.

7. **FETCH_FILE sourcing:** Use a quoted heredoc (`'EOF'`) to prevent command substitution,
   and quote variables on assignment. Better yet, use a key=value parser that does not
   `source` the file.

8. **Attachment path traversal:** Validate `attachmentName` against a whitelist of safe
   characters (alphanumeric, dots, hyphens), strip all directory separators, and use
   `-o "$(basename "${attachmentName}")"` to prevent path components from being
   interpreted.
