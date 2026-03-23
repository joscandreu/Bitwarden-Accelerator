# Proof-of-Concept Scripts

Each script demonstrates one vulnerability from the security audit.
Scripts are self-contained and print their own output.

| Script | Severity | Vulnerability |
|--------|----------|---------------|
| `poc1_json_injection_unlock.sh` | CRITICAL | JSON injection via master password in `unlock.sh:40` |
| `poc2_plaintext_password_on_disk.sh` | CRITICAL | Plaintext master password written to `~/bwpass.<user>` in `unlock.sh:56` |
| `poc3_unauth_local_api.sh` | CRITICAL | Unauthenticated local HTTP API (`bw serve`) |
| `poc4_path_hijacking.sh` | CRITICAL | PATH hijacking via cache directory prepend in `env.sh:10` |
| `poc5_json_injection_add_item.sh` | HIGH | JSON injection via user input in `add_item.sh:61–67` |
| `poc6_jq_injection_browser_url.sh` | HIGH | jq expression injection via browser URL in `list_items.sh:73` |
| `poc7_jq_injection_field_edit.sh` | HIGH | jq expression injection via field edit value in `get_new_field.sh:22` |
| `poc8_applescript_injection.sh` | HIGH | AppleScript injection via workflow variables |
| `poc9_shell_injection_fetch_file.sh` | HIGH | Shell code injection via sourced FETCH_FILE in `utils.sh:48–59` |

## Running

```bash
chmod +x poc/*.sh
bash poc/poc6_jq_injection_browser_url.sh   # no live server needed
bash poc/poc7_jq_injection_field_edit.sh    # no live server needed
bash poc/poc9_shell_injection_fetch_file.sh # no live server needed
bash poc/poc5_json_injection_add_item.sh    # no live server needed (static analysis)
bash poc/poc1_json_injection_unlock.sh      # static + optional live bw serve
bash poc/poc3_unauth_local_api.sh           # requires unlocked bw serve on :8087
bash poc/poc4_path_hijacking.sh             # safe simulation, no live bw needed
bash poc/poc2_plaintext_password_on_disk.sh # reads ~/bwpass.<user> if it exists
bash poc/poc8_applescript_injection.sh      # runs osascript; needs macOS GUI session
```

PoCs 1, 2, 5, 6, 7, 9 and the static portions of 4 and 8 run fully offline.
PoC 3 requires `bw serve` to be running with an unlocked vault.
PoC 8 requires a macOS GUI session for `osascript`.
