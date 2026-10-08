# mac_triage.sh — is this Mac compromised, and what ran on it?

Read-only evidence collector and endpoint scanner for a suspected-compromised macOS laptop. It
never deletes, kills, unloads, mounts, installs or "cleans" anything; it only reads and writes its
own output directory. It makes **no network calls** unless you opt in with `-X` or `-V` (below), so
it works with Wi-Fi off. Apple `/bin/bash` 3.2 and stock macOS tools only; nothing to install.

## Before you run it (order matters)

1. **Do not reboot, do not "clean up", do not delete the PDF.** Birth times, quarantine
   records, /var/folders temp files and the unified log are the evidence.
2. **Disconnect from Wi-Fi / unplug Ethernet** unless you are told to keep it up to watch a
   beacon. Everything the script needs is local.
3. Give Terminal **Full Disk Access**: System Settings → Privacy & Security → Full Disk
   Access → add Terminal. Without it: Safari history, TCC.db, Mail and Messages data are unreadable.
4. Copy `mac_triage.sh` onto the laptop via USB stick or AirDrop (not by logging into anything).
5. Have an external drive or USB stick mounted to receive the output (`-o /Volumes/USB/triage`).

## Run

```bash
# the whole thing, one command, no flags: 30-day file window, 7-day log window, every download analysed
sudo bash mac_triage.sh -o /Volumes/USB/triage
```

Optional tuning (only if you need it):

```bash
sudo bash mac_triage.sh -q -l 1d          # ~5 min preview: skips the deep filesystem walks, 1 day of log
sudo bash mac_triage.sh -p ~/Downloads/x.pdf   # also analyse one specific file (all quarantined downloads are analysed anyway)
```

| flag | meaning | default |
|---|---|---|
| `-d DAYS` | "recent" window for files, downloads, installs | 30 |
| `-l WIN` | unified-log window (`12h`, `3d`, `7d`). This is the slow part: budget ~5–10 min per day of log on a busy Mac | 7d |
| `-q` | quick mode: skip sections 10/11 (deep find over home dir); section 28 then only walks `~/Library`, Downloads/Desktop/Documents, hidden home dirs, tmp and /Users/Shared for `#!` scripts | off |
| `-u USER` | the phished account (if you run as a different admin) | the sudo-ing user |
| `-o DIR` | output directory | `/Users/Shared/triage-<host>-<ts>` |
| `-p FILE` | one extra file to analyse; every quarantined download in the window is analysed automatically | none |
| `-X` | also run `xprotect check` and `xprotect logs` (macOS 15+). **`xprotect check` is an online check of the newest XProtect version in iCloud, not a malware scan**; it is the only network call `-X` adds. XProtect Remediator detections are collected anyway from the unified log (`19`) and `xprotect version`/`status` (`26`) | off |
| `-V` | VirusTotal **hash lookups** (GET `/files/<sha256>` only, nothing uploaded) for the suspect downloads, unsigned/odd Mach-Os and running binaries, max 25; needs `VT_API_KEY` in the environment (`sudo VT_API_KEY=... bash mac_triage.sh -V`). Prints hash + verdict only, into `31_virustotal.txt` | off |

Output: one `.txt` per section, `00_SUMMARY.txt` first, plus a `.tgz` + `.sha256` of the whole
directory. The directory is `chmod go-rwx` and contains browser history, shell history and
file names — treat it as sensitive.

## How to read it — the 15-minute version

Start from the time the PDF was downloaded/opened and work outward. The timestamp is in
`07_quarantine_events.txt` / `08_downloaded_files.txt` (`kMDItemWhereFroms`, `kMDItemDownloadedDate`)
and in `25_suspect_files.txt` (birth time, `LastUsedDate`, `UseCount`).

| file | question it answers | red flag |
|---|---|---|
| `25_suspect_files.txt` | is the "PDF" really a PDF, and does it carry active content? | `file` says Mach-O / zip / disk image; non-zero `/JS`, `/JavaScript`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`; embedded URLs you do not recognise. A pure-PDF lure usually has **no** active content and just links to a credential-phish page — then the damage is the password you typed, not malware. |
| `07`, `08`, `09` | what else was downloaded, by which app, from where, **after** the PDF | any `.dmg`, `.pkg`, `.zip`, `.app`, `.sh`, `.command`, `.scpt`, `.jar`, `.py` with an unfamiliar source URL; files in `/var/folders`, `/tmp`, `~/Library/Application Support/<odd name>` |
| `18_unifiedlog_execution.txt` | **the spawn timeline**: every GUI-session process launchd started, with pid and time. Also osascript `display dialog` (fake password prompts), `curl ... \| sh`, `chmod +x`, `nohup`, inline `bash -c`/`python3 -c`, and `sudo` commands | processes named like a system tool but spawned from a user path; `osascript` or `Terminal`/`bash`/`sh`/`curl`/`python3` spawned within minutes of the PDF open; `display dialog` asking for a password |
| `11_recent_executables.txt` | new Mach-O binaries and scripts in user-writable paths | `code object is not signed at all`, `Signature=adhoc`, `TeamIdentifier=not set` on something you did not build; anything in `~/Library`, `/Users/Shared`, `/tmp`, `/private/var/folders` |
| `03`, `04`, `05` | persistence | LaunchAgent/Daemon plist with birth time in the window; a `Program` that is unsigned or lives in `~/Library`/`/tmp`; new BTM login item (`sfltool dumpbtm`); cron entries; `.zshrc`/`.zprofile` modified in the window with a line you did not add |
| `15_tcc_permissions.txt` | what was granted Screen Recording / Accessibility / Full Disk Access / Apple Events | `auth_value 2` for a client you do not recognise, with `last_modified` in the window |
| `13`, `14` | what is running and talking right now | unsigned running binary; `ESTABLISHED` to an IP you cannot attribute; changed DNS servers or a proxy/PAC URL set; a listener on an odd port; unknown entry in `~/.ssh/authorized_keys` |
| `19`, `20`, `21` | did Gatekeeper/XProtect block or flag anything; did BTM register a new item; did TCC prompt | `XProtect ... detected`, `blocked`, `malware`; `BTM ... added`; `TCC Prompting` for an app you never saw |
| `16_shell_history.txt` | commands run in terminals (timestamped) | commands you did not type |
| `24_credential_files.txt` | what a stealer could have taken; `acc` = last access time | an access time inside the window on `~/.aws/credentials`, `~/.ssh/id_*`, `~/.kube/config`, Chrome `Login Data`/`Cookies`, `Library/Keychains`, when you were not using those tools |
| `26_malware_iocs.txt` | does anything on disk, in launchd, in processes, in rc files or in shell history match a **known macOS malware family**, and do the generic stealer heuristics fire? | any `IOC ` line (family + where + evidence). Any `HEUR ` line: `osascript_password_prompt`, `unsigned_macho_userdir`, `stealer_strings_in_binary`, `hidden_app_userdir`, `base64_blob_in_plist`, `dyld_or_lsenvironment_in_plist`, `shell_oneliner_in_plist`, `interpreter_as_launchd_program`, `launchd_program_in_tmp_or_hidden`, `user_launchagent_named_com_apple`, `hidden_entry_in_Library`, `hidden_entry_in_shared_or_tmp`, `suspicious_cron`, `rc_fetch_or_decode`. `INFO` lines are signed, probably-legitimate context. `no IOC matches` / `no heuristic hits` is the clean result |
| `27_login_activity.txt` | who logged in, unlocked, sudo'd, ssh'd or screen-shared, when, from where; failed-password bursts | `FAIL` rows clustered in time (password guessing), `ssh-login`/`screen-sharing` from an address you do not know, `sudo` from a TTY at a time you were not there, `authz-ok` granting a right to a client in `/tmp`, `/var/folders` or `~/Library`, a `LOGINHOOK`, `failedLoginCount > 0` on an account nobody uses |
| `28_script_execution.txt` | what interpreters and scripts ran: every user's shell history, `SPAWN` lines (launchd started python/osascript/sh/curl/...), `#!` scripts born in the window, Terminal profiles that run a command, Automator/Shortcuts/Services, `at`/periodic | history lines you did not type (the "suspicious history lines" block), a `SPAWN` of `osascript`/`python3`/`curl` at the compromise time, a `SHEBANG` file in `~/Library`, `/tmp`, `/var/folders` or `/Users/Shared`, a Terminal `CommandString`, a Shortcut or `.workflow` you did not make |
| `29_tamper_and_hijack.txt` | has the trust base of the machine been changed: root CAs, profiles, `/etc/hosts`, pam/sudoers/sshd, login mechanisms, SIP/Gatekeeper, kexts/sysexts, codesign of changed apps, browser homepage/search/extensions/policies | a `CA ` line you did not install (TLS interception), a `profileIdentifier:` you did not enrol, `HOSTS` entries for login/bank/update domains, `MODIFIED-AFTER-OS-UPDATE` on a pam/sshd file, `NON-APPLE-MECHANISM`, `SSHD-RISKY`, SIP/Gatekeeper disabled or `boot-args` set, a `REGULAR-FILE` in `/opt/homebrew/bin`, `CODESIGN-FAIL`, an `EXT` flagged `SIDELOADED`/`POLICY-INSTALLED`/`NON-STORE-UPDATE-URL`/`NEW-IN-WINDOW`, a `POLICY` line in Chrome managed preferences, a Firefox `user.js` |
| `30_network_history.txt` | the network view `14` does not have: routes, ARP, proxies, VPN/NetworkExtension registrations (content filters, DNS proxies), known Wi-Fi networks, pf anchors, `/etc/resolver`, and every `ESTABLISHED` connection joined to its process path + signer with a coarse IP attribution | a route/DNS/proxy/PAC you did not set, a NetworkExtension bundle id you do not recognise, an `/etc/resolver` entry, non-Apple pf rules, a connection flagged `ODD-PATH` or `UNSIGNED`, an `unattributed` remote endpoint that persists across runs (attribution is a local prefix match, not a lookup) |

**Important asymmetry**: an empty persistence section does not mean clean. The common macOS
phishing payload today is an infostealer (AMOS/Atomic family and clones): one run, a fake
"macOS needs your password" dialog via osascript, then it zips the keychain, browser
passwords/cookies, `~/.ssh`, `~/.aws`, crypto wallets, Notes, and uploads them — no
persistence, process gone. Evidence of that is in `18` (osascript/display dialog), `08`/`11`
(a dropped binary in `/var/folders` or `/tmp`), `24` (access times), and `14` (an outbound
connection if it is still mid-exfil).

## Detection coverage (section 26)

The IOC list is embedded in the script as a heredoc inside `ioc_list()` (search for `IOCS`). One
line per indicator, `family|kind|note|pattern` (pattern last, so it may contain `|`; the note may not), kinds: `path` (glob, `~` = every user home), `label`
(launchd), `proc` (ps), `str` (launchd plists + rc files + cron + small scripts in tmp dirs), `hist`
(every user's shell history), `bin` (`strings` of recent Mach-Os in user-writable dirs), `app`
(bundle names), `ext` (Chrome-family extension id). Families currently covered:

- **Stealers:** Atomic/AMOS (incl. the 2025 backdoor variant: `.helper`/`.agent`, `com.finder.helper`, `/tmp/.pass`), Poseidon, Cuckoo, Banshee, MacSync, Cthulhu (`/Users/Shared/NW`), MacStealer, Realst (fake-game bundles)
- **Adware / bundlers:** Adload (hidden `Application Support/.<x>/Services/*.app` layout), Shlayer (`openssl enc` stage-1), Bundlore, Pirrit, Genieo
- **Developer-targeting:** XCSSET (`~/.zshrc_aliases`, fake `/Applications/Launchpad.app`)
- **DPRK:** RustBucket (`com.apple.systemupdate`, `Internal PDF Viewer.app`), KandyKorn/SugarLoader (`.sld`, partial), BeaverTail/InvisibleFerret (`~/.n2`, `~/.n3`, `~/.npl`, `~/.pyp`, node/python from those dirs)
- **Backdoors / spyware:** JokerSpy (`/Users/Shared/AppleAccount.tmp`, `xcc`, `sh.py`), ChromeLoader (`--load-extension=`), Silver Sparrow (`._insu`, `agent_updater`, `verx_updater`, `init_verx`/`init_agent`), Dacls (`~/Library/.mina`, `com.aex-loop.agent`)
- **ClickFix / ClearFake "paste this into Terminal" lures:** `base64 -d | sh`, `curl -s ... | sh`, `$(curl ...)`, inline base64 echo, `xattr -d com.apple.quarantine` / `xattr -c`, `spctl --master-disable`, `osascript ... do shell script`, `nohup ... &` in any user's history. These are matched on what the victim typed, so a developer's own `xattr -c` will also show up: read the line.
- **C2 frameworks:** Geacon/Cobalt Strike, Sliver, Mythic (Apfell, Poseidon, Orthrus, Thanatos) via strings in recent Mach-Os and process names

Plus the generic heuristics listed in the table above, which are what catch an unknown stealer:
AppleScript password prompts in recently written files, unsigned/ad-hoc Mach-Os and UI-less apps in
user-writable dirs, stealer strings (`Login Data`, `keychain`, `wallet`, `exodus`, `metamask`,
`task_for_pid`, ...) in those binaries, base64 blobs / `curl|sh` / `DYLD_INSERT_LIBRARIES` /
interpreters as `Program` in launchd plists, `com.apple.*` agents in a user's LaunchAgents, hidden
entries in `Application Support`, `/Users/Shared` and tmp, cron and rc-file fetch/decode lines.

**IOCs go stale.** The bundled list is a snapshot of public vendor reporting (through late 2025);
malware authors rename paths and labels every few months. `no IOC matches` means none of *these*
matched, not that the Mac is clean: the heuristics and sections 03-25 are the durable part. No
Chrome extension ids are bundled because the public ones rotate too fast to be worth hard-coding.
To add an indicator, append a `family|kind|note|pattern` line inside the `IOCS` heredoc (patterns
are `grep -E` regexes except `path`, which is a shell glob) and re-run; nothing else changes. A
`#`-prefixed line is a comment.

## If anything above is positive — or you typed a password into a page the PDF linked to

Treat every credential reachable from that laptop as stolen, in this order:

1. Google Workspace password + sign out all sessions + re-check 2FA devices and app passwords.
2. AWS: IAM Identity Center / SSO session revoke; any long-lived keys in `~/.aws/credentials` → rotate (ask the platform team: the profile names in `24_credential_files.txt` say which).
3. GitHub: revoke the `gh` OAuth token and any PATs; rotate SSH key in GitHub settings.
4. Kubernetes: contexts in `~/.kube/config` are SSO-backed, but revoke the SSO session; check CloudTrail/EKS audit for the user's ARN from the compromise time.
5. Tailscale: expire the node key for that laptop from the admin console.
6. Slack, 1Password/password manager, Vanta, Cloudflare, Grafana: sign out everywhere, rotate.
7. Keep the laptop off the network until it is reimaged. Do not "clean" it — reimage.
8. Ask the security engineer to pull CloudTrail (`userIdentity.arn` = your SSO role) and GitHub audit log for the window, to see whether the stolen creds were *used*.

## Caveats

- macOS has no default exec audit log. Execution is reconstructed from launchd spawn records
  (GUI-session processes only), quarantine, Gatekeeper, BTM, shell history and file birth times.
  A process started by a shell inside Terminal is visible via shell history and the `bash -c`/`curl` log matches, not the spawn timeline.
- Unified log retention is finite (often days to a couple of weeks on a busy machine). If the
  phishing was longer ago than that, the log sections will simply start later than the event.
- `[exit=1]` at the end of a section usually just means the last `grep`/`find` matched nothing.
- Section 26 `INFO` lines (signed, non-Apple Mach-Os and UI-less helper apps under `~/Library`) are normal on a developer Mac: JetBrains, VS Code, Google updater, Slack helpers and the like all live there. Only `IOC `/`HEUR ` lines are counted.
- The IP attribution in `30` is a coarse, offline prefix match (private / Apple / Google / Cloudflare / Fastly / Akamai / Microsoft / Amazon-ish / Meta / GitHub). `unattributed` means "not obviously one of those", nothing more; it is a starting point, not a verdict.
- `strings`/`otool` are Xcode Command Line Tools shims; without the CLT the binary-strings heuristic and `bin` IOCs are skipped (the section header says `strings-scan available=0`).
- For a live trace from now on: `sudo eslogger exec open > /Volumes/USB/exec.jsonl`.
- For Apple's full dump: `sudo sysdiagnose -f /Volumes/USB` (slow, 300MB+, includes everything here and more; what Apple/Jamf/a DFIR vendor will ask for).
