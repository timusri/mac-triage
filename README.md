# mac_triage.sh — what ran on this Mac after the phishing PDF?

Read-only evidence collector for a suspected-compromised macOS laptop. It never deletes,
kills or "cleans" anything; it only reads and writes its own output directory.

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
| `-q` | quick mode: skip sections 10/11 (deep find over home dir) | off |
| `-u USER` | the phished account (if you run as a different admin) | the sudo-ing user |
| `-o DIR` | output directory | `/Users/Shared/triage-<host>-<ts>` |
| `-p FILE` | one extra file to analyse; every quarantined download in the window is analysed automatically | none |

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

**Important asymmetry**: an empty persistence section does not mean clean. The common macOS
phishing payload today is an infostealer (AMOS/Atomic family and clones): one run, a fake
"macOS needs your password" dialog via osascript, then it zips the keychain, browser
passwords/cookies, `~/.ssh`, `~/.aws`, crypto wallets, Notes, and uploads them — no
persistence, process gone. Evidence of that is in `18` (osascript/display dialog), `08`/`11`
(a dropped binary in `/var/folders` or `/tmp`), `24` (access times), and `14` (an outbound
connection if it is still mid-exfil).

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
- For a live trace from now on: `sudo eslogger exec open > /Volumes/USB/exec.jsonl`.
- For Apple's full dump: `sudo sysdiagnose -f /Volumes/USB` (slow, 300MB+, includes everything here and more; what Apple/Jamf/a DFIR vendor will ask for).
