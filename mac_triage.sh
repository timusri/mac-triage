#!/bin/bash
# mac_triage.sh - READ-ONLY macOS incident triage collector.
#
# Collects evidence of what was downloaded / executed / persisted on a Mac after a
# suspected phishing compromise, and sweeps for known macOS malware families and generic
# stealer/persistence/tamper heuristics (sections 26-30). It never modifies, deletes,
# kills, unloads, mounts, installs or "cleans" anything, and makes no network calls unless -X or -V is given.
#
# Run from a Terminal that has Full Disk Access (System Settings > Privacy & Security
# > Full Disk Access > Terminal), ideally with sudo so system logs, TCC and
# Background Task Management data are readable:
#
#   sudo bash mac_triage.sh            # full run, no flags needed: 30-day file window, 7-day log window, all downloads analysed
#   sudo bash mac_triage.sh [-d DAYS] [-l WIN] [-q] [-u USER] [-o OUTDIR] [-p FILE] [-X] [-V]   # optional tuning
#
#   -d DAYS   look-back window for "recent" (default 30)
#   -u USER   the user whose account was phished (default: the sudo-ing user)
#   -o OUTDIR where to write (default: /Users/Shared/triage-<host>-<ts>) - point this
#             at an external drive if you can.
#   -p FILE   a specific suspected file to analyse (every quarantined download in the window is analysed anyway)
#   -l WIN    unified-log window, e.g. 12h, 3d (default 7d). Log scans are the slow part: 1d on a busy Mac can take 5-10 min per query.
#   -q        quick mode: skip the deep filesystem walks (sections 10, 11; section 28 walks only the small user-writable dirs) - run this first, then the full run.
#   -X        also run `xprotect check` + `xprotect logs` (macOS 15+). NOTE: on current macOS `xprotect check` is an ONLINE check of the
#             latest XProtect version in iCloud, not a malware scan; it is the only network call the script can make. Off by default.
#   -V        VirusTotal hash lookups (GET only, nothing uploaded) for suspect/unsigned/running binaries; needs VT_API_KEY in the environment. Off by default.
#
# Output: a directory of .txt files + a .tgz + sha256, nothing else is written.
set -u
set +e
PATH="/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec:$PATH"   # Apple tools first; Homebrew grep/awk/sed would change output. Optional tools (tailscale, qpdf) still resolve.

DAYS=30
LOGWIN=7d
QUICK=0
XPROTECT_CHECK=0
VT_LOOKUP=0
OUTDIR=""
SUSPECT=""
TARGET_USER="${SUDO_USER:-$(whoami)}"
while getopts "d:u:o:p:l:qXVh" opt; do
  case "$opt" in
    d) DAYS="$OPTARG" ;;
    u) TARGET_USER="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    p) SUSPECT="$OPTARG" ;;
    l) LOGWIN="$OPTARG" ;;
    q) QUICK=1 ;;
    X) XPROTECT_CHECK=1 ;;
    V) VT_LOOKUP=1 ;;
    *) sed -n '2,20p' "$0"; exit 1 ;;
  esac
done

HOST=$(hostname -s 2>/dev/null || hostname)
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="${OUTDIR:-/Users/Shared/triage-${HOST}-${TS}}"
mkdir -p "$OUT" || { echo "cannot create $OUT"; exit 1; }
UHOME=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
UHOME="${UHOME:-/Users/$TARGET_USER}"
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1

echo "== macOS triage: host=$HOST user=$TARGET_USER home=$UHOME window=${DAYS}d logwindow=$LOGWIN quick=$QUICK root=$IS_ROOT out=$OUT"
[ $IS_ROOT -eq 0 ] && echo "!! not root: TCC.db, system launchctl, sfltool, pfctl, install.log and other users' data will be incomplete"

# section NAME cmd args...   -> $OUT/NAME.txt   (use: section name bash -c '...pipeline...')
section() {
  local name="$1"; shift
  local f="$OUT/$name.txt"
  echo "-- $name" >&2
  { echo "### $name"; echo "### cmd: $*"; echo "### collected: $(date -u +%FT%TZ)"; echo; } > "$f"
  "$@" >> "$f" 2>&1
  echo "[exit=$?]" >> "$f"
}
# append NAME "label" cmd...   -> appends to $OUT/NAME.txt
append() {
  local name="$1" label="$2"; shift 2
  local f="$OUT/$name.txt"
  { echo; echo "----- $label"; echo "----- cmd: $*"; } >> "$f"
  "$@" >> "$f" 2>&1
  echo "[exit=$?]" >> "$f"
}
statf() { stat -f '%Sm mod | %Sc chg | %SB birth | %Sa acc | %z B | %Su:%Sg %Sp | %N' "$@"; }
hashit() { shasum -a 256 "$@" 2>/dev/null; }
FIND_EXCL=( -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/Library/Caches/*' -not -path '*/Library/Developer/*' -not -path '*/Cellar/*' -not -path '*/.cache/*' -not -path '*/Library/Containers/*/Data/Library/Caches/*' )

############################ 1. system ############################
section 01_system bash -c "
sw_vers; echo; uname -a; echo; date; echo; uptime; echo
echo '--- SIP / Gatekeeper / firewall'; csrutil status; spctl --status; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
echo; echo '--- XProtect version'; defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null; ls -la /Library/Apple/System/Library/CoreServices/ 2>/dev/null | grep -i xprotect
echo; echo '--- MDM / profiles'; profiles status -type enrollment 2>&1; profiles list -all 2>&1
echo; echo '--- who / last'; who; echo; last -50
echo; echo '--- software overview'; system_profiler SPSoftwareDataType 2>/dev/null"

############################ 2. users / privilege ############################
section 02_users bash -c "
echo '--- users (UID<500 or unusual are suspicious):'; dscl . -list /Users UniqueID | sort -k2 -n
echo; echo '--- admin group'; dscl . -read /Groups/admin GroupMembership
echo; echo '--- wheel group'; dscl . -read /Groups/wheel GroupMembership
echo; echo '--- hidden users / login hooks'; defaults read /Library/Preferences/com.apple.loginwindow 2>&1
echo; echo '--- sudoers'; cat /etc/sudoers 2>&1; ls -la /etc/sudoers.d 2>&1; cat /etc/sudoers.d/* 2>/dev/null
echo; echo '--- /etc recently changed'; find /etc /private/etc -type f \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) -exec stat -f '%Sm %N' {} \; 2>/dev/null
echo; echo '--- passwd/shadow-ish policy for target user'; dscl . -read /Users/$TARGET_USER PrimaryGroupID UniqueID UserShell NFSHomeDirectory 2>&1"

############################ 3. persistence ############################
section 03_persistence_launchd bash -c "
for d in '$UHOME/Library/LaunchAgents' /Library/LaunchAgents /Library/LaunchDaemons /Library/StartupItems /System/Library/LaunchAgents /System/Library/LaunchDaemons; do
  [ -d \"\$d\" ] || continue
  echo '==================' \"\$d\"
  ls -la@t \"\$d\"
  case \"\$d\" in /System/*) echo '(system dir: listing only, newest first)'; continue;; esac
  for p in \"\$d\"/*.plist; do
    [ -f \"\$p\" ] || continue
    echo; echo '------' \"\$p\"; stat -f '%Sm mod | %SB birth | %Su' \"\$p\"; xattr -l \"\$p\" 2>/dev/null
    plutil -p \"\$p\" 2>&1
    prog=\$(plutil -extract Program raw -o - \"\$p\" 2>/dev/null); [ -z \"\$prog\" ] && prog=\$(plutil -extract ProgramArguments.0 raw -o - \"\$p\" 2>/dev/null)
    if [ -n \"\$prog\" ]; then echo \"  -> program: \$prog\"; [ -e \"\$prog\" ] && { shasum -a 256 \"\$prog\"; stat -f '     %Sm mod | %SB birth | %z B' \"\$prog\"; codesign -dv \"\$prog\" 2>&1 | grep -E 'Identifier=|Authority=|TeamIdentifier=|not signed' | sed 's/^/     /'; } || echo '     (program path missing)'; fi
  done
done"
append 03_persistence_launchd "launchctl list (system/root context)" launchctl list
append 03_persistence_launchd "launchctl list (user $TARGET_USER)" sudo -u "$TARGET_USER" launchctl list
append 03_persistence_launchd "launchctl print-disabled" launchctl print-disabled system
append 03_persistence_launchd "DYLD env via launchd" bash -c 'launchctl getenv DYLD_INSERT_LIBRARIES; launchctl getenv DYLD_LIBRARY_PATH; cat /etc/launchd.conf 2>/dev/null; env | grep -i DYLD'

section 04_persistence_loginitems bash -c "
echo '--- Background Task Management (login items, agents, daemons; macOS 13+, needs root)'; sfltool dumpbtm 2>&1
echo; echo '--- System Events login items'; sudo -u '$TARGET_USER' osascript -e 'tell application \"System Events\" to get the properties of every login item' 2>&1
echo; echo '--- cron'; crontab -l -u '$TARGET_USER' 2>&1; ls -la /usr/lib/cron/tabs/ 2>&1; cat /usr/lib/cron/tabs/* 2>/dev/null; cat /etc/crontab 2>/dev/null; atq 2>&1
echo; echo '--- periodic / emond / rc'; ls -laR /etc/periodic 2>/dev/null | head -80; ls -la /etc/emond.d /etc/emond.d/rules 2>&1; cat /etc/emond.d/rules/*.plist 2>/dev/null; ls -la /etc/rc.common /etc/rc.local 2>&1
echo; echo '--- Kernel / system extensions'; kmutil showloaded --no-kernel-components 2>&1 | head -60; echo; systemextensionsctl list 2>&1
echo; echo '--- scripting additions / folder actions / quicklook / spotlight plugins'
for d in /Library/ScriptingAdditions '$UHOME/Library/ScriptingAdditions' '$UHOME/Library/Scripts' '$UHOME/Library/Application Scripts' /Library/Scripts/Folder\ Action\ Scripts '$UHOME/Library/QuickLook' /Library/QuickLook '$UHOME/Library/Spotlight' /Library/Spotlight /Library/Audio/Plug-Ins/HAL /Library/Security/SecurityAgentPlugins /Library/PrivilegedHelperTools; do [ -d \"\$d\" ] && { echo \"== \$d\"; ls -lat@ \"\$d\" | head -30; }; done
echo; echo '--- authorization db (login/screensaver mechanisms)'; security authorizationdb read system.login.console 2>/dev/null | grep -A30 mechanisms | head -40"

section 05_persistence_shellrc bash -c "
for f in '$UHOME'/.zshrc '$UHOME'/.zprofile '$UHOME'/.zshenv '$UHOME'/.zlogin '$UHOME'/.zlogout '$UHOME'/.bash_profile '$UHOME'/.bashrc '$UHOME'/.profile '$UHOME'/.bash_login '$UHOME'/.config/fish/config.fish '$UHOME'/.hushlogin '$UHOME'/.ssh/rc /etc/zshrc /etc/zprofile /etc/zshenv /etc/profile /etc/bashrc /etc/bashrc_Apple_Terminal /etc/paths /etc/ssh/sshrc; do
  [ -e \"\$f\" ] || continue; echo '==========' \"\$f\"; stat -f '%Sm mod | %SB birth | %z B' \"\$f\"; cat \"\$f\"; echo
done
echo '========== /etc/paths.d'; ls -la /etc/paths.d; cat /etc/paths.d/* 2>/dev/null
echo; echo '========== git hooks / global git config (hooksPath, credential helpers)'; sudo -u '$TARGET_USER' git config --global --list 2>&1
echo; echo '========== oh-my-zsh / custom plugins recently changed'; find '$UHOME/.oh-my-zsh' '$UHOME/.zsh' '$UHOME/.config' -type f -ctime -${DAYS}d 2>/dev/null | head -100"

section 06_browser_extensions bash -c "
for base in '$UHOME/Library/Application Support/Google/Chrome' '$UHOME/Library/Application Support/BraveSoftware/Brave-Browser' '$UHOME/Library/Application Support/Microsoft Edge' '$UHOME/Library/Application Support/Arc/User Data'; do
  [ -d \"\$base\" ] || continue
  for prof in \"\$base\"/Default \"\$base\"/Profile\ *; do
    [ -d \"\$prof/Extensions\" ] || continue
    echo '==========' \"\$prof/Extensions\"
    for e in \"\$prof\"/Extensions/*; do
      id=\$(basename \"\$e\"); v=\$(ls -t \"\$e\" | head -1); m=\"\$e/\$v/manifest.json\"
      n=\$(plutil -extract name raw -o - \"\$m\" 2>/dev/null || grep -m1 '\"name\"' \"\$m\" 2>/dev/null)
      echo \"\$(stat -f '%SB' \"\$e\")  \$id  \$v  \$n\"
    done
  done
done
echo; echo '========== Firefox'; for p in '$UHOME'/Library/Application\ Support/Firefox/Profiles/*; do [ -f \"\$p/extensions.json\" ] && { echo \"== \$p\"; grep -o '\"name\":\"[^\"]*\"' \"\$p/extensions.json\" | sort -u; }; done
echo; echo '========== Safari'; ls -la '$UHOME/Library/Safari/Extensions' 2>&1; ls -la '$UHOME/Library/Containers' 2>/dev/null | grep -i safari | head"

############################ 4. downloads / quarantine ############################
section 07_quarantine_events bash -c "
db='$UHOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'
if [ -f \"\$db\" ]; then cp \"\$db\" '$OUT/QuarantineEventsV2.sqlite' 2>/dev/null
  sqlite3 -readonly -header -list -separator ' | ' '$OUT/QuarantineEventsV2.sqlite' \"select datetime(LSQuarantineTimeStamp+978307200,'unixepoch') as utc, LSQuarantineAgentName as agent, LSQuarantineDataURLString as url, LSQuarantineOriginURLString as origin from LSQuarantineEvent where LSQuarantineTimeStamp > strftime('%s','now')-978307200-${DAYS}*86400 order by LSQuarantineTimeStamp desc;\"
  echo; echo '(NOTE: on recent macOS Chrome rows often have an empty url here; the source URL is on the file itself, see kMDItemWhereFroms in 08_downloaded_files.txt)'; echo; echo '(all-time count:)'; sqlite3 -readonly '$OUT/QuarantineEventsV2.sqlite' 'select count(*) from LSQuarantineEvent;'
else echo 'no QuarantineEventsV2 db (or no Full Disk Access)'; fi"

section 08_downloaded_files bash -c "
echo '--- files carrying com.apple.quarantine, changed in last ${DAYS}d (user dirs, tmp, shared):'
find '$UHOME/Downloads' '$UHOME/Desktop' '$UHOME/Documents' '$UHOME/Library' '$UHOME/.Trash' /tmp /private/var/tmp /private/var/folders /Users/Shared /Applications '$UHOME/Applications' ${FIND_EXCL[*]} -xattrname com.apple.quarantine \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) 2>/dev/null | grep -vE '/Application Support/(Google|BraveSoftware|Microsoft Edge|Arc|Code|Slack|zoom.us)/|/Library/(Caches|Group Containers|Containers|Preferences|Intents|Logs|HTTPStorages|WebKit)/' | while IFS= read -r f; do
  echo; stat -f '%Sm mod | %SB birth | %z B | %N' \"\$f\"
  echo \"   quarantine: \$(xattr -p com.apple.quarantine \"\$f\" 2>/dev/null)\"
  mdls -name kMDItemWhereFroms -name kMDItemDownloadedDate -name kMDItemContentType \"\$f\" 2>/dev/null | sed 's/^/   /'
  file -b \"\$f\" | sed 's/^/   type: /'
done
echo; echo '--- Spotlight: everything with a WhereFroms URL downloaded in last ${DAYS}d:'
mdfind -onlyin '$UHOME' 'kMDItemWhereFroms == \"*\" && kMDItemDownloadedDate >= \$time.now(-'\$((DAYS*86400))')' 2>/dev/null | while IFS= read -r f; do echo \"\$f\"; mdls -name kMDItemWhereFroms -name kMDItemDownloadedDate \"\$f\" 2>/dev/null | tr -s ' \n' ' ' | sed 's/^/   /'; echo; done
echo; echo '--- Downloads/ Desktop/ newest first:'; ls -lat@ '$UHOME/Downloads' | head -60; ls -lat '$UHOME/Desktop' | head -30
echo; echo '--- Trash:'; ls -lat@ '$UHOME/.Trash' 2>&1 | head -60
echo; echo '--- mounted / recently mounted disk images (dmg-based droppers):'; hdiutil info 2>&1 | grep -E 'image-path|/dev/disk' ; ls -la /Volumes"

section 09_browser_downloads bash -c "
tmp='$OUT/.browserdb'; mkdir -p \"\$tmp\"
for base in '$UHOME/Library/Application Support/Google/Chrome' '$UHOME/Library/Application Support/BraveSoftware/Brave-Browser' '$UHOME/Library/Application Support/Microsoft Edge' '$UHOME/Library/Application Support/Arc/User Data'; do
  [ -d \"\$base\" ] || continue
  for prof in \"\$base\"/Default \"\$base\"/Profile\ *; do
    [ -f \"\$prof/History\" ] || continue
    echo '==========' \"\$prof\" ; cp \"\$prof/History\" \"\$tmp/h.sqlite\"
    echo '--- downloads'; sqlite3 -readonly -header -column \"\$tmp/h.sqlite\" \"select datetime(start_time/1000000-11644473600,'unixepoch') utc, target_path, tab_url, referrer, mime_type, danger_type, state, received_bytes from downloads where start_time/1000000-11644473600 > strftime('%s','now')-${DAYS}*86400 order by start_time desc;\" 2>&1
    echo '--- download url chains'; sqlite3 -readonly -column \"\$tmp/h.sqlite\" \"select d.id, datetime(d.start_time/1000000-11644473600,'unixepoch'), u.url from downloads_url_chains u join downloads d on d.id=u.id where d.start_time/1000000-11644473600 > strftime('%s','now')-${DAYS}*86400 order by d.start_time desc, u.chain_index;\" 2>&1
    echo '--- last 300 visits'; sqlite3 -readonly -column \"\$tmp/h.sqlite\" \"select datetime(v.visit_time/1000000-11644473600,'unixepoch') utc, substr(u.url,1,160), substr(u.title,1,60) from visits v join urls u on u.id=v.url where v.visit_time/1000000-11644473600 > strftime('%s','now')-${DAYS}*86400 order by v.visit_time desc limit 300;\" 2>&1
  done
done
echo; echo '========== Safari'
[ -f '$UHOME/Library/Safari/Downloads.plist' ] && plutil -p '$UHOME/Library/Safari/Downloads.plist' 2>&1 | head -200
if cp '$UHOME/Library/Safari/History.db' \"\$tmp/s.sqlite\" 2>/dev/null; then cp '$UHOME/Library/Safari/History.db-wal' \"\$tmp/s.sqlite-wal\" 2>/dev/null
  sqlite3 -readonly -column \"\$tmp/s.sqlite\" \"select datetime(hv.visit_time+978307200,'unixepoch') utc, substr(hi.url,1,160), substr(hv.title,1,60) from history_visits hv join history_items hi on hv.history_item=hi.id where hv.visit_time+978307200 > strftime('%s','now')-${DAYS}*86400 order by hv.visit_time desc limit 300;\" 2>&1
else echo 'no Safari History.db readable (needs Full Disk Access)'; fi
echo; echo '========== Firefox'
for p in '$UHOME'/Library/Application\ Support/Firefox/Profiles/*; do [ -f \"\$p/places.sqlite\" ] || continue; cp \"\$p/places.sqlite\" \"\$tmp/f.sqlite\"; echo \"== \$p\"
  sqlite3 -readonly -column \"\$tmp/f.sqlite\" \"select datetime(a.dateAdded/1000000,'unixepoch'), p.url, a.content from moz_annos a join moz_places p on p.id=a.place_id join moz_anno_attributes n on n.id=a.anno_attribute_id where n.name like 'downloads/%' order by a.dateAdded desc limit 100;\" 2>&1
done
rm -rf \"\$tmp\""

if [ $QUICK -eq 1 ]; then echo "-- quick mode: skipping 10_recent_files and 11_recent_executables" >&2; fi
[ $QUICK -eq 0 ] && \

section 10_recent_files bash -c "
echo '--- new or changed files, last ${DAYS}d (excluding caches/dev dirs), newest first:'
find '$UHOME' /tmp /private/var/tmp /Users/Shared /usr/local /opt /Library /private/etc /Applications ${FIND_EXCL[*]} -type f \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) 2>/dev/null | grep -vE '/Library/(Caches|Logs|Metadata|Saved Application State|HTTPStorages|Cookies|WebKit|Application Support/(Slack|Code|Google|Spotify|zoom.us|Microsoft|discord|Notion|Figma|JetBrains|Cursor)/)|/\.(npm|cargo|rustup|pyenv|nvm|gradle|m2|docker|vscode|cursor)/|/Containers/|/Group Containers/' | head -3000 | while IFS= read -r f; do stat -f '%Sm|%SB|%z|%N' \"\$f\"; done | sort -r
echo; echo '--- hidden files/dirs in home (depth 2), changed last ${DAYS}d:'
find '$UHOME' -maxdepth 2 -name '.*' \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) -exec stat -f '%Sm %N' {} \; 2>/dev/null"

[ $QUICK -eq 0 ] && \

section 11_recent_executables bash -c "
echo '--- executable files (user-writable areas) changed in last ${DAYS}d, with type/signature:'
find '$UHOME' /tmp /private/var/tmp /private/var/folders /Users/Shared /usr/local/bin /usr/local/sbin /opt /Library /Applications ${FIND_EXCL[*]} -type f -perm -u+x \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) 2>/dev/null | grep -vE '/Library/(Caches|Developer)/|/\.(npm|cargo|rustup|pyenv|nvm|gradle|docker|vscode|cursor|terraform\.d)/|/Contents/(Frameworks|Resources|PlugIns|XPCServices)/|/node_modules/|/\.terraform/|/Application Support/(Google|BraveSoftware|Microsoft Edge|Arc)/' | head -1500 | while IFS= read -r f; do
  t=\$(file -b \"\$f\" | cut -c1-70)
  case \"\$t\" in *Mach-O*|*script*|*executable*) ;; *) continue;; esac
  echo; stat -f '%Sm mod | %SB birth | %z B | %N' \"\$f\"; echo \"   type: \$t\"; shasum -a 256 \"\$f\" | cut -c1-64 | sed 's/^/   sha256: /'
  xattr -p com.apple.quarantine \"\$f\" 2>/dev/null | sed 's/^/   quarantine: /'
  case \"\$t\" in *Mach-O*) codesign -dv \"\$f\" 2>&1 | grep -E 'Identifier=|Authority=|TeamIdentifier=|not signed|adhoc' | head -4 | sed 's/^/   sign: /';; esac
done
echo; echo '--- Applications by birth/change time (newest first):'; ls -latc /Applications | head -30; ls -latc '$UHOME/Applications' 2>/dev/null | head
echo; echo '--- apps added in last ${DAYS}d:'; find /Applications '$UHOME/Applications' /Library/Application\ Support -maxdepth 3 -name '*.app' -Btime -${DAYS}d 2>/dev/null | while IFS= read -r a; do stat -f '%SB %N' \"\$a\"; codesign -dv \"\$a\" 2>&1 | grep -E 'Authority=|not signed' | head -1 | sed 's/^/   /'; done"

section 12_installed_software bash -c "
echo '--- pkg receipts by install time (newest first):'
for p in \$(pkgutil --pkgs 2>/dev/null); do t=\$(pkgutil --pkg-info \"\$p\" 2>/dev/null | awk '/install-time/{print \$2}'); [ -n \"\$t\" ] && echo \"\$t \$(date -r \"\$t\" '+%F %T') \$p\"; done | sort -rn | head -60 | cut -d' ' -f2-
echo; echo '--- /var/db/receipts newest:'; ls -lat /var/db/receipts 2>/dev/null | head -30
echo; echo '--- install history (system_profiler):'; system_profiler SPInstallHistoryDataType 2>/dev/null | grep -B1 -A4 \"Install Date: \" | head -200
echo; echo '--- homebrew:'; for h in /opt/homebrew /usr/local; do [ -d \"\$h/Cellar\" ] && { echo \"== \$h\"; ls -latc \"\$h/Cellar\" | head -20; ls -latc \"\$h/Caskroom\" 2>/dev/null | head -20; }; done
echo; echo '--- python/pip/npm global recently touched:'; ls -lat '$UHOME/Library/Python' 2>/dev/null | head; ls -lat /opt/homebrew/lib/node_modules 2>/dev/null | head
echo; echo '--- /var/log/install.log, last ${DAYS}d:'; awk -v d=\"\$(date -v-${DAYS}d '+%Y-%m-%d')\" '\$1 >= d' /var/log/install.log 2>/dev/null | tail -400"

############################ 5. processes / network ############################
section 13_processes bash -c "
echo '--- all processes:'; ps axo pid,ppid,user,lstart,%cpu,%mem,stat,command
echo; echo '--- processes NOT running from system/app locations (worth a look):'
ps axo pid,ppid,user,lstart,command | awk 'NR>1 && \$0 !~ /\\/(System|usr\\/(bin|sbin|libexec)|sbin|bin|Applications|Library\\/Apple|opt\\/homebrew|usr\\/local)\\//'
echo; echo '--- unique executables of running processes: hash + signature:'
ps axo command= | awk '{print \$1}' | grep '^/' | sort -u | grep -vE '^/(System|usr/libexec|usr/bin|usr/sbin|bin|sbin)/' | while IFS= read -r b; do
  [ -f \"\$b\" ] || continue; echo; echo \"\$b\"; shasum -a 256 \"\$b\" | cut -c1-64 | sed 's/^/   sha256: /'; stat -f '   %Sm mod | %SB birth' \"\$b\"
  codesign -dv \"\$b\" 2>&1 | grep -E 'Identifier=|Authority=|TeamIdentifier=|not signed' | head -3 | sed 's/^/   /'
done
echo; echo '--- open files of shell/script interpreters (what are they running?):'
for pid in \$(ps axo pid=,comm= | awk '\$2 ~ /(bash|zsh|sh|python|perl|ruby|osascript|node|curl|nc|ncat|socat|screen|tmux)\$/ {print \$1}'); do echo \"== pid \$pid: \$(ps -o command= -p \$pid)\"; lsof -p \$pid 2>/dev/null | awk '\$4==\"cwd\" || \$4==\"txt\" || \$5==\"REG\" {print \"   \"\$4, \$NF}' | sort -u | head -15; done"

section 14_network bash -c "
echo '--- listening + established (lsof):'; lsof -nP -i 2>&1
echo; echo '--- netstat -anv (with pids):'; netstat -anv 2>&1 | grep -E 'LISTEN|ESTABLISHED|udp' | head -200
echo; echo '--- DNS:'; scutil --dns 2>&1 | grep -E 'nameserver|domain|resolver' | head -30; cat /etc/resolv.conf 2>&1
echo; echo '--- /etc/hosts:'; cat /etc/hosts
echo; echo '--- proxies per network service:'; networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | while IFS= read -r s; do echo \"== \$s\"; networksetup -getdnsservers \"\$s\" 2>&1; networksetup -getwebproxy \"\$s\" 2>&1 | grep -E 'Enabled|Server'; networksetup -getsecurewebproxy \"\$s\" 2>&1 | grep -E 'Enabled|Server'; networksetup -getautoproxyurl \"\$s\" 2>&1; done
echo; echo '--- VPN / network configs:'; scutil --nc list 2>&1
echo; echo '--- pf rules:'; pfctl -s rules 2>&1 | head -40
echo; echo '--- tailscale:'; command -v tailscale >/dev/null && tailscale status 2>&1 | head -40; /Applications/Tailscale.app/Contents/MacOS/Tailscale status 2>/dev/null | head -40
echo; echo '--- ssh:'; ls -la '$UHOME/.ssh' 2>&1; echo '== authorized_keys:'; cat '$UHOME/.ssh/authorized_keys' 2>/dev/null; echo '== config:'; cat '$UHOME/.ssh/config' 2>/dev/null; echo '== sshd enabled?:'; systemsetup -getremotelogin 2>&1; launchctl print system/com.openssh.sshd 2>&1 | head -3
echo; echo '--- screen sharing / remote mgmt:'; launchctl print system/com.apple.screensharing 2>&1 | head -3; ls -la /Library/Preferences/com.apple.RemoteManagement.plist 2>&1
echo; echo '--- wifi known networks (recent):'; ls -la /Library/Preferences/com.apple.wifi.known-networks.plist 2>&1; tail -200 /var/log/wifi.log 2>/dev/null | grep -iE 'join|assoc' | tail -30"

############################ 6. privacy / permissions / handlers ############################
section 15_tcc_permissions bash -c "
q=\"select datetime(last_modified,'unixepoch') utc, service, client, client_type, auth_value, auth_reason from access order by last_modified desc;\"
for db in '$UHOME/Library/Application Support/com.apple.TCC/TCC.db' /Library/Application\ Support/com.apple.TCC/TCC.db; do
  echo '==========' \"\$db\"; cp \"\$db\" '$OUT/.tcc.sqlite' 2>/dev/null && sqlite3 -readonly -header -column '$OUT/.tcc.sqlite' \"\$q\" 2>&1 || echo 'not readable (needs root + Full Disk Access)'
done; rm -f '$OUT/.tcc.sqlite'
echo; echo '(auth_value 2 = allowed. Look for kTCCServiceScreenCapture, Accessibility, SystemPolicyAllFiles, Microphone, Camera, AppleEvents granted to anything unexpected.)'
echo; echo '--- LaunchServices handlers (default app for pdf/http etc.):'; plutil -p '$UHOME/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist' 2>&1 | grep -E 'LSHandlerURLScheme|LSHandlerContentType|LSHandlerRole|LSHandlerContentTag' | paste - - 2>/dev/null | head -80
echo; echo '--- keychains:'; sudo -u '$TARGET_USER' security list-keychains 2>&1; ls -lat '$UHOME/Library/Keychains' 2>&1 | head"

############################ 7. logs ############################
section 16_shell_history bash -c "
conv() { while IFS= read -r line; do if [[ \"\$line\" =~ ^:\\ ([0-9]+):[0-9]+\;(.*)\$ ]]; then echo \"\$(date -r \"\${BASH_REMATCH[1]}\" '+%F %T') \${BASH_REMATCH[2]}\"; else echo \"                    \$line\"; fi; done; }
for h in '$UHOME'/.zsh_history '$UHOME'/.bash_history '$UHOME'/.sh_history /var/root/.zsh_history /var/root/.bash_history; do [ -f \"\$h\" ] && { echo '==========' \"\$h\" \"(\$(stat -f '%Sm' \"\$h\"))\"; tail -n 2000 \"\$h\" | conv; echo; }; done
echo '========== .zsh_sessions (per-terminal history, newest first)'; ls -lat '$UHOME/.zsh_sessions' 2>/dev/null | head -20
for s in \$(ls -t '$UHOME'/.zsh_sessions/*.history 2>/dev/null | head -10); do echo \"--- \$s (\$(stat -f '%Sm' \"\$s\"))\"; tail -n 60 \"\$s\" | conv; done
for h in .python_history .node_repl_history .irb_history .mysql_history .psql_history .lesshst .viminfo; do [ -f \"$UHOME/\$h\" ] && { echo \"========== $UHOME/\$h\"; tail -n 50 \"$UHOME/\$h\"; }; done
echo; echo '========== Terminal / iTerm saved state'; ls -lat '$UHOME/Library/Saved Application State/com.apple.Terminal.savedState' 2>/dev/null | head"

section 17_crash_and_app_logs bash -c "
echo '--- crash / diagnostic reports last ${DAYS}d (exploited viewers crash):'; find /Library/Logs/DiagnosticReports '$UHOME/Library/Logs/DiagnosticReports' -type f -mtime -${DAYS}d 2>/dev/null -exec stat -f '%Sm %N' {} \; | sort -r | head -60
echo; echo '--- ~/Library/Logs newest:'; ls -lat '$UHOME/Library/Logs' 2>/dev/null | head -30
echo; echo '--- /var/log newest:'; ls -lat /var/log 2>/dev/null | head -30
echo; echo '--- system.log tail:'; tail -200 /var/log/system.log 2>/dev/null
echo; echo '--- Adobe Reader / Preview recent files:'; plutil -p '$UHOME/Library/Preferences/com.apple.Preview.plist' 2>/dev/null | head -40; ls -lat '$UHOME/Library/Application Support/Adobe/Acrobat' 2>/dev/null | head"


LOGW="$LOGWIN"
# ONE unified-log scan with a union predicate (the scan cost is the window size, not the predicate), then split with grep.
UNION='(process == "launchd" AND eventMessage CONTAINS "added unmanaged") OR process == "sudo" OR eventMessage CONTAINS "display dialog" OR eventMessage CONTAINS "curl " OR eventMessage CONTAINS "chmod +x" OR eventMessage CONTAINS "nohup" OR eventMessage CONTAINS "base64 -" OR eventMessage CONTAINS "python3 -c" OR eventMessage CONTAINS "bash -c" OR (process == "syspolicyd" AND (eventMessage CONTAINS "GK" OR eventMessage CONTAINS "assessment" OR eventMessage CONTAINS "Gatekeeper" OR eventMessage CONTAINS "blocked" OR eventMessage CONTAINS "malware" OR eventMessage CONTAINS "quarantine" OR eventMessage CONTAINS "notariz")) OR (process BEGINSWITH "XProtect" AND (eventMessage CONTAINS "detect" OR eventMessage CONTAINS "remediat" OR eventMessage CONTAINS "malware" OR eventMessage CONTAINS "XPEvent")) OR process == "XProtectRemediator" OR subsystem == "com.apple.backgroundtaskmanagement" OR (process == "launchd" AND (eventMessage CONTAINS "LaunchAgents" OR eventMessage CONTAINS "LaunchDaemons")) OR (subsystem == "com.apple.TCC" AND (eventMessage CONTAINS "Granting" OR eventMessage CONTAINS "AUTHREQ_RESULT" OR eventMessage CONTAINS "Handling access request" OR eventMessage CONTAINS "Override" OR eventMessage CONTAINS "update access record" OR eventMessage CONTAINS "Prompting policy for hardened runtime; service")) OR process == "sshd" OR process == "sshd-session" OR process == "screensharingd" OR (process == "SecurityAgent" AND subsystem == "com.apple.Authorization") OR process BEGINSWITH "Adobe" OR eventMessage CONTAINS[c] ".pdf" OR (subsystem == "com.apple.Authorization" AND (eventMessage CONTAINS "Succeeded authorizing right" OR eventMessage CONTAINS "Failed to authorize right" OR eventMessage CONTAINS "AgentMechanism invoked" OR eventMessage CONTAINS "FVUnlock" OR eventMessage CONTAINS "SecurityAgent start")) OR (process == "opendirectoryd" AND (eventMessage CONTAINS "Authentication failed" OR eventMessage CONTAINS "Invalid password" OR eventMessage CONTAINS[c] "failed to authenticate")) OR (process == "loginwindow" AND (eventMessage CONTAINS "USER_PROCESS" OR eventMessage CONTAINS "DEAD_PROCESS" OR eventMessage CONTAINS "LoginHook" OR eventMessage CONTAINS "loginIsComplete" OR eventMessage CONTAINS "inform UA unlocked" OR eventMessage CONTAINS "userSwitched" OR eventMessage CONTAINS "activateForUserName" OR eventMessage CONTAINS[c] "logout" OR eventMessage CONTAINS "AutoUnlock state:3" OR eventMessage CONTAINS "Watch unlock")) OR (process == "coreauthd" AND eventMessage CONTAINS "evaluatePolicy:") OR (process IN {"su","login"} AND NOT (eventMessage BEGINSWITH "Retrieve" OR eventMessage BEGINSWITH "Membership" OR eventMessage BEGINSWITH "Open a given" OR eventMessage BEGINSWITH "Copy " OR subsystem == "com.apple.xpc")) OR (subsystem == "com.apple.authkit" AND category != "signpost" AND (eventMessage CONTAINS[c] "sign in" OR eventMessage CONTAINS[c] "signin" OR eventMessage CONTAINS[c] "password")) OR (process IN {"python3","python","perl","ruby","node","osascript","automator","shortcuts","Script Editor","sh","bash","zsh","curl","wget","nc"} AND NOT (eventMessage BEGINSWITH "Retrieve" OR eventMessage BEGINSWITH "Membership" OR subsystem == "com.apple.xpc" OR subsystem == "com.apple.CFPreferences" OR subsystem == "com.apple.network" OR subsystem == "com.apple.defaults" OR subsystem == "com.apple.CoreAnalytics"))'
echo "-- unified log scan (window $LOGW; this is the slow step)" >&2
ALL="$OUT/18_unifiedlog_ALL.txt"; ALLB="$OUT/.18_body.txt"
{ echo "### unified log, --last $LOGW, union predicate:"; echo "### $UNION"; echo; /usr/bin/log show --last "$LOGW" --style compact --info --predicate "$UNION" 2>&1; echo "[exit=$?]"; } > "$ALL"; grep -v "^###" "$ALL" > "$ALLB"
split_log() { # name "title" egrep-pattern [exclude-pattern]
  local name="$1" title="$2" pat="$3" excl="${4:-__none__}"
  { echo "### $name  ($title)  window=$LOGW  source=18_unifiedlog_ALL.txt"; echo; grep -E "$pat" "$ALLB" | grep -vE "$excl"; } > "$OUT/$name.txt"
}
{ echo "### 18_unifiedlog_execution  window=$LOGW"; echo
  echo "--- process spawn timeline (launchd 'added unmanaged': every GUI-session process start, name truncated to 15 chars)"
  grep 'added unmanaged' "$ALLB" | sed -E 's/^([0-9-]+ [0-9:.]+).*unmanaged\.(.*)\.([0-9]+) \[[0-9]+\]:.*/\1  pid=\3  \2/' 
  echo; echo "--- spawn counts by name:"; grep 'added unmanaged' "$ALLB" | sed -E 's/.*unmanaged\.(.*)\.[0-9]+ \[.*/\1/' | sort | uniq -c | sort -rn
  echo; echo "--- osascript / display dialog (password-prompt stealers) / curl|sh / chmod +x / nohup / base64 / inline python|bash:"
  grep -E 'osascript|display dialog|curl |chmod \+x|nohup|base64 -|python3 -c|bash -c' "$ALLB" | grep -vE 'replicatord|libsystem_info|added unmanaged|service inactive|removing inactive|xpc:connection|CoreAnalytics|CarbonCore|xprotect:xprotect|CFPrefs|Preferences From|com.apple.log:'
  echo; echo "--- osascript asking TCC for Apple Events / System Events control (fake password dialogs do this):"; grep -E "tccd\[.*osascript|osascript.*kTCCService" "$ALLB"
  echo; echo "--- sudo (TTY/COMMAND lines = commands run as root):"; grep -E ' sudo\[' "$ALLB" | grep -vE 'Reading config|libsystem_info|Retrieve Group|Too many groups'
} > "$OUT/18_unifiedlog_execution.txt"
split_log 19_unifiedlog_gatekeeper "Gatekeeper / XProtect assessments, blocks, detections" 'syspolicyd\[|XProtect|Xprotect' 'activating connection|invalidated after|bootstrap look-up|Got an event in libXPP|Newer ticket'
split_log 20_unifiedlog_persistence "Background Task Management + launchd agent/daemon loads" 'backgroundtaskmanagement|BTM|LaunchAgents|LaunchDaemons' 'added unmanaged|service inactive|removing inactive'
split_log 21_unifiedlog_tcc_prompts "TCC permission prompts/grants" 'TCC|tccd\['
split_log 22_unifiedlog_auth_remote "ssh / screen sharing / auth agent" ' (sshd|sshd-session|screensharingd|SecurityAgent)\['
split_log 23_unifiedlog_pdf_opens "PDF handling and Adobe processes" '\.pdf|\.PDF|Adobe'
# $ALLB (log body) is kept until sections 27/28 and 31 have read it; removed after section 31.

############################ 8. credential exposure inventory (names + times only) ############################
section 24_credential_files bash -c "
echo '--- what an infostealer would take (existence, size, mtime, atime). Values are NOT read.'
for f in .aws/credentials .aws/config .aws/sso/cache .ssh/id_rsa .ssh/id_ed25519 .ssh/id_ecdsa .ssh/known_hosts .kube/config .config/gh/hosts.yml .config/gcloud/credentials.db .config/gcloud/access_tokens.db .docker/config.json .npmrc .netrc .pypirc .gnupg .terraform.d/credentials.tfrc.json .tailscale .config/tailscale .vault-token .gitconfig .git-credentials .env .zsh_history .bash_history .config/op .1password .config/Code/User/globalStorage .cursor .claude/.credentials.json .claude .config/configstore .local/share/keyrings .config/slack .config/argocd/config .azure/accessTokens.json .boto .s3cfg 'Library/Keychains' 'Library/Application Support/Google/Chrome/Default/Login Data' 'Library/Application Support/Google/Chrome/Default/Cookies' 'Library/Application Support/Google/Chrome/Default/Network/Cookies' 'Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data' 'Library/Application Support/Firefox/Profiles' 'Library/Cookies' 'Library/Application Support/Slack' 'Library/Application Support/discord' 'Library/Application Support/Telegram Desktop' 'Library/Group Containers/group.com.apple.notes' 'Library/Containers/com.apple.Notes'; do
  p=\"$UHOME/\$f\"; [ -e \"\$p\" ] && stat -f '%z B | mod %Sm | acc %Sa | %N' \"\$p\"
done
echo; echo '--- .env files in home (names only):'; find '$UHOME' ${FIND_EXCL[*]} -maxdepth 5 -name '.env*' -type f 2>/dev/null | head -50
echo; echo '--- AWS profiles (names only):'; grep -E '^\[' '$UHOME/.aws/credentials' '$UHOME/.aws/config' 2>/dev/null
echo; echo '--- kube contexts:'; grep -E '^\s+name:|server:' '$UHOME/.kube/config' 2>/dev/null | head -40
echo; echo '--- gh hosts:'; grep -E 'user:|git_protocol' '$UHOME/.config/gh/hosts.yml' 2>/dev/null"

############################ 9. suspect files (auto-discovered, plus -p) ############################
analyse_file() { # path -> appended to 25_suspect_files.txt
  local f="$1" out="$OUT/25_suspect_files.txt"
  {
    echo; echo "=================================================================="
    echo "FILE: $f"
    stat -f '%z B | mod %Sm | birth %SB | acc %Sa | %Su' "$f"
    echo "--- type:"; file -b "$f"
    echo "--- hashes (search sha256 on VirusTotal; do NOT upload a file that may hold company data):"; shasum -a 256 "$f" | cut -c1-64; md5 -q "$f"
    echo "--- quarantine record (agent;origin):"; xattr -p com.apple.quarantine "$f" 2>/dev/null || echo "(none)"
    echo "--- spotlight metadata (where from, download date, last opened, open count):"
    mdls -name kMDItemWhereFroms -name kMDItemDownloadedDate -name kMDItemContentType -name kMDItemLastUsedDate -name kMDItemUseCount -name kMDItemCreator -name kMDItemAuthors -name kMDItemTitle "$f" 2>/dev/null
    case "$(file -b "$f")" in
      *PDF*)
        echo "--- PDF version/trailer:"; head -c 64 "$f" | strings | head -1; tail -c 200 "$f" | strings | tail -3
        echo "--- active-content keyword counts (non-zero /JS /JavaScript /OpenAction /AA /Launch /EmbeddedFile /XFA /RichMedia = suspicious):"
        for k in /JS /JavaScript /OpenAction /AA /Launch /EmbeddedFile /EmbeddedFiles /URI /SubmitForm /GoToR /GoToE /RichMedia /AcroForm /XFA /ObjStm /Encrypt /JBIG2Decode; do printf '   %-16s %s\n' "$k" "$(grep -a -c -F -- "$k" "$f")"; done
        command -v qpdf >/dev/null && { echo "--- qpdf --check:"; qpdf --check "$f" 2>&1 | head -10; } ;;
      *Mach-O*|*executable*)
        echo "--- !!! EXECUTABLE disguised as a download. codesign:"; codesign -dvv "$f" 2>&1 | head -8
        echo "--- linked libs:"; otool -L "$f" 2>/dev/null | head -20 ;;
      *"disk image"*|*DMG*|*"Apple Disk Image"*|*zlib*|*bzip2*)
        echo "--- disk image (NOT mounted). hdiutil imageinfo:"; hdiutil imageinfo "$f" 2>&1 | grep -E 'Format|Checksum|Size Information' -A1 | head -12 ;;
      *Zip*|*zip*)
        echo "--- archive listing:"; unzip -l "$f" 2>&1 | head -40 ;;
      *xar*|*"installer"*)
        echo "--- pkg contents + scripts (NOT installed):"; pkgutil --payload-files "$f" 2>/dev/null | head -40; xar -t -f "$f" 2>/dev/null | grep -iE 'script|preinstall|postinstall' | head ;;
      *script*|*text*)
        echo "--- first 60 lines:"; head -60 "$f" ;;
    esac
    echo "--- URLs embedded:"; strings -n 8 "$f" | grep -aoE '(https?|ftp|file|smb)://[^ )>"<\\]+' | sort -u | head -60
    echo "--- suspicious strings:"; strings -n 6 "$f" | grep -aiE 'osascript|/bin/(ba)?sh|curl |wget |base64|chmod|launchctl|\.app/|\.dmg|\.pkg|powershell|cmd\.exe|eval\(|unescape|fromCharCode|app\.launchURL|exportDataObject|util\.printf|display dialog|do shell script|administrator privileges' | head -30
  } >> "$out" 2>&1
}
{ echo "### 25_suspect_files  window=${DAYS}d"; echo "### every quarantined download (pdf/dmg/pkg/zip/app/script/...) in Downloads, Desktop, Documents, Mail attachments and tmp from the last ${DAYS}d, plus any -p file. Nothing is opened, mounted or installed."; } > "$OUT/25_suspect_files.txt"
n=0
[ -n "$SUSPECT" ] && { if [ -e "$SUSPECT" ]; then echo "-- analysing -p $SUSPECT" >&2; analyse_file "$SUSPECT"; n=$((n+1)); else echo "!! -p file not found: $SUSPECT" | tee -a "$OUT/25_suspect_files.txt" >&2; fi; }
echo "-- 25_suspect_files (auto-discovery)" >&2
find "$UHOME/Downloads" "$UHOME/Desktop" "$UHOME/Documents" "$UHOME/Library/Mail" "$UHOME/Library/Containers/com.apple.mail/Data/Library/Mail Downloads" "$UHOME/Library/Messages/Attachments" /tmp /private/var/tmp /Users/Shared -maxdepth 4 -type f \
  \( -iname '*.pdf' -o -iname '*.dmg' -o -iname '*.pkg' -o -iname '*.mpkg' -o -iname '*.zip' -o -iname '*.rar' -o -iname '*.7z' -o -iname '*.iso' -o -iname '*.jar' -o -iname '*.sh' -o -iname '*.command' -o -iname '*.scpt' -o -iname '*.applescript' -o -iname '*.py' -o -iname '*.js' -o -iname '*.html' -o -iname '*.htm' -o -iname '*.docm' -o -iname '*.xlsm' -o -iname '*.doc' -o -iname '*.docx' -o -iname '*.xls' -o -iname '*.xlsx' -o -iname '*.ppt*' -o -iname '*.lnk' -o -iname '*.exe' -o -iname '*.terminal' -o -iname '*.webloc' -o -iname '*.inetloc' \) \
  \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) 2>/dev/null | head -40 | while IFS= read -r f; do
    [ -n "$SUSPECT" ] && [ "$f" = "$SUSPECT" ] && continue
    analyse_file "$f"
done
echo "--- apps/bundles downloaded in window (quarantined .app):" >> "$OUT/25_suspect_files.txt"
find "$UHOME/Downloads" "$UHOME/Desktop" "$UHOME/Applications" /Applications /Users/Shared /tmp -maxdepth 3 -name '*.app' -xattrname com.apple.quarantine \( -ctime -${DAYS}d -o -Btime -${DAYS}d \) 2>/dev/null | while IFS= read -r a; do
  { echo; echo "APP: $a"; stat -f '%SB birth | %Sm mod' "$a"; xattr -p com.apple.quarantine "$a" 2>/dev/null; mdls -name kMDItemWhereFroms "$a" 2>/dev/null; codesign -dvv "$a" 2>&1 | grep -E 'Identifier=|Authority=|TeamIdentifier=|not signed' | head -4; } >> "$OUT/25_suspect_files.txt"
done

############################ 11. detection sections (26-30) ############################
# Helpers shared by sections 26-30. bash 3.2 compatible: no associative arrays, mapfile or ${var,,}.
HAVE_CLT=0; xcode-select -p >/dev/null 2>&1 && HAVE_CLT=1   # /usr/bin/strings and otool are Command Line Tools shims
# sig_of PATH -> one word/line: unsigned | adhoc | Apple | TeamIdentifier=... Authority=...
sig_of() {
  local o; o=$(codesign -dvv "$1" 2>&1)
  case "$o" in
    *"not signed at all"*) echo unsigned; return;;
    *"Signature=adhoc"*) echo adhoc; return;;
  esac
  local tid auth; tid=$(printf '%s\n' "$o" | grep -m1 '^TeamIdentifier=' | cut -d= -f2); auth=$(printf '%s\n' "$o" | grep -m1 '^Authority=' | cut -d= -f2-)
  case "$auth" in "Software Signing"|"macOS Software Signing"|"Apple Mac OS Application Signing"|"Apple iPhone OS Application Signing"|"Apple Software") echo "Apple ($auth)"; return;; esac
  [ -z "$auth" ] && { echo "unknown"; return; }
  echo "TeamIdentifier=${tid:-?} Authority=$auth"
}
# hist_conv: zsh EXTENDED_HISTORY lines -> "YYYY-mm-dd HH:MM:SS cmd"
hist_conv() {
  local line re='^: ([0-9]+):[0-9]+;(.*)$'
  while IFS= read -r line; do
    if [[ "$line" =~ $re ]]; then echo "$(date -r "${BASH_REMATCH[1]}" '+%F %T') ${BASH_REMATCH[2]}"; else echo "                    $line"; fi
  done
}
# user_homes: every real home dir (UID >= 500) plus root's
user_homes() {
  local h; for h in /Users/*; do [ -d "$h" ] || continue; case "$h" in /Users/Shared|/Users/Guest) continue;; esac; echo "$h"; done; [ -d /var/root ] && echo /var/root
}
# recent_machos: executable files in user-writable, non-app locations changed in the window (bounded; same exclusions as section 11)
USERWRITABLE_DIRS=( "$UHOME/Library" "$UHOME/Applications" "$UHOME/Downloads" "$UHOME/Desktop" "$UHOME/Documents" "$UHOME/Public" /tmp /private/var/tmp /private/var/folders /Users/Shared )
recent_machos() {
  find "${USERWRITABLE_DIRS[@]}" "${FIND_EXCL[@]}" -not -path "$OUT/*" -not -path '/Users/Shared/triage-*' -type f -perm -u+x \( -ctime -"${DAYS}"d -o -Btime -"${DAYS}"d \) 2>/dev/null \
   | grep -vE '/Library/(Caches|Developer|pnpm)/|/\.(npm|cargo|rustup|pyenv|nvm|gradle|docker|vscode|cursor|terraform\.d|pnpm)/|/triage[^/]*/|/Contents/(Frameworks|Resources|PlugIns|XPCServices)/|/node_modules/|/\.terraform/|/Application Support/(Google|BraveSoftware|Microsoft Edge|Arc)/|/triage[^/]*/' \
   | head -800 | while IFS= read -r f; do case "$(file -b "$f" 2>/dev/null | cut -c1-40)" in *Mach-O*) echo "$f";; esac; done | head -300
}

############################ 26. malware IOC sweep ############################
# Offline indicator list. One entry per line:  family|kind|note|pattern   (pattern LAST because regexes contain '|'; note must not)
#   kind=path   : filesystem glob; a leading ~ is expanded to EVERY user home (and /var/root). Hit = exists.
#   kind=label  : regex against launchd plist file names, Label values and `launchctl list` (all users, /Library, not /System)
#   kind=proc   : regex against `ps axo command`
#   kind=str    : regex against the text corpus = launchd plists (plutil -p), shell rc files, cron, /etc/periodic, small scripts/plists in tmp dirs
#   kind=hist   : regex against every user's shell history (ClickFix-style paste lures)
#   kind=bin    : regex against `strings` of recent Mach-O files in user-writable dirs (C2 frameworks, stealer code)
#   kind=app    : regex against .app bundle names in /Applications, ~/Applications, ~/Downloads, ~/Desktop, /Users/Shared, /tmp
#   kind=ext    : Chrome-family extension ID (32 chars a-p) present in any profile's Extensions dir
# IOCs go stale: these are drawn from public vendor reporting up to late 2025. Add a line, keep the format, re-run.
# No extension IDs are bundled: the public ones rotate too fast to be worth hard-coding; add kind=ext rows from your own intel.
ioc_list() { cat <<'IOCS'
# --- Atomic macOS Stealer (AMOS) and its 2025 backdoor variant, plus clones sold on the same model ---
AMOS/Atomic|path|password captured by the fake dialog is cached here|/tmp/.pass
AMOS/Atomic|path|backdoor binary (hidden)|~/Library/Application Support/.helper
AMOS/Atomic|path|wrapper script that loops the backdoor|~/Library/Application Support/.agent
AMOS/Atomic|path|backdoor binary, system-wide variant|/Library/Application Support/.helper
AMOS/Atomic|label|LaunchDaemon label used by the backdoor variant|com\.finder\.helper
AMOS/Atomic|str|password-prompt lure text|macOS needs to access System Settings
AMOS/Atomic|str|password-prompt lure text (also Poseidon)|Required Application Helper
AMOS/Atomic|str|lure text|To launch the application, you need to update the system settings
AMOS/Atomic|hist|lure text pasted into Terminal|macOS needs to access System Settings
AMOS/Atomic|bin|self-identifying string in some builds|Atomic[ _]Stealer
Poseidon|bin|AMOS fork sold as Poseidon (not the Mythic agent)|[Pp]oseidon[ _]?[Ss]tealer
Poseidon|str|Poseidon dialog text|Required Application Helper\.
Cuckoo|app|trojanised "music converter" brands that carried Cuckoo (verify signature; some brands are also legit)|^(DumpMedia|TunesFun|TuneSolo|FoneDog|TunesKit|Tunes ?Fun).*\.app$
Cuckoo|bin||Cuckoo[ _]?Stealer
Banshee|bin||[Bb]anshee[ _]?[Ss]tealer
Banshee|str||Banshee
MacSync|proc|2025 stealer process name|MacSync
MacSync|bin||MacSync
Cthulhu|path|Cthulhu Stealer staging directory|/Users/Shared/NW
Cthulhu|bin||[Cc]thulhu
MacStealer|bin||[Mm]ac[Ss]tealer
Realst|bin|Rust stealer shipped inside fake games|[Rr]ealst
Realst|app|fake-game brands that carried Realst|^(Brawl Earth|WildWorld|Dawnland|Destruction|Evolion|Pearl|Olymp of Reptiles|SaintLegend|RyzeX)\.app$
# --- adware / bundlers (mostly LaunchAgent + hidden dir under Application Support) ---
Adload|path|hidden dir with a Services/*.app helper = classic Adload layout|~/Library/Application Support/.*/Services/*.app
Adload|path|system-wide Adload layout|/Library/Application Support/.*/Services/*.app
Adload|path|Adload daemon layout|/Library/Application Support/.*/*.system
Adload|label|LaunchAgent label ending in .service is the Adload pattern (check the program path)|\.service$
Shlayer|str|Shlayer stage-1 shell script decrypts its payload with openssl|openssl enc -aes-256-cbc
Shlayer|str|random-named script in /tmp|/tmp/[A-Za-z0-9]{8,}\.(sh|command)
Bundlore|path|Bundlore installer dir|~/Library/Application Support/mm-install-macos*
Bundlore|str||mm-install-macos
Pirrit|str||[Pp]irrit
Pirrit|path||/Library/Pirrit*
Pirrit|path||~/Library/Application Support/*Pirrit*
Genieo|path||/Library/Application Support/Genieo*
Genieo|path||~/Library/Application Support/Genieo*
Genieo|path||/Applications/Genieo.app
Genieo|path||/Applications/Uninstall Genieo.app
Genieo|path||/Applications/InstallMac.app
Genieo|label|also matches com.genieoinnovation.*|com\.genieo
# --- XCSSET (developer-targeting; zsh and Xcode project injection) ---
XCSSET|path|XCSSET 2025 variant persists by sourcing this file from .zshrc|~/.zshrc_aliases
XCSSET|str||\.zshrc_aliases
XCSSET|path|real Launchpad lives in /System/Applications; a copy here is the XCSSET dock hijack|/Applications/Launchpad.app
# --- DPRK: RustBucket, KandyKorn/SugarLoader, BeaverTail/InvisibleFerret (Contagious Interview, npm/node based) ---
RustBucket|label|LaunchAgent label used by RustBucket stage 3|com\.apple\.systemupdate
RustBucket|path|RustBucket persisted binary|~/Library/Metadata/System Update
RustBucket|app|RustBucket stage 2|^Internal PDF Viewer\.app$
KandyKorn|path|SugarLoader artefacts (partial list)|/Users/Shared/.sld
KandyKorn|path||~/Library/Application Support/*/.sld
KandyKorn|path||~/Library/Application Support/discord/.sld
BeaverTail|path|BeaverTail/InvisibleFerret working dirs|~/.n2
BeaverTail|path||~/.n3
BeaverTail|path|InvisibleFerret python payload|~/.npl
BeaverTail|path|bundled python runtime|~/.pyp
BeaverTail|proc|interpreter running from a hidden DPRK dir|(node|python[0-9.]*) .*/\.(n2|n3|npl|pyp)/
BeaverTail|str||/\.(n2|npl|pyp)/
BeaverTail|hist||/\.(n2|npl|pyp)/
# --- other backdoors / spyware ---
JokerSpy|path||/Users/Shared/AppleAccount.tmp
JokerSpy|path||/Users/Shared/xcc
JokerSpy|path||/Users/Shared/sh.py
ChromeLoader|str|LaunchAgent that starts Chrome with a sideloaded extension|--load-extension=
SilverSparrow|path||~/Library/._insu
SilverSparrow|path||/tmp/agent.sh
SilverSparrow|path||/tmp/version.json
SilverSparrow|path||/tmp/version.plist
SilverSparrow|path||~/Library/Application Support/agent_updater
SilverSparrow|path||~/Library/Application Support/verx_updater
SilverSparrow|label||init_(verx|agent)
Dacls|path|Lazarus Dacls RAT|~/Library/.mina
Dacls|label||com\.aex-loop\.agent
# --- ClickFix / ClearFake style "paste this into Terminal" lures (what the victim typed) ---
ClickFix|hist|decode-and-pipe-to-shell|base64 +(-d|-D|--decode)[^|]{0,160}\|[[:space:]]*(/bin/)?(ba|z)?sh([[:space:]]|$|;|"|')
ClickFix|hist|curl piped straight into a shell|curl +-[A-Za-z]*s[A-Za-z]* +[^|]{0,160}\|[[:space:]]*(/bin/)?(ba|z)?sh([[:space:]]|$|;|"|')
ClickFix|hist||wget +[^|]{0,160}\|[[:space:]]*(/bin/)?(ba|z)?sh([[:space:]]|$|;|"|')
ClickFix|hist|download-and-run one-liner|/bin/(ba|z)?sh -c ["']?\$\(curl
ClickFix|hist|inline base64 blob decoded in the shell|echo +[A-Za-z0-9+/=]{40,} *\| *base64
ClickFix|hist|instruction to strip quarantine (Gatekeeper bypass)|xattr +-[a-z]*[cd][a-z]* +.*com\.apple\.quarantine
ClickFix|hist|strip all xattrs (Gatekeeper bypass)|xattr +-c[r]? +
ClickFix|hist|Gatekeeper disabled from Terminal|spctl +--(master|global)-disable
ClickFix|hist|AppleScript running shell as admin|osascript +-e +.*do shell script
ClickFix|hist|backgrounded detached process|nohup +.*&[[:space:]]*$
ClickFix|str|curl-pipe-sh inside a plist, rc file or script|curl +-[A-Za-z]*s[A-Za-z]* +[^|]{0,160}\|[[:space:]]*(/bin/)?(ba|z)?sh([[:space:]]|$|;|"|')
ClickFix|str||base64 +(-d|-D|--decode)[^|]{0,160}\|[[:space:]]*(/bin/)?(ba|z)?sh([[:space:]]|$|;|"|')
# --- C2 frameworks with macOS implants ---
Geacon/CobaltStrike|bin|Go re-implementation of the Cobalt Strike beacon|[Gg]eacon
Geacon/CobaltStrike|bin|Cobalt Strike pipe-name template|MSSE-%d-server
Geacon/CobaltStrike|bin||beacon\.(x64|dll)
Sliver|bin||bishopfox/sliver
Sliver|bin||sliverpb
Mythic|bin|Mythic JXA agent|[Aa]pfell
Mythic|bin||mythic_payload
Mythic|bin|Mythic Poseidon (Go) agent source paths|poseidon/pkg/
Mythic|bin||[Oo]rthrus
Mythic|bin||[Tt]hanatos
Mythic|proc||(^|/)(apfell|poseidon|orthrus|thanatos)( |$)
IOCS
}

ioc_scan() {
  echo "RED FLAG: any line starting with 'IOC ' (known malware family) or 'HEUR ' (generic stealer/persistence heuristic). 'INFO ' lines are context (signed, probably legitimate) and are not counted."
  echo "Hit format: IOC  family=<f> kind=<k> where=<path or file> | <evidence>     HEUR heuristic=<name> where=<path> | <evidence>"
  echo
  local tmpd="$OUT/.26"; mkdir -p "$tmpd"
  local nioc=0 nheur=0 h p f line fam kind pat note m sig
  # ---------- build inputs once ----------
  echo "--- inputs (bounded):"
  # launchd plists (non-system), with one 'path: ' prefix per dumped line
  : > "$tmpd/corpus.txt"; : > "$tmpd/plists.txt"
  for h in $(user_homes); do for p in "$h"/Library/LaunchAgents/*.plist; do [ -f "$p" ] && echo "$p"; done; done >> "$tmpd/plists.txt"
  for p in /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do [ -f "$p" ] && echo "$p"; done >> "$tmpd/plists.txt"
  while IFS= read -r p; do plutil -p "$p" 2>/dev/null | awk -v p="$p" '{print p ": " $0}'; done < "$tmpd/plists.txt" >> "$tmpd/corpus.txt"
  # rc files, cron, periodic, every user
  for h in $(user_homes); do for f in .zshrc .zprofile .zshenv .zlogin .zlogout .bash_profile .bashrc .profile .bash_login .zshrc_aliases .config/fish/config.fish .ssh/rc; do [ -f "$h/$f" ] && echo "$h/$f"; done; done > "$tmpd/rc.txt"
  for f in /etc/zshrc /etc/zprofile /etc/zshenv /etc/profile /etc/bashrc /etc/bashrc_Apple_Terminal /etc/ssh/sshrc /etc/crontab /etc/rc.common /etc/rc.local /usr/lib/cron/tabs/* /etc/periodic/*/* /usr/local/etc/periodic/*/* /etc/emond.d/rules/*.plist; do [ -f "$f" ] && echo "$f"; done >> "$tmpd/rc.txt"
  while IFS= read -r f; do head -500 "$f" 2>/dev/null | awk -v p="$f" '{print p ": " $0}'; done < "$tmpd/rc.txt" >> "$tmpd/corpus.txt"
  # small scripts / plists / text dropped in tmp and user-writable dirs in the window (first 200 lines each)
  find /tmp /private/var/tmp /private/var/folders /Users/Shared "$UHOME/Library/Application Support" "$UHOME/Library/Scripts" "$UHOME/Library/Application Scripts" "$UHOME/Library/Services" "$UHOME/Downloads" "$UHOME/Desktop" "$UHOME/Public" "${FIND_EXCL[@]}" -not -path "$OUT/*" -not -path '*/triage*' -maxdepth 5 -type f -size -512k -mtime -"${DAYS}" \
     \( -name '*.sh' -o -name '*.command' -o -name '*.scpt' -o -name '*.applescript' -o -name '*.py' -o -name '*.js' -o -name '*.plist' -o -name '*.txt' -o -name '*.zsh' -o -name '*.bash' -o -name '*.pl' -o -name '*.rb' -o -name '*.json' \) 2>/dev/null \
     | grep -vE '/Application Support/(Google|BraveSoftware|Microsoft Edge|Arc|Code|Cursor|Slack|zoom\.us|JetBrains|discord|Notion|Figma|Spotify)/' | head -600 > "$tmpd/tmpfiles.txt"
  while IFS= read -r f; do case "$(file -b "$f" 2>/dev/null)" in *text*|*script*|*XML*|*JSON*) head -200 "$f" 2>/dev/null | awk -v p="$f" '{print p ": " $0}';; *plist*) plutil -p "$f" 2>/dev/null | awk -v p="$f" '{print p ": " $0}';; esac; done < "$tmpd/tmpfiles.txt" >> "$tmpd/corpus.txt"
  # histories
  : > "$tmpd/hist.txt"
  for h in $(user_homes); do for f in .zsh_history .bash_history .sh_history .python_history .node_repl_history; do [ -f "$h/$f" ] && tail -n 5000 "$h/$f" 2>/dev/null | awk -v p="$h/$f" '{print p ": " $0}'; done; for f in "$h"/.zsh_sessions/*.history; do [ -f "$f" ] && tail -n 300 "$f" 2>/dev/null | awk -v p="$f" '{print p ": " $0}'; done; done >> "$tmpd/hist.txt"
  # processes, labels, apps, machos
  ps axo pid=,user=,command= > "$tmpd/ps.txt" 2>/dev/null
  { launchctl list 2>/dev/null; [ "$IS_ROOT" -eq 1 ] && sudo -u "$TARGET_USER" launchctl list 2>/dev/null; sed 's|.*/||' "$tmpd/plists.txt"; grep '"Label" =>' "$tmpd/corpus.txt"; } > "$tmpd/labels.txt"
  find /Applications "$UHOME/Applications" "$UHOME/Downloads" "$UHOME/Desktop" /Users/Shared /tmp /private/var/tmp -maxdepth 3 -name '*.app' -type d 2>/dev/null | head -1500 > "$tmpd/apps.txt"
  recent_machos > "$tmpd/machos.txt"
  echo "   launchd plists=$(wc -l < "$tmpd/plists.txt" | tr -d ' ')  rc/cron files=$(wc -l < "$tmpd/rc.txt" | tr -d ' ')  tmp text files=$(wc -l < "$tmpd/tmpfiles.txt" | tr -d ' ')  history lines=$(wc -l < "$tmpd/hist.txt" | tr -d ' ')  apps=$(wc -l < "$tmpd/apps.txt" | tr -d ' ')  recent Mach-O in user dirs=$(wc -l < "$tmpd/machos.txt" | tr -d ' ')  strings-scan available=$HAVE_CLT"
  # strings of recent Mach-Os, one pass per file (bounded: 150 files, < 40 MB each). Written as 'path: string'
  : > "$tmpd/binstr.txt"
  if [ "$HAVE_CLT" -eq 1 ]; then
    head -150 "$tmpd/machos.txt" | while IFS= read -r f; do
      [ "$(stat -f %z "$f" 2>/dev/null || echo 0)" -gt 41943040 ] && continue
      strings -n 7 "$f" 2>/dev/null | grep -aE 'eacon|MSSE-%d-server|bishopfox|sliverpb|pfell|mythic|poseidon/pkg|rthrus|hanatos|ptrace|task_for_pid|[Kk]eychain|Login Data|[Ww]allet|[Ee]xodus|[Mm]etamask|with hidden answer|display dialog|Cookies|tealer|anshee|thulhu|MacSync|ealst|Atomic|Cuckoo' | sort -u | head -40 | awk -v p="$f" '{print p ": " $0}'
    done > "$tmpd/binstr.txt"
  fi
  echo
  # ---------- known-family IOCs ----------
  echo "--- known-family indicators:"
  ioc_list | grep -v '^#' | grep -v '^[[:space:]]*$' | while IFS='|' read -r fam kind note pat; do
    case "$kind" in
      path)
        local IFS_SAVE="$IFS" IFS=$'\n'
        if [ "${pat#\~}" != "$pat" ]; then
          for h in $(user_homes); do for m in $h${pat#\~}; do case "$m" in */./*|*/../*) continue;; esac; [ -e "$m" ] && echo "IOC  family=$fam kind=path where=$m | $(stat -f '%Sm mod, %SB birth, %z B, %Su' "$m" 2>/dev/null) ${note:+($note)}"; done; done
        else
          for m in $pat; do case "$m" in */./*|*/../*) continue;; esac; [ -e "$m" ] && echo "IOC  family=$fam kind=path where=$m | $(stat -f '%Sm mod, %SB birth, %z B, %Su' "$m" 2>/dev/null) ${note:+($note)}"; done
        fi
        IFS="$IFS_SAVE";;
      label) grep -E "$pat" "$tmpd/labels.txt" 2>/dev/null | sort -u | head -5 | sed "s|^|IOC  family=$fam kind=label where=launchd | |";;
      proc)  grep -E "$pat" "$tmpd/ps.txt"  2>/dev/null | head -5 | cut -c1-220 | sed "s|^|IOC  family=$fam kind=proc where=ps | |";;
      str)   grep -E "$pat" "$tmpd/corpus.txt" 2>/dev/null | head -5 | cut -c1-260 | sed "s|^|IOC  family=$fam kind=str where=|; s|: | \| |";;
      hist)  grep -E "$pat" "$tmpd/hist.txt" 2>/dev/null | head -5 | cut -c1-260 | sed "s|^|IOC  family=$fam kind=hist where=|; s|: | \| |";;
      bin)   grep -E "$pat" "$tmpd/binstr.txt" 2>/dev/null | head -5 | cut -c1-260 | sed "s|^|IOC  family=$fam kind=bin where=|; s|: | \| |";;
      app)   sed 's|.*/||' "$tmpd/apps.txt" | grep -E "$pat" | head -5 | while IFS= read -r m; do grep -F "/$m" "$tmpd/apps.txt" | head -1 | sed "s|^|IOC  family=$fam kind=app where=|; s|\$| \| $(echo "$note" | tr '|' '/')|"; done;;
      ext)   for h in $(user_homes); do find "$h/Library/Application Support" -maxdepth 7 -type d -name "$pat" -path '*/Extensions/*' 2>/dev/null | head -3 | sed "s|^|IOC  family=$fam kind=ext where=|; s|\$| \| ${note}|"; done;;
    esac
  done > "$tmpd/ioc_hits.txt"
  cat "$tmpd/ioc_hits.txt"; nioc=$(grep -c '^IOC ' "$tmpd/ioc_hits.txt")
  [ "$nioc" -eq 0 ] && echo "no IOC matches"
  echo
  # ---------- generic heuristics (catch unknown stealers / loaders) ----------
  echo "--- generic heuristics:"
  {
  # H1: AppleScript credential-prompt / privilege strings in files touched in the window
  grep -E 'with hidden answer|display dialog|with administrator privileges' "$tmpd/corpus.txt" | grep -vE '/Library/Application Support/(Alfred|Raycast|Keyboard Maestro|BetterTouchTool)/' | head -20 | cut -c1-260 | sed 's|^|HEUR heuristic=osascript_password_prompt where=|; s|: | \| |'
  # H2/H4: recent Mach-O in user-writable dirs: unsigned/adhoc = HEUR; non-Apple signed = INFO (reviewer decides); plus stealer-string scan
  while IFS= read -r f; do
    sig=$(sig_of "$f"); line="$(stat -f '%Sm mod, %SB birth, %z B' "$f" 2>/dev/null)"
    case "$sig" in unsigned|adhoc) echo "HEUR heuristic=unsigned_macho_userdir where=$f | sig=$sig; $line";; Apple*) ;; *) echo "INFO non-Apple Mach-O in user dir: $f | $sig; $line";; esac
    if [ -s "$tmpd/binstr.txt" ]; then
      m=$(grep -F "$f: " "$tmpd/binstr.txt" | sed "s|^$f: ||" | tr '\n' ',' | cut -c1-200)
      [ -n "$m" ] && { case "$sig" in unsigned|adhoc) echo "HEUR heuristic=stealer_strings_in_binary where=$f | sig=$sig; $m";; *) case "$m" in *"Login Data"*|*xodus*|*etamask*|*"hidden answer"*|*"display dialog"*|*task_for_pid*|*eacon*|*bishopfox*|*pfell*|*mythic*) echo "HEUR heuristic=stealer_strings_in_binary where=$f | sig=$sig; $m";; *) echo "INFO strings in signed binary: $f | $sig; $m";; esac;; esac; }
    fi
  done < "$tmpd/machos.txt"
  # H3: .app bundles in user-writable dirs that are UI-less (LSUIElement) or icon-less
  find "$UHOME/Library" "$UHOME/Applications" "$UHOME/Downloads" "$UHOME/Desktop" /Users/Shared /tmp /private/var/tmp /private/var/folders "${FIND_EXCL[@]}" -maxdepth 7 -name '*.app' -type d 2>/dev/null | grep -vE '/Contents/|/Application Support/(Google|BraveSoftware|Microsoft Edge|Arc|Code|Cursor|JetBrains|Slack|zoom\.us|Microsoft)/' | head -200 | while IFS= read -r m; do
    p="$m/Contents/Info.plist"; [ -f "$p" ] || continue
    local ui icon; ui=$(plutil -extract LSUIElement raw -o - "$p" 2>/dev/null); icon=$(plutil -extract CFBundleIconFile raw -o - "$p" 2>/dev/null)
    if [ "$ui" = "true" ] || [ "$ui" = "1" ] || [ -z "$icon" ]; then
      sig=$(sig_of "$m"); case "$sig" in unsigned|adhoc) echo "HEUR heuristic=hidden_app_userdir where=$m | LSUIElement=${ui:-no} icon=${icon:-none} sig=$sig; $(stat -f '%SB birth' "$m" 2>/dev/null)";; Apple*) ;; *) echo "INFO UI-less/icon-less app in user dir: $m | LSUIElement=${ui:-no} icon=${icon:-none} $sig";; esac
    fi
  done
  # H5: base64 blobs, curl|sh, DYLD/LSEnvironment, interpreter-as-Program inside launchd plists (non-System dirs)
  grep -E '"ProgramArguments"|=> "' "$tmpd/corpus.txt" | grep -E '\.plist: ' | grep -E '[A-Za-z0-9+/]{60,}={0,2}' | head -10 | cut -c1-260 | sed 's|^|HEUR heuristic=base64_blob_in_plist where=|; s|: | \| |'
  grep -E '\.plist: ' "$tmpd/corpus.txt" | grep -E 'DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|"LSEnvironment"|DYLD_FRAMEWORK_PATH' | head -10 | cut -c1-260 | sed 's|^|HEUR heuristic=dyld_or_lsenvironment_in_plist where=|; s|: | \| |'
  grep -E '\.plist: ' "$tmpd/corpus.txt" | grep -E '(curl|wget)[^|]*\|[[:space:]]*(ba|z)?sh|/bin/(ba|z)?sh -c |nohup ' | head -10 | cut -c1-260 | sed 's|^|HEUR heuristic=shell_oneliner_in_plist where=|; s|: | \| |'
  while IFS= read -r p; do
    local prog; prog=$(plutil -extract Program raw -o - "$p" 2>/dev/null); [ -z "$prog" ] && prog=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
    [ -z "$prog" ] && continue
    case "$(basename "$prog")" in python|python3|python2|osascript|bash|sh|zsh|perl|ruby|node|nohup|curl|env) echo "HEUR heuristic=interpreter_as_launchd_program where=$p | program=$prog args=$(plutil -extract ProgramArguments json -o - "$p" 2>/dev/null | cut -c1-200)";; esac
    case "$prog" in /tmp/*|/private/tmp/*|/private/var/folders/*|/var/folders/*|/Users/Shared/*|*/Library/Application\ Support/.*|/Users/*/.*|"$UHOME"/.*) echo "HEUR heuristic=launchd_program_in_tmp_or_hidden where=$p | program=$prog";; esac
    case "$p" in /Users/*/Library/LaunchAgents/com.apple.*|/var/root/Library/LaunchAgents/com.apple.*) echo "HEUR heuristic=user_launchagent_named_com_apple where=$p | Apple never installs com.apple.* agents in a user's LaunchAgents; program=$prog";; esac
  done < "$tmpd/plists.txt"
  # H6: hidden directories / executables in Application Support, /Users/Shared, tmp (Adload, AMOS backdoor, DPRK)
  for h in $(user_homes); do for m in "$h/Library/Application Support"/.[!.]* "$h/Library"/.[!.]* ; do [ -e "$m" ] || continue; case "$m" in */.DS_Store|*/.localized) continue;; esac; echo "HEUR heuristic=hidden_entry_in_Library where=$m | $(stat -f '%Sm mod, %SB birth, %Sp' "$m" 2>/dev/null)"; done; done
  for m in "/Library/Application Support"/.[!.]* /Users/Shared/.[!.]* /tmp/.[!.]* /private/var/tmp/.[!.]*; do [ -e "$m" ] || continue; case "$m" in */.DS_Store|*/.localized|*/.X11-unix|*/.font-unix|*/.ICE-unix|*/.XIM-unix|*/.TemporaryItems|*/.Trashes|*/.vbox-*|*/.com.apple.*|*/.s.PGSQL*) continue;; esac; echo "HEUR heuristic=hidden_entry_in_shared_or_tmp where=$m | $(stat -f '%Sm mod, %SB birth, %Sp %Su' "$m" 2>/dev/null)"; done
  # H7: cron entries with network/decoder/interpreter
  grep -E 'cron|crontab' "$tmpd/corpus.txt" | grep -vE ': *#' | grep -E 'curl|wget|base64|python|osascript|/tmp/|nohup|\.sh' | head -10 | cut -c1-260 | sed 's|^|HEUR heuristic=suspicious_cron where=|; s|: | \| |'
  # H8: rc-file lines that fetch or decode at shell start
  grep -E '^[^:]*/\.(zshrc|zprofile|zshenv|zlogin|bash_profile|bashrc|profile|zshrc_aliases): ' "$tmpd/corpus.txt" | grep -vE ': *#' | grep -E 'curl |wget |base64|eval "\$\(|nohup|/tmp/|/var/folders|osascript|python3? -c|\.n2/' | grep -vE 'brew shellenv|nvm\.sh|pyenv init|rbenv init|conda|sdkman|direnv|starship|zoxide|fzf|op completion|gh completion|mise|asdf|cargo/env|google-cloud-sdk|iterm2_shell_integration|zinit|antigen|oh-my-zsh|p10k|kubectl completion' | head -15 | cut -c1-260 | sed 's|^|HEUR heuristic=rc_fetch_or_decode where=|; s|: | \| |'
  } > "$tmpd/heur_hits.txt" 2>/dev/null
  cat "$tmpd/heur_hits.txt"; nheur=$(grep -c '^HEUR ' "$tmpd/heur_hits.txt")
  [ "$nheur" -eq 0 ] && echo "no heuristic hits"
  echo
  echo "--- XProtect (Apple's built-in signatures; detections are in 19_unifiedlog_gatekeeper.txt):"
  command -v xprotect >/dev/null 2>&1 && { xprotect version 2>&1; xprotect status 2>&1 | head -20; }
  defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null | sed 's/^/XProtect.bundle version: /'
  echo
  echo "--- totals: IOC matches=$nioc  heuristic hits=$nheur  (INFO lines not counted)"
  rm -rf "$tmpd"
  return 0
}
section 26_malware_iocs ioc_scan
if [ "$XPROTECT_CHECK" -eq 1 ]; then
  append 26_malware_iocs "xprotect check (-X: ONLINE version check against Apple; this is the only network call in the script) + xprotect logs" bash -c 'xprotect check 2>&1; echo; xprotect logs 2>&1 | tail -200'
fi

############################ 27. login / authentication activity ############################
login_activity() {
  echo "RED FLAG: logins/unlocks at hours you were not at the Mac; 'FAIL' bursts (password guessing); ssh/screen-sharing logins from an address you do not know; a 'sudo' or authorization right granted to a client in /tmp, /var/folders or ~/Library; failedLoginCount > 0 on an account nobody uses; a LoginHook."
  echo "Table columns: time | event | who | from | result | detail.   Sources: utmpx (last), unified log window=$LOGWIN, accountPolicyData per user."
  echo
  echo "--- last -200 (utmpx: console/tty/ssh sessions, reboots; 'still logged in' = current):"; last -200 2>&1
  echo; echo "--- reboots / shutdowns:"; last reboot 2>/dev/null | head -10; last shutdown 2>/dev/null | head -10
  echo; echo "--- per-user password policy data (failedLoginCount resets on success; failedLoginTimestamp is the last failure):"
  local u apd k v
  dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 || $1 == "root" {print $1}' | while read -r u; do
    apd=$(dscl . -read "/Users/$u" accountPolicyData 2>/dev/null | sed '1d')
    [ -z "$apd" ] && { echo "  $u: (no accountPolicyData readable)"; continue; }
    printf '  %-20s' "$u"
    for k in creationTime passwordLastSetTime failedLoginCount failedLoginTimestamp; do
      v=$(printf '%s\n' "$apd" | plutil -extract "$k" raw -o - - 2>/dev/null); v="${v%%.*}"
      case "$k" in *Time*) [ -n "$v" ] && [ "$v" != "0" ] && v="$(date -r "$v" '+%F %T' 2>/dev/null)";; esac
      printf ' %s=%s' "$k" "${v:-?}"
    done; echo
  done
  echo; echo "--- Wi-Fi joins (/var/log/wifi.log, if present on this OS):"; grep -ihE 'join|assoc|AutoJoin' /var/log/wifi.log 2>/dev/null | tail -40 || echo "  (no /var/log/wifi.log; Wi-Fi history is in 30_network_history.txt known-networks instead)"
  echo; echo "--- authentication events from the unified log (chronological; built from 18_unifiedlog_ALL.txt):"
  if [ ! -s "$ALLB" ]; then echo "  (no unified-log body available)"; return; fi
  grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ +[A-Za-z]+ +(sudo|su|login|authd|SecurityAgent|authorizationhost|opendirectoryd|loginwindow|coreauthd|sshd|sshd-session|screensharingd|akd|AppleIDSettings)\[' "$ALLB" \
   | grep -vE 'Retrieve (User|Group)|Membership API|Open a given node|Copy nodenames|activating connection|invalidated after|Reading config|Too many groups|com\.apple\.Authorization:analytics|Will use icon|Dialog icon|CSInlineDonation|AuthenticationHintsProvider|calling activate|shouldReplaceiCloudRecoveryKey|isLAServiceEnabled|evaluatePolicy:.*options' \
   | awk '
     function trunc(s,n){ return (length(s)>n) ? substr(s,1,n) "..." : s }
     {
       ts=$1 " " substr($2,1,8); proc=$4; sub(/\[.*/,"",proc)
       msg=$0; i=index(msg,"] "); if(i>0) msg=substr(msg,i+2); if(substr(msg,1,1)=="[") { i=index(msg,"] "); if(i>0) msg=substr(msg,i+2) }
       ev=proc; who="-"; from="-"; res="-"
       if(proc=="sudo"){ if(msg ~ /COMMAND=/){ ev="sudo"; who=msg; sub(/ :.*/,"",who); from=msg; sub(/.*TTY=/,"",from); sub(/ ;.*/,"",from); res="OK" }
                         else if(msg ~ /incorrect password|authentication failure|NOT in sudoers|3 incorrect/){ ev="sudo"; res="FAIL"; who=msg; sub(/ :.*/,"",who) } else next }
       else if(proc=="opendirectoryd"){ ev="od-auth"; res="FAIL"; who=msg; sub(/.*for /,"",who); sub(/ .*/,"",who) }
       else if(proc=="authd"){ if(msg ~ /Succeeded authorizing right/){ ev="authz-ok"; res="OK" } else if(msg ~ /Failed to authorize right|denied/){ ev="authz-fail"; res="FAIL" } else next
                               who=msg; sub(/.*right .?/,"",who); sub(/.? by client.*/,"",who); from=msg; sub(/.*by client .?/,"",from); sub(/.? \[.*/,"",from) }
       else if(proc=="SecurityAgent"){ if(msg ~ /SecurityAgent start|dialog|Watch unlock|password|Password|cancel|Cancel/) ev="auth-dialog"; else next }
       else if(proc=="authorizationhost"){ if(msg ~ /FVUnlock result/){ ev="filevault-unlock"; res=(msg ~ /result: 0/)?"OK":"FAIL" } else if(msg ~ /AgentMechanism invoked/){ ev="auth-mechanism"; who=msg; sub(/.*invoked \[/,"",who); sub(/\].*/,"",who) } else next }
       else if(proc=="loginwindow"){ if(msg ~ /loginIsComplete returning: 1/) ev="login-complete"; else if(msg ~ /inform UA unlocked|screen is unlocked|Screen unlocked/) ev="screen-unlock"; else if(msg ~ /userSwitched|FUS/) ev="fast-user-switch"; else if(msg ~ /activateForUserName/){ ev="auth-for-user"; who=msg; sub(/.*activateForUserName: */,"",who); sub(/ .*/,"",who) } else if(msg ~ /USER_PROCESS|DEAD_PROCESS/) ev="session"; else if(msg ~ /LoginHook/) ev="LOGINHOOK"; else if(msg ~ /[Ll]ogout/) ev="logout"; else if(msg ~ /AutoUnlock state:3|Watch unlock/) ev="watch-unlock"; else next }
       else if(proc=="coreauthd"){ ev="touchid-request" }
       else if(proc=="sshd" || proc=="sshd-session"){ if(msg ~ /Accepted/){ ev="ssh-login"; res="OK" } else if(msg ~ /Failed|Invalid user|authentication failure|Disconnecting invalid|Connection closed by authenticating/){ ev="ssh-auth"; res="FAIL" } else if(msg ~ /session opened|session closed|Received disconnect/) ev="ssh-session"; else next
                                 if(match(msg,/for (invalid user )?[A-Za-z0-9_.-]+ from [0-9A-Fa-f.:]+/)){ s=substr(msg,RSTART,RLENGTH); who=s; sub(/^for (invalid user )?/,"",who); sub(/ from.*/,"",who); from=s; sub(/.* from /,"",from) } }
       else if(proc=="screensharingd"){ ev="screen-sharing"; if(msg ~ /SUCCEEDED|Succeeded/) res="OK"; else if(msg ~ /FAILED|Failed/) res="FAIL"; if(match(msg,/Viewer Address: [0-9A-Fa-f.:]+/)){ from=substr(msg,RSTART+16,RLENGTH-16) } if(match(msg,/Viewer Address: [0-9A-Fa-f.:]+/)){ from=substr(msg,RSTART+16,RLENGTH-16) } }
       else if(proc=="su" || proc=="login"){ if(msg ~ /FAILED|failed|incorrect|BAD/) res="FAIL"; else if(msg ~ /succeeded|to root|login:/) res="OK"; else next }
       else if(proc=="akd" || proc=="AppleIDSettings"){ ev="appleid"; if(msg ~ /[Ff]ail|[Ee]rror/) res="FAIL" }
       printf "%s | %s | %s | %s | %s | %s\n", ts, ev, trunc(who,40), trunc(from,40), res, trunc(msg,140)
     }' > "$OUT/.27_table.txt"
  echo "  rows: $(wc -l < "$OUT/.27_table.txt" | tr -d ' ')   FAIL rows: $(grep -c ' | FAIL | ' "$OUT/.27_table.txt")   sudo COMMAND rows: $(grep -c ' | sudo | .* | OK | ' "$OUT/.27_table.txt")"
  echo; echo "--- counts by event:"; awk -F' \\| ' '{print $2" "$5}' "$OUT/.27_table.txt" | sort | uniq -c | sort -rn | head -30
  echo; echo "--- authorization rights granted, by right and client (authd):"; grep -E ' \| authz-(ok|fail) \| ' "$OUT/.27_table.txt" | awk -F' \\| ' '{print $5" "$3" <- "$4}' | sort | uniq -c | sort -rn | head -40
  echo; echo "--- FAIL rows (all):"; grep ' | FAIL | ' "$OUT/.27_table.txt" | head -300
  echo; echo "--- sudo commands (all):"; grep ' | sudo | ' "$OUT/.27_table.txt" | head -300
  echo; echo "--- ssh / screen sharing / LoginHook / fast-user-switch rows:"; grep -E ' \| (ssh-[a-z]+|screen-sharing|LOGINHOOK|fast-user-switch) \| ' "$OUT/.27_table.txt" | head -200
  echo; echo "--- full chronological table (capped at 3000 rows):"; head -3000 "$OUT/.27_table.txt"
  rm -f "$OUT/.27_table.txt"
  return 0
}
section 27_login_activity login_activity

############################ 28. script / interpreter execution ############################
script_execution() {
  echo "RED FLAG: history lines you did not type (esp. curl|sh, base64 -d, osascript, nohup, chmod +x, /tmp paths); an interpreter spawned by launchd (SPAWN lines) at the compromise time; a #! script born in the window in ~/Library, /tmp, /var/folders or /Users/Shared; a Terminal profile with a CommandString; an Automator/Shortcut/Service changed in the window; an at job."
  echo
  local h f n
  echo "--- shell histories, every user (last 400 lines each, timestamps where the shell recorded them):"
  for h in $(user_homes); do
    for f in .zsh_history .bash_history .sh_history; do
      [ -f "$h/$f" ] || continue; n=$(wc -l < "$h/$f" | tr -d ' ')
      echo "========== $h/$f  ($n lines, mod $(stat -f '%Sm' "$h/$f"))"; tail -n 400 "$h/$f" | hist_conv; echo
    done
    [ -d "$h/.zsh_sessions" ] && { echo "========== $h/.zsh_sessions (newest first, name = terminal session):"; ls -lat "$h/.zsh_sessions" 2>/dev/null | head -15; }
    for f in .python_history .node_repl_history .irb_history .lesshst; do [ -f "$h/$f" ] && { echo "========== $h/$f"; tail -n 40 "$h/$f"; }; done
  done
  echo; echo "--- suspicious history lines (all users, all history files):"
  for h in $(user_homes); do for f in "$h"/.zsh_history "$h"/.bash_history "$h"/.sh_history "$h"/.zsh_sessions/*.history; do [ -f "$f" ] || continue
    grep -nE 'curl[^|]*\|[[:space:]]*(ba|z)?sh|wget[^|]*\|[[:space:]]*(ba|z)?sh|base64 +(-d|-D|--decode)|osascript|nohup |chmod +\+x|/tmp/[A-Za-z0-9_.-]+|/var/folders/|xattr +-[a-z]*[cd]|spctl +--|launchctl +(load|bootstrap|submit)|crontab|security +(find|dump)|defaults +write +com\.apple\.(loginwindow|LaunchServices)|python[0-9.]* +-c|perl +-e|ruby +-e|node +-e|eval ' "$f" 2>/dev/null | sed 's/^: [0-9]*:[0-9]*;//' | head -60 | sed "s|^|$f:|" | cut -c1-240
  done; done
  echo; echo "--- interpreters spawned by launchd in the log window (GUI-session spawns only; SPAWN lines are counted in the summary):"
  if [ -s "$ALLB" ]; then
    grep 'added unmanaged' "$ALLB" | sed -E 's/^([0-9-]+ [0-9:.]+).*unmanaged\.(.*)\.([0-9]+) \[[0-9]+\]:.*/\1  pid=\3  \2/' | grep -E '  (python[0-9.]*|perl|ruby|node|osascript|automator|shortcuts|Script Editor|sh|bash|zsh|curl|wget|nc|ncat|socat|java|php|tclsh|expect|screen|tmux)$' | sed 's/^/SPAWN /' | head -500
    echo; echo "--- interpreter process log lines in the window (python3/perl/ruby/node/osascript/automator/shortcuts/sh/bash/zsh/curl/wget/nc; noise removed):"
    grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ +[A-Za-z]+ +(python[0-9.]*|perl|ruby|node|osascript|automator|shortcuts|Script Editor|sh|bash|zsh|curl|wget|nc)\[' "$ALLB" | grep -vE 'Retrieve (User|Group)|Membership API|libsystem_info|com\.apple\.xpc|CFPrefs|Preferences From|tcc:|nw_|com\.apple\.network|CoreAnalytics|CarbonCore|LaunchServices|RunningBoard' | head -400 | cut -c1-240
    echo; echo "--- osascript / shell one-liners seen anywhere in the log window:"
    grep -E 'osascript|/bin/(ba|z)?sh -c|python[0-9.]* -c|perl -e|curl -[A-Za-z]*s|base64 -|nohup ' "$ALLB" | grep -vE 'added unmanaged|service inactive|removing inactive|xpc:connection|libsystem_info|CoreAnalytics|CFPrefs|Preferences From|com\.apple\.log:' | head -200 | cut -c1-240
  else echo "  (no unified-log body available)"; fi
  echo; echo "--- recent-document lists (sfl2 are binary bookmarks: name + mtime; script-like paths extracted with strings):"
  local d="$UHOME/Library/Application Support/com.apple.sharedfilelist"
  ls -lat "$d" 2>&1 | head -20; ls -lat "$d/com.apple.LSSharedFileList.ApplicationRecentDocuments" 2>/dev/null | head -40
  for f in "$d"/com.apple.LSSharedFileList.RecentDocuments.sfl* "$d"/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.apple.scripteditor2.sfl* "$d"/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.apple.terminal.sfl* "$d"/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.apple.automator.sfl* "$d"/com.apple.LSSharedFileList.ApplicationRecentDocuments/com.apple.textedit.sfl*; do
    [ -f "$f" ] || continue; echo "== $f ($(stat -f '%Sm' "$f"))"
    if [ "$HAVE_CLT" -eq 1 ]; then strings -n 6 "$f" 2>/dev/null | grep -E '\.(sh|py|scpt|applescript|command|rb|pl|js|workflow|zsh|bash|plist|txt)$|^/Users/|^/tmp|^/private|file://' | sort -u | head -40 | sed 's/^/   /'; fi
  done
  echo; echo "--- Script Editor / Automator / Shortcuts / Services:"
  ls -lat "$UHOME/Library/Application Support/Script Editor" 2>/dev/null | head; plutil -p "$UHOME/Library/Preferences/com.apple.ScriptEditor2.plist" 2>/dev/null | grep -iE 'Recent|Path' | head -10
  echo "== Automator workflows / Shortcuts changed in last ${DAYS}d:"; find "$UHOME/Library/Services" /Library/Services "$UHOME/Library/Workflows" "$UHOME/Library/Automator" "$UHOME/Documents" "$UHOME/Desktop" "$UHOME/Downloads" -maxdepth 4 \( -name '*.workflow' -o -name '*.shortcut' -o -name '*.action' \) \( -ctime -"${DAYS}"d -o -Btime -"${DAYS}"d \) 2>/dev/null | head -40 | while IFS= read -r f; do stat -f '%Sm mod | %SB birth | %N' "$f"; done
  echo "== ~/Library/Services and /Library/Services:"; ls -lat "$UHOME/Library/Services" 2>&1 | head -20; ls -lat /Library/Services 2>/dev/null | head
  for f in "$UHOME/Library/Shortcuts/Shortcuts.sqlite" "$UHOME/Library/Group Containers/group.com.apple.shortcuts/Shortcuts.sqlite"; do [ -f "$f" ] || continue; echo "== $f ($(stat -f '%Sm' "$f"))"; cp "$f" "$OUT/.sc.sqlite" 2>/dev/null && sqlite3 -readonly "$OUT/.sc.sqlite" "select datetime(ZMODIFICATIONDATE+978307200,'unixepoch'), ZNAME from ZSHORTCUT order by ZMODIFICATIONDATE desc limit 30;" 2>&1 | head -30; rm -f "$OUT/.sc.sqlite"; done
  echo; echo "--- at / periodic / emond:"; atq 2>&1 | head; ls -la /usr/lib/cron/jobs /var/at/jobs 2>/dev/null | head
  find /etc/periodic /usr/local/etc/periodic /etc/emond.d -type f \( -ctime -"${DAYS}"d -o -Btime -"${DAYS}"d \) 2>/dev/null | while IFS= read -r f; do stat -f 'CHANGED %Sm | %N' "$f"; done
  echo; echo "--- Terminal / iTerm: profiles that run a command at open (CommandString), saved state, recent sessions:"
  plutil -p "$UHOME/Library/Preferences/com.apple.Terminal.plist" 2>/dev/null | grep -E 'CommandString|RunCommandAsShell|"Shell"|Default Window Settings|Startup Window Settings' | head -20
  plutil -p "$UHOME/Library/Preferences/com.googlecode.iterm2.plist" 2>/dev/null | grep -E '"Command"|"Initial Text"|Custom Command' | grep -v '""' | head -20
  for d in "$UHOME/Library/Saved Application State/com.apple.Terminal.savedState" "$UHOME/Library/Saved Application State/com.googlecode.iterm2.savedState" "$UHOME/Library/Application Support/iTerm2"; do [ -d "$d" ] && { echo "== $d"; ls -lat "$d" | head -8; }; done
  echo; echo "--- files with a #! shebang created in last ${DAYS}d in user-writable dirs (quick mode: ~/Library, Downloads, Desktop, Documents, hidden home dirs, tmp, Shared; full mode: whole home):"
  if [ "$QUICK" -eq 1 ]; then
    find "${USERWRITABLE_DIRS[@]}" "$UHOME"/.[!.]* "${FIND_EXCL[@]}" -not -path "$OUT/*" -not -path '/Users/Shared/triage-*' -maxdepth 6 -type f -size -2000k -Btime -"${DAYS}"d 2>/dev/null
  else
    find "$UHOME" /tmp /private/var/tmp /private/var/folders /Users/Shared "${FIND_EXCL[@]}" -not -path "$OUT/*" -not -path '/Users/Shared/triage-*' -type f -size -2000k -Btime -"${DAYS}"d 2>/dev/null
  fi | grep -vE '/Library/(Caches|Logs|Metadata|Saved Application State|HTTPStorages|Cookies|WebKit)/|/Application Support/(Google|BraveSoftware|Microsoft Edge|Arc|Code|Cursor|Slack|zoom\.us|JetBrains|discord|Notion|Figma|Spotify|Microsoft)/|/\.(npm|cargo|rustup|pyenv|nvm|gradle|m2|docker|vscode|cursor|terraform\.d|pnpm|bun|deno|go|asdf|mise|rbenv|local/share)/|/Library/pnpm/|/triage[^/]*/|\.app/Contents/|/\.(claude|codex|cursor|copilot|gemini)/|/Containers/|/Group Containers/|/node_modules/|/venv/|/\.venv/|/site-packages/' | head -4000 | while IFS= read -r f; do
    [ "$(head -c 2 "$f" 2>/dev/null)" = '#!' ] || continue
    echo "SHEBANG $(stat -f '%SB birth | %Sm mod | %z B | %N' "$f") | $(head -1 "$f" | cut -c1-60) | q=$(xattr -p com.apple.quarantine "$f" 2>/dev/null | cut -c1-30)"
  done | head -200
  return 0
}
section 28_script_execution script_execution

############################ 29. tamper / hijack checks ############################
tamper_checks() {
  echo "RED FLAG: a 'CA ' line you did not install (TLS interception); a 'PROFILE ' you did not enrol; /etc/hosts entries for Apple/Google/bank domains; a pam.d or sshd_config file modified after the last OS update; a non-Apple login mechanism; boot-args set, SIP or Gatekeeper off; a kext/sysext from an unknown team; a 'CODESIGN-FAIL' on an app you use; a browser homepage/search/extension or policy you did not set."
  echo
  local f n osts
  osts=$(stat -f %m /System/Library/CoreServices/SystemVersion.plist 2>/dev/null || echo 0)
  echo "--- last OS update (SystemVersion.plist mtime): $(date -r "$osts" '+%F %T' 2>/dev/null)   SIP/boot:"
  csrutil status 2>&1; csrutil authenticated-root status 2>&1; nvram boot-args 2>&1; spctl --status 2>&1; echo "secure boot / ownership:"; nvram -p 2>/dev/null | grep -iE 'boot-args|SystemAudioVolume|security-mode|csr-active-config|efi-boot' | cut -c1-120
  echo; echo "--- root CAs and trust overrides outside Apple's built-in store (each counted line starts with 'CA '):"
  for dom in user admin; do
    case $dom in user) o=$(security dump-trust-settings 2>&1);; admin) o=$(security dump-trust-settings -d 2>&1);; esac
    printf '%s\n' "$o" | grep -E '^Cert [0-9]+:' | sed "s/^Cert \([0-9]*\): /CA  domain=$dom cert=/"
    printf '%s\n' "$o" | grep -vE '^Cert [0-9]+:' | head -40 | sed 's/^/     /'
  done
  echo "== certificates in the System keychain (admin-installed; subject/issuer/validity, bounded to 60):"
  security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null | awk '/BEGIN CERT/{n++} {print > ("'"$OUT"'/.29_cert_" n ".pem")}'
  n=0; for f in "$OUT"/.29_cert_*.pem; do [ -f "$f" ] || continue; n=$((n+1)); [ $n -gt 60 ] && break
    /usr/bin/openssl x509 -in "$f" -noout -subject -issuer -dates -fingerprint -sha256 2>/dev/null | tr '\n' ' ' | sed -E 's/subject= */SYSKC subject=/; s/ issuer=/ | issuer=/; s/ notBefore=/ | from=/; s/ notAfter=/ | to=/; s/ (SHA256|sha256) Fingerprint=/ | /'; echo
  done; rm -f "$OUT"/.29_cert_*.pem
  echo "== certificates in the login keychain whose subject == issuer (self-signed roots), bounded:"
  security find-certificate -a -p "$UHOME/Library/Keychains/login.keychain-db" 2>/dev/null | awk '/BEGIN CERT/{n++} {print > ("'"$OUT"'/.29_ucert_" n ".pem")}'
  n=0; for f in "$OUT"/.29_ucert_*.pem; do [ -f "$f" ] || continue; n=$((n+1)); [ $n -gt 200 ] && break
    s=$(/usr/bin/openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject= *//'); i=$(/usr/bin/openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
    [ -n "$s" ] && [ "$s" = "$i" ] && echo "USERKC self-signed: $s | $(/usr/bin/openssl x509 -in "$f" -noout -dates 2>/dev/null | tr '\n' ' ')"
  done; rm -f "$OUT"/.29_ucert_*.pem
  echo; echo "--- configuration profiles (each counted line contains 'profileIdentifier:'):"
  if [ "$IS_ROOT" -eq 1 ]; then profiles show -all 2>&1 | head -200; else profiles list 2>&1 | head -60; echo "(run as root for system/device profiles)"; fi
  profiles status -type enrollment 2>&1
  echo; echo "--- /etc/hosts: non-default lines:"; grep -vE '^[[:space:]]*#|^[[:space:]]*$|^127\.0\.0\.1[[:space:]]+localhost[[:space:]]*$|^255\.255\.255\.255[[:space:]]+broadcasthost|^::1[[:space:]]+localhost[[:space:]]*$' /etc/hosts 2>/dev/null | sed 's/^/HOSTS /'; echo "(/etc/hosts mod $(stat -f '%Sm' /etc/hosts 2>/dev/null))"
  echo; echo "--- /etc/pam.d, sudoers, sshd_config, authorization: modified AFTER the last OS update is flagged:"
  for f in /etc/pam.d/* /etc/sudoers /etc/sudoers.d/* /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/ssh/ssh_config /etc/authorization /etc/security/audit_control /etc/ttys /etc/launchd.conf /etc/csh.cshrc /etc/csh.login; do
    [ -e "$f" ] || continue; m=$(stat -f %m "$f"); flag=""; [ "$m" -gt $((osts + 3600)) ] && flag="MODIFIED-AFTER-OS-UPDATE"
    echo "$(stat -f '%Sm | %Su:%Sg %Sp | %N' "$f") $flag"
  done
  echo "== sshd_config effective non-comment lines:"; grep -hvE '^[[:space:]]*#|^[[:space:]]*$' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | sed 's/^/   /'
  grep -hvE '^[[:space:]]*#' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | grep -iE 'PermitRootLogin[[:space:]]+yes|PasswordAuthentication[[:space:]]+yes|AuthorizedKeysCommand|ForceCommand|PermitEmptyPasswords[[:space:]]+yes' | sed 's/^/   SSHD-RISKY: /'
  echo "== pam.d/sudo and pam.d/screensaver contents (Touch ID line is normal; anything else non-Apple is not):"; grep -hvE '^#' /etc/pam.d/sudo /etc/pam.d/sudo_local /etc/pam.d/screensaver 2>/dev/null | sed 's/^/   /'
  echo; echo "--- authorization db: login/screensaver mechanisms not from Apple's known set are flagged:"
  for r in system.login.console system.login.screensaver authenticate system.preferences; do
    echo "== $r"; security authorizationdb read "$r" 2>/dev/null | grep -A60 '<key>mechanisms' | grep '<string>' | sed -E 's/.*<string>(.*)<\/string>.*/\1/' | while IFS= read -r m; do
      case "$m" in builtin:*|loginwindow:*|PKINITMechanism:*|HomeDirMechanism:*|MCXMechanism:*|CryptoTokenKit:*|FDEMechanism:*|TeamIdentityPrompt:*|authinternal|loginKC:*|Crypto*|"") echo "   $m";; *) echo "   NON-APPLE-MECHANISM: $m";; esac
    done
  done
  echo; echo "--- Gatekeeper per-app overrides (spctl --list, bounded; cdhash/anchor rules a user added by 'Open Anyway'):"; spctl --list 2>&1 | grep -vE '^\s*$' | head -120
  echo; echo "--- kernel / system extensions not from Apple:"
  kmutil showloaded --no-kernel-components 2>&1 | grep -vE 'com\.apple\.|^Index|^No variant|^Executing' | head -40
  systemextensionsctl list 2>&1 | grep -vE 'com\.apple\.' | head -60
  echo; echo "--- XProtect bundle / remediator versions and dates:"; ls -ld /Library/Apple/System/Library/CoreServices/XProtect* 2>/dev/null; defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null; command -v xprotect >/dev/null && xprotect version 2>&1
  echo; echo "--- /usr/local/bin and /opt/homebrew/bin: newest 30, and REGULAR FILES (Homebrew installs symlinks; a real binary here was put there by hand or by an installer):"
  for d in /usr/local/bin /usr/local/sbin /opt/homebrew/bin /opt/homebrew/sbin; do [ -d "$d" ] || continue; echo "== $d"; ls -lat "$d" | head -31; find "$d" -maxdepth 1 -type f 2>/dev/null | head -30 | while IFS= read -r f; do echo "   REGULAR-FILE $(stat -f '%Sm | %z B | %Su' "$f") $f | $(sig_of "$f")"; done; done
  echo; echo "--- code signature verification of apps changed in last ${DAYS}d (/Applications, ~/Applications; --deep --strict; huge apps skipped; bounded to 40):"
  find /Applications "$UHOME/Applications" -maxdepth 2 -name '*.app' -type d \( -ctime -"${DAYS}"d -o -Btime -"${DAYS}"d -o -mtime -"${DAYS}"d \) 2>/dev/null | grep -vE '/(Xcode|Xcode-beta|Android Studio|Unity|Docker|Final Cut Pro|Logic Pro|Parallels Desktop|VMware Fusion|GarageBand|iMovie|Visual Studio)[^/]*\.app$' | head -40 | while IFS= read -r a; do
    if o=$(codesign --verify --deep --strict "$a" 2>&1); then echo "codesign ok   $a | $(sig_of "$a")"; else echo "CODESIGN-FAIL $a | $(echo "$o" | head -2 | tr '\n' ' ') | $(sig_of "$a")"; fi
  done
  echo; echo "--- browser hijack: Chrome-family Preferences (homepage, startup, search engine, extensions with install time; location 4=unpacked/sideloaded, 8=command-line, 9=policy):"
  local base prof id mf nm up perms it loc
  for base in "$UHOME/Library/Application Support/Google/Chrome" "$UHOME/Library/Application Support/BraveSoftware/Brave-Browser" "$UHOME/Library/Application Support/Microsoft Edge" "$UHOME/Library/Application Support/Arc/User Data" "$UHOME/Library/Application Support/Chromium" "$UHOME/Library/Application Support/Vivaldi"; do
    [ -d "$base" ] || continue
    for prof in "$base"/Default "$base"/Profile\ *; do
      [ -f "$prof/Preferences" ] || continue; echo "========== $prof"
      for f in "$prof/Preferences" "$prof/Secure Preferences"; do [ -f "$f" ] || continue
        grep -oE '"homepage":"[^"]*"|"homepage_is_newtabpage":(true|false)|"restore_on_startup":[0-9]+|"startup_urls":\[[^]]*\]|"keyword":"[^"]*","name":"[^"]*"|"search_url":"[^"]*"|"url":"[^"]{0,120}","usage_count"|"alternate_error_pages"|"proxy":\{[^}]*\}|"default_search_provider_data":\{"template_url_data":\{"[a-z_]+":"[^"]*"' "$f" 2>/dev/null | sort -u | head -20 | sed 's/^/   /'
      done
      [ -d "$prof/Extensions" ] || continue
      for e in "$prof"/Extensions/*; do
        id=$(basename "$e"); [ ${#id} -eq 32 ] || continue; v=$(ls -t "$e" 2>/dev/null | head -1); mf="$e/$v/manifest.json"; [ -f "$mf" ] || continue
        nm=$(plutil -extract name raw -o - "$mf" 2>/dev/null); up=$(plutil -extract update_url raw -o - "$mf" 2>/dev/null); perms=$(plutil -extract permissions json -o - "$mf" 2>/dev/null | tr -d '\n ' | cut -c1-160); hp=$(plutil -extract host_permissions json -o - "$mf" 2>/dev/null | tr -d '\n ' | cut -c1-120)
        it=""; loc=""
        for f in "$prof/Secure Preferences" "$prof/Preferences"; do [ -f "$f" ] || continue
          seg=$(awk -v id="\"$id\":{" 'BEGIN{RS="\0"} { i=index($0,id); if(i>0) print substr($0,i,12000) }' "$f" 2>/dev/null)
          [ -z "$it" ] && it=$(printf '%s' "$seg" | grep -oE '"(first_install_time|install_time)":"[0-9]+"' | head -1 | grep -oE '[0-9]+')
          [ -z "$loc" ] && loc=$(printf '%s' "$seg" | grep -oE '"location":[0-9]+' | head -1 | grep -oE '[0-9]+')
        done
        itd=""; [ -n "$it" ] && itd=$(date -r $(( it/1000000 - 11644473600 )) '+%F %T' 2>/dev/null)
        flag=""; [ -n "$it" ] && [ $(( it/1000000 - 11644473600 )) -gt $(( $(date +%s) - DAYS*86400 )) ] && flag="NEW-IN-WINDOW"
        case "$loc" in 4|8) flag="$flag SIDELOADED";; 9|7) flag="$flag POLICY-INSTALLED";; esac
        case "$up" in *google.com*|*edge.microsoft.com*|*brave.com*|"") ;; *) flag="$flag NON-STORE-UPDATE-URL";; esac
        echo "   EXT $id | $nm | v=$v | installed=${itd:-?} loc=${loc:-?} | update_url=${up:-none} | perms=$perms | hosts=$hp ${flag:+| $flag}"
      done
    done
  done
  echo "== Chrome/Edge/Brave managed policies (ExtensionInstallForcelist, HomepageLocation, DefaultSearchProvider*, Proxy*; MDM or malware both write these):"
  for f in /Library/Managed\ Preferences/*/com.google.Chrome.plist /Library/Managed\ Preferences/com.google.Chrome.plist "$UHOME/Library/Preferences/com.google.Chrome.plist" /Library/Preferences/com.google.Chrome.plist /Library/Managed\ Preferences/*/com.microsoft.Edge.plist /Library/Managed\ Preferences/*/com.brave.Browser.plist; do
    [ -f "$f" ] || continue; o=$(plutil -p "$f" 2>/dev/null | grep -E 'ExtensionInstallForcelist|ExtensionInstallSources|HomepageLocation|RestoreOnStartupURLs|DefaultSearchProvider|Proxy|NewTabPageLocation|AlternateErrorPages|ExtensionSettings|DeveloperToolsAvailability' | head -20); [ -n "$o" ] && { echo "== $f"; printf '%s\n' "$o" | sed 's/^/   POLICY /'; }
  done
  echo "== Safari (homepage, search, extensions):"
  for f in "$UHOME/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist" "$UHOME/Library/Preferences/com.apple.Safari.plist"; do [ -f "$f" ] && plutil -p "$f" 2>/dev/null | grep -E 'HomePage|SearchProviderIdentifier|NewTabBehavior|NewWindowBehavior|ExtensionsEnabled|HideStartPage' | head -10 | sed 's/^/   /'; done
  ls -lat "$UHOME/Library/Safari/Extensions" 2>/dev/null | head; ls -lat "$UHOME/Library/Safari/AppExtensions" 2>/dev/null | head
  echo "== Firefox (user.js = hand-written overrides; prefs.js homepage/search/proxy/enterprise roots):"
  for p in "$UHOME"/Library/Application\ Support/Firefox/Profiles/*; do [ -d "$p" ] || continue; echo "== $p"
    [ -f "$p/user.js" ] && { echo "   user.js EXISTS ($(stat -f '%Sm' "$p/user.js")):"; head -40 "$p/user.js" | sed 's/^/      /'; }
    grep -hE 'browser\.startup\.homepage|keyword\.URL|browser\.search\.|network\.proxy\.|security\.enterprise_roots|extensions\.enabledScopes|app\.update\.enabled|browser\.newtab' "$p/prefs.js" 2>/dev/null | head -20 | sed 's/^/   /'
  done
  for f in /Applications/Firefox.app/Contents/Resources/distribution/policies.json /Library/Managed\ Preferences/*/org.mozilla.firefox.plist; do [ -f "$f" ] && { echo "== $f (enterprise policy):"; head -60 "$f" | sed 's/^/   /'; }; done
  return 0
}
section 29_tamper_and_hijack tamper_checks

############################ 30. network history / live connections ############################
network_history() {
  echo "RED FLAG: a default route or DNS/proxy you did not set; an /etc/resolver entry; a pf anchor or rule you did not add; a content-filter/DNS-proxy/VPN extension from an unknown bundle id; an ESTABLISHED connection whose process is unsigned/adhoc or lives in /tmp, /var/folders or ~/Library; an 'unattributed' remote IP that stays connected across runs."
  echo "No network lookups are done: IP annotations are coarse prefix matches (private / apple / google / cloudflare / fastly / akamai / microsoft / amazon-ish) and 'unattributed' only means not in those lists."
  echo
  echo "--- routes:"; netstat -rn 2>&1 | head -60
  echo; echo "--- ARP table (a MAC that changes for the gateway between runs = spoofing):"; arp -an 2>&1 | head -40
  echo; echo "--- proxy (scutil --proxy):"; scutil --proxy 2>&1
  echo; echo "--- hardware ports / services:"; networksetup -listallhardwareports 2>&1 | head -60; networksetup -listnetworkserviceorder 2>&1 | head -40
  echo; echo "--- VPN / network configurations (scutil --nc) and SystemConfiguration services:"; scutil --nc list 2>&1
  plutil -p /Library/Preferences/SystemConfiguration/preferences.plist 2>/dev/null | grep -E '"UserDefinedName"|ProxyAutoConfigURLString|ProxyAutoConfigEnable|HTTPProxy|HTTPSProxy|SOCKSProxy|"ServerAddresses"|"SearchDomains"|"AuthorizationID"' | sort | uniq -c | sort -rn | head -40
  echo; echo "--- NetworkExtension registrations (content filters, DNS proxies, app proxies, packet tunnels; bundle ids):"
  plutil -p /Library/Preferences/com.apple.networkextension.plist 2>/dev/null | grep -oE '"(com|org|net|io|app|dev)\.[A-Za-z0-9._-]+"' | sort | uniq -c | sort -rn | head -40
  plutil -p /Library/Preferences/com.apple.networkextension.necp.plist 2>/dev/null | head -20
  echo; echo "--- known Wi-Fi networks (names and join times only; root needed):"
  plutil -p /Library/Preferences/com.apple.wifi.known-networks.plist 2>/dev/null | grep -E '^  "wifi\.network\.ssid\.|"AddedAt"|"JoinedByUserAt"|"JoinedBySystemAt"|"UpdatedAt"' | sed -E 's/^  "wifi\.network\.ssid\.(.*)" => \{/== \1/' | head -200
  echo; echo "--- pf firewall (root): anchors, rules, states summary:"; pfctl -s info 2>&1 | head -5; pfctl -s rules 2>&1 | head -60; pfctl -s Anchors -v 2>&1 | head -20; pfctl -s nat 2>&1 | head -20
  echo "== /etc/pf.conf non-default and /etc/pf.anchors:"; grep -vE '^#|^$' /etc/pf.conf 2>/dev/null | grep -vE '^(scrub-anchor|nat-anchor|rdr-anchor|dummynet-anchor|anchor|load anchor) "com\.apple' ; ls -la /etc/pf.anchors 2>/dev/null
  echo; echo "--- /etc/resolver/* (per-domain DNS overrides):"; ls -la /etc/resolver 2>&1; cat /etc/resolver/* 2>/dev/null
  echo "== DNS configuration:"; scutil --dns 2>&1 | grep -E 'resolver|nameserver|domain|search|flags' | head -40
  echo "== DNS cache stats (root):"; dscacheutil -statistics 2>&1 | head -20
  echo; echo "--- ESTABLISHED connections with process path + signer (lsof; non-root sees only your own processes):"
  local pid exe sig flag p
  lsof -nP -iTCP -sTCP:ESTABLISHED +c 0 2>/dev/null | awk 'NR>1 {print $2}' | sort -un | while read -r pid; do
    exe=$(ps -o comm= -p "$pid" 2>/dev/null); [ -z "$exe" ] && continue
    case "$exe" in /*) ;; *) p=$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | grep -m1 '^n/' | cut -c2-); [ -n "$p" ] && exe="$p";; esac
    case "$exe" in /*) ;; *) p=$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | grep -m1 '^n/' | cut -c2-); [ -n "$p" ] && exe="$p";; esac
    sig=$(sig_of "$exe" 2>/dev/null)
    case "$exe" in /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*|/Users/Shared/*|"$UHOME"/Library/*) flag="ODD-PATH";; *) flag="";; esac
    case "$sig" in unsigned|adhoc) flag="$flag UNSIGNED";; esac
    echo "== pid=$pid $exe | $sig ${flag:+| $flag}"
    lsof -nP -iTCP -sTCP:ESTABLISHED -a -p "$pid" 2>/dev/null | awk 'NR>1 {print "   " $9}' | sort -u | head -20
  done
  echo; echo "--- remote endpoints by attribution (unique ip:port, process; 'unattributed' = not private/Apple/known-CDN prefix):"
  lsof -nP -iTCP -sTCP:ESTABLISHED +c 0 2>/dev/null | awk 'NR>1 {split($9,a,"->"); print a[2] " " $1}' | sort -u | awk '
    function tag(ip,   o,n){ 
      if(ip ~ /^\[/) { if(ip ~ /^\[(fe80|fd|fc|::1)/) return "private-v6"; if(ip ~ /^\[2a01:b740|^\[2620:149|^\[2403:300/) return "apple"; return "unattributed-v6" }
      n=split(ip,o,"."); if(n<4) return "?"
      a=o[1]+0; b=o[2]+0
      if(a==10||a==127||(a==172&&b>=16&&b<=31)||(a==192&&b==168)||(a==169&&b==254)||(a==100&&b>=64&&b<=127)) return "private"
      if(a==17) return "apple"
      if((a==142&&b>=250&&b<=251)||(a==172&&b==217)||(a==216&&b==58)||(a==74&&b==125)||(a==64&&b>=233&&b<=233)||(a==108&&b==177)||(a==173&&b==194)||(a==209&&b==85)||(a==34&&b>=64&&b<=127)||(a==35&&b>=184&&b<=247)) return "google"
      if((a==104&&b>=16&&b<=31)||(a==172&&b>=64&&b<=71)||(a==162&&b>=158&&b<=159)||(a==188&&b==114)||(a==198&&b==41)||(a==1&&b==1)) return "cloudflare"
      if(a==151&&b==101) return "fastly"
      if((a==23&&b>=0&&b<=79)||(a==184&&b>=24&&b<=31)||(a==2&&b>=16&&b<=23)||(a==95&&b>=100&&b<=101)) return "akamai"
      if((a==13&&b>=64&&b<=107)||(a==20&&b>=33&&b<=128)||(a==40&&b>=74&&b<=127)||(a==52&&b>=96&&b<=191)||(a==51&&b>=140&&b<=143)||(a==4&&b>=144&&b<=255)) return "microsoft"
      if((a==52&&b>=0&&b<=95)||(a==54)||(a==3&&b>=0&&b<=255)||(a==18)||(a==34&&b>=192&&b<=255)||(a==35&&b>=152&&b<=183)||(a==13&&b>=32&&b<=59)||(a==15&&b>=160&&b<=255)||(a==99&&b>=77&&b<=84)||(a==65&&b>=0&&b<=15)) return "amazon-ish"
      if(a==199&&b==232) return "fastly"
      if((a==157&&b==240)||(a==31&&b==13)||(a==163&&b==70)||(a==129&&b==134)) return "meta"
      if(a==140&&b==82||a==192&&b==30||a==185&&b==199) return "github"
      return "unattributed"
    }
    { ip=$1; sub(/:[0-9]+$/,"",ip); printf "%-14s %-45s %s\n", tag(ip), $1, $2 }' | sort | head -200
  echo; echo "--- listeners (anything bound to 0.0.0.0/* on an odd port):"; lsof -nP -iTCP -sTCP:LISTEN +c 0 2>/dev/null | awk 'NR>1 {print $1, $2, $9}' | sort -u | head -60
  echo; echo "--- UDP sockets (beacons over UDP/QUIC):"; lsof -nP -iUDP +c 0 2>/dev/null | awk 'NR>1 && $9 !~ /\*:\*$/ {print $1, $2, $9}' | sort -u | head -60
  return 0
}
section 30_network_history network_history

############################ 31. VirusTotal hash lookups (opt-in: -V and VT_API_KEY) ############################
if [ "$VT_LOOKUP" -eq 1 ]; then
  vt_lookup() {
    echo "Opt-in (-V). Hash lookups only (GET /api/v3/files/<sha256>): nothing is uploaded. Hashes come from 25_suspect_files.txt, 26 unsigned Mach-Os and 13 running binaries; bounded to 25 lookups. Output is hash + verdict only."
    echo "RED FLAG: malicious > 0 on anything; 'not found' on an unsigned binary that is not your own build."
    [ -z "${VT_API_KEY:-}" ] && { echo "VT_API_KEY is not set; skipped."; return; }
    { grep -hoE '^[0-9a-f]{64}$' "$OUT/25_suspect_files.txt" 2>/dev/null; grep -h 'sha256:' "$OUT/13_processes.txt" "$OUT/11_recent_executables.txt" 2>/dev/null | grep -oE '[0-9a-f]{64}'; grep -E '^HEUR heuristic=(unsigned_macho_userdir|stealer_strings_in_binary) ' "$OUT/26_malware_iocs.txt" 2>/dev/null | sed -E 's/^HEUR [^=]*=[^ ]* where=//; s/ \|.*//' | while IFS= read -r f; do [ -f "$f" ] && shasum -a 256 "$f" | cut -c1-64; done; } | sort -u | head -25 | while IFS= read -r h; do
      r=$(curl -s -m 20 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/$h" 2>/dev/null)
      case "$r" in *NotFoundError*) echo "$h  not found";; "") echo "$h  no response (offline?)";; *) echo "$h  $(printf '%s' "$r" | tr -d '\n ' | grep -oE '"last_analysis_stats":\{[^}]*\}' | head -1)  $(printf '%s' "$r" | tr -d '\n' | grep -oE '"popular_threat_label": *"[^"]*"' | head -1)";; esac
      sleep 1
    done
  }
  section 31_virustotal vt_lookup
fi
rm -f "$ALLB"

############################ 10. summary / pack ############################
cnt() { local n; n=$(grep -c "$@" 2>/dev/null); echo "${n:-0}"; }   # grep -c that always prints an integer (0 when the file is missing)
{
  echo "# Triage summary  host=$HOST user=$TARGET_USER window=${DAYS}d logwindow=$LOGWIN quick=$QUICK collected=$(date -u +%FT%TZ) root=$IS_ROOT"
  echo
  echo "## Read these first, in this order"
  echo "  26_malware_iocs.txt        - KNOWN-FAMILY IOC sweep + generic stealer heuristics; any 'IOC ' or 'HEUR ' line is a finding until explained"
  echo "  25_suspect_files.txt       - every downloaded PDF/DMG/PKG/ZIP/script in the window: real type, active content, URLs, where it came from, when opened"
  echo "  07_quarantine_events.txt   - every download by URL+time (the PDF and anything fetched after it)"
  echo "  08_downloaded_files.txt    - quarantined files still on disk, with source URL"
  echo "  09_browser_downloads.txt   - browser download/visit history around the phishing time"
  echo "  11_recent_executables.txt  - new Mach-O/scripts; anything 'not signed' / adhoc / in ~/Library, /tmp, /var/folders is a red flag"
  echo "  03/04_persistence_*.txt    - LaunchAgents/Daemons, BTM login items, cron, kexts added in window"
  echo "  05_persistence_shellrc.txt - rc files modified in window"
  echo "  29_tamper_and_hijack.txt   - added root CAs, profiles, /etc/hosts, pam/sshd changes, login mechanisms, SIP/Gatekeeper, codesign failures, browser homepage/search/extension/policy hijacks"
  echo "  27_login_activity.txt      - who logged in / unlocked / sudo'd / ssh'd, when, from where; FAIL bursts = password guessing"
  echo "  28_script_execution.txt    - every user's shell history, interpreter spawns, #! scripts born in the window, Terminal profile commands, Automator/Shortcuts"
  echo "  15_tcc_permissions.txt     - screen recording / accessibility / full-disk grants to unknown clients"
  echo "  13_processes.txt + 14_network.txt + 30_network_history.txt - live beacons, unsigned binaries, odd DNS/proxy/routes/pf/NetworkExtension, unattributed remote IPs"
  echo "  18_unifiedlog_execution.txt - PROCESS SPAWN TIMELINE (launchd), osascript 'display dialog' (password-prompt stealers), curl|sh, sudo"
  echo "  24_credential_files.txt    - what was reachable; assume all of it is stolen if anything above is positive"
  echo "  16_shell_history.txt       - commands you did NOT type"
  [ "$VT_LOOKUP" -eq 1 ] && echo "  31_virustotal.txt          - hash verdicts for suspect/unsigned/running binaries (opt-in)"
  echo
  echo "## Quick counts"
  echo "  quarantine events in window : $(cnt -E '^[0-9]{4}-' "$OUT/07_quarantine_events.txt")"
  echo "  user LaunchAgents           : $(find "$UHOME/Library/LaunchAgents" -maxdepth 1 -name '*.plist' 2>/dev/null | wc -l | tr -d ' ')"
  echo "  system LaunchAgents/Daemons : $(find /Library/LaunchAgents /Library/LaunchDaemons -maxdepth 1 -name '*.plist' 2>/dev/null | wc -l | tr -d ' ')"
  echo "  recent executables found    : $(cnt 'sha256:' "$OUT/11_recent_executables.txt")"
  echo "  unsigned among them         : $(cnt "code object is not signed" "$OUT/11_recent_executables.txt")"
  echo "  unsigned running binaries   : $(cnt "code object is not signed" "$OUT/13_processes.txt")"
  echo "  established connections     : $(cnt ESTABLISHED "$OUT/14_network.txt")"
  echo "  osascript/display dialog log lines : $(cnt -iE 'display dialog' "$OUT/18_unifiedlog_execution.txt")"
  echo "  XProtect/Gatekeeper log lines      : $(cnt -E 'XProtect|blocked|malware' "$OUT/19_unifiedlog_gatekeeper.txt")"
  echo "  --- detection sections (26-30)"
  echo "  IOC matches (known families)       : $(cnt '^IOC ' "$OUT/26_malware_iocs.txt")"
  echo "  heuristic hits                     : $(cnt '^HEUR ' "$OUT/26_malware_iocs.txt")"
  echo "  failed logins / auth failures      : $(cnt ' | FAIL | ' "$OUT/27_login_activity.txt")"
  echo "  sudo commands (log window)         : $(cnt -E ' \| sudo \| .* \| OK \| ' "$OUT/27_login_activity.txt")"
  echo "  interpreter spawns (launchd)       : $(cnt '^SPAWN ' "$OUT/28_script_execution.txt")"
  echo "  #! scripts born in window          : $(cnt '^SHEBANG ' "$OUT/28_script_execution.txt")"
  echo "  non-Apple root CAs / trust entries : $(cnt '^CA ' "$OUT/29_tamper_and_hijack.txt")"
  echo "  profiles installed                 : $(cnt 'profileIdentifier:' "$OUT/29_tamper_and_hijack.txt")"
  echo "  codesign failures (changed apps)   : $(cnt '^CODESIGN-FAIL' "$OUT/29_tamper_and_hijack.txt")"
  echo "  non-Apple auth mechanisms          : $(cnt 'NON-APPLE-MECHANISM' "$OUT/29_tamper_and_hijack.txt")"
  echo "  system files changed after OS update: $(cnt 'MODIFIED-AFTER-OS-UPDATE' "$OUT/29_tamper_and_hijack.txt")"
  echo "  sideloaded/policy browser extensions: $(cnt -E 'SIDELOADED|POLICY-INSTALLED|NON-STORE-UPDATE-URL' "$OUT/29_tamper_and_hijack.txt")"
  echo "  unattributed remote connections    : $(cnt '^unattributed' "$OUT/30_network_history.txt")"
  echo "  connections from odd/unsigned procs: $(cnt -E 'ODD-PATH|UNSIGNED' "$OUT/30_network_history.txt")"
  echo
  echo "## Caveats"
  echo "  - [exit=1] at the end of a section usually just means the last grep/find matched nothing or hit a permission-denied dir; it is not a script failure."
  echo "  - macOS keeps no default exec audit trail; execution is inferred from quarantine, Gatekeeper/syspolicy, BTM, shell history, file birth times and unified log."
  echo "  - A stealer (e.g. AMOS-type) needs no persistence: one run, exfil keychain/browser/cloud creds, exit. Empty persistence does NOT mean clean."
  echo "  - 'no IOC matches' means none of the bundled indicators matched; the list is a snapshot of public reporting and goes stale. Heuristics and the other sections still apply."
  echo "  - If the window was > log retention, unified-log sections will be truncated at the oldest kept entry."
  echo "  - For a live exec trace from now on: sudo eslogger exec open > exec.jsonl   (macOS 13+)"
  echo "  - For Apple's full dump: sudo sysdiagnose -f /Users/Shared   (large, slow, includes everything above and more)"
} > "$OUT/00_SUMMARY.txt"

chmod -R go-rwx "$OUT" 2>/dev/null
[ $IS_ROOT -eq 1 ] && chown -R "$TARGET_USER" "$OUT" 2>/dev/null
tar -czf "$OUT.tgz" -C "$(dirname "$OUT")" "$(basename "$OUT")" && shasum -a 256 "$OUT.tgz" > "$OUT.tgz.sha256"
echo
echo "== done. Output: $OUT"
echo "== archive: $OUT.tgz  ($(cat "$OUT.tgz.sha256" | cut -c1-16)...)"
echo "== start with: $OUT/00_SUMMARY.txt"
