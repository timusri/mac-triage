#!/bin/bash
# mac_triage.sh - READ-ONLY macOS incident triage collector.
#
# Collects evidence of what was downloaded / executed / persisted on a Mac after a
# suspected phishing compromise. It never modifies, deletes or "cleans" anything.
#
# Run from a Terminal that has Full Disk Access (System Settings > Privacy & Security
# > Full Disk Access > Terminal), ideally with sudo so system logs, TCC and
# Background Task Management data are readable:
#
#   sudo bash mac_triage.sh            # full run, no flags needed: 30-day file window, 7-day log window, all downloads analysed
#   sudo bash mac_triage.sh [-d DAYS] [-l WIN] [-q] [-u USER] [-o OUTDIR] [-p FILE]   # optional tuning
#
#   -d DAYS   look-back window for "recent" (default 30)
#   -u USER   the user whose account was phished (default: the sudo-ing user)
#   -o OUTDIR where to write (default: /Users/Shared/triage-<host>-<ts>) - point this
#             at an external drive if you can.
#   -p FILE   a specific suspected file to analyse (every quarantined download in the window is analysed anyway)
#   -l WIN    unified-log window, e.g. 12h, 3d (default 7d). Log scans are the slow part: 1d on a busy Mac can take 5-10 min per query.
#   -q        quick mode: skip the deep filesystem walks (sections 10, 11) - run this first, then the full run.
#
# Output: a directory of .txt files + a .tgz + sha256, nothing else is written.
set -u
set +e

DAYS=30
LOGWIN=7d
QUICK=0
OUTDIR=""
SUSPECT=""
TARGET_USER="${SUDO_USER:-$(whoami)}"
while getopts "d:u:o:p:l:qh" opt; do
  case "$opt" in
    d) DAYS="$OPTARG" ;;
    u) TARGET_USER="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    p) SUSPECT="$OPTARG" ;;
    l) LOGWIN="$OPTARG" ;;
    q) QUICK=1 ;;
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
PFX="$OUT/${HOST}"

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
UNION='(process == "launchd" AND eventMessage CONTAINS "added unmanaged") OR process == "sudo" OR eventMessage CONTAINS "display dialog" OR eventMessage CONTAINS "curl " OR eventMessage CONTAINS "chmod +x" OR eventMessage CONTAINS "nohup" OR eventMessage CONTAINS "base64 -" OR eventMessage CONTAINS "python3 -c" OR eventMessage CONTAINS "bash -c" OR (process == "syspolicyd" AND (eventMessage CONTAINS "GK" OR eventMessage CONTAINS "assessment" OR eventMessage CONTAINS "Gatekeeper" OR eventMessage CONTAINS "blocked" OR eventMessage CONTAINS "malware" OR eventMessage CONTAINS "quarantine" OR eventMessage CONTAINS "notariz")) OR (process BEGINSWITH "XProtect" AND (eventMessage CONTAINS "detect" OR eventMessage CONTAINS "remediat" OR eventMessage CONTAINS "malware" OR eventMessage CONTAINS "XPEvent")) OR process == "XProtectRemediator" OR subsystem == "com.apple.backgroundtaskmanagement" OR (process == "launchd" AND (eventMessage CONTAINS "LaunchAgents" OR eventMessage CONTAINS "LaunchDaemons")) OR (subsystem == "com.apple.TCC" AND (eventMessage CONTAINS "Granting" OR eventMessage CONTAINS "AUTHREQ_RESULT" OR eventMessage CONTAINS "Handling access request" OR eventMessage CONTAINS "Override" OR eventMessage CONTAINS "update access record" OR eventMessage CONTAINS "Prompting policy for hardened runtime; service")) OR process == "sshd" OR process == "sshd-session" OR process == "screensharingd" OR (process == "SecurityAgent" AND subsystem == "com.apple.Authorization") OR process BEGINSWITH "Adobe" OR eventMessage CONTAINS[c] ".pdf"'
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
rm -f "$ALLB"

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
      *Zip*|*zip*)
        echo "--- archive listing:"; unzip -l "$f" 2>&1 | head -40 ;;
      *"disk image"*|*DMG*|*"Apple Disk Image"*|*zlib*|*bzip2*)
        echo "--- disk image (NOT mounted). hdiutil imageinfo:"; hdiutil imageinfo "$f" 2>&1 | grep -E 'Format|Checksum|Size Information' -A1 | head -12 ;;
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

############################ 10. summary / pack ############################
{
  echo "# Triage summary  host=$HOST user=$TARGET_USER window=${DAYS}d logwindow=$LOGWIN quick=$QUICK collected=$(date -u +%FT%TZ) root=$IS_ROOT"
  echo
  echo "## Read these first, in this order"
  echo "  25_suspect_files.txt       - every downloaded PDF/DMG/PKG/ZIP/script in the window: real type, active content, URLs, where it came from, when opened"
  echo "  07_quarantine_events.txt   - every download by URL+time (the PDF and anything fetched after it)"
  echo "  08_downloaded_files.txt    - quarantined files still on disk, with source URL"
  echo "  09_browser_downloads.txt   - browser download/visit history around the phishing time"
  echo "  11_recent_executables.txt  - new Mach-O/scripts; anything 'not signed' / adhoc / in ~/Library, /tmp, /var/folders is a red flag"
  echo "  03/04_persistence_*.txt    - LaunchAgents/Daemons, BTM login items, cron, kexts added in window"
  echo "  05_persistence_shellrc.txt - rc files modified in window"
  echo "  15_tcc_permissions.txt     - screen recording / accessibility / full-disk grants to unknown clients"
  echo "  13_processes.txt + 14_network.txt - live beacons, unsigned binaries, odd DNS/proxy"
  echo "  18_unifiedlog_execution.txt - PROCESS SPAWN TIMELINE (launchd), osascript 'display dialog' (password-prompt stealers), curl|sh, sudo"
  echo "  24_credential_files.txt    - what was reachable; assume all of it is stolen if anything above is positive"
  echo "  16_shell_history.txt       - commands you did NOT type"
  echo
  echo "## Quick counts"
  echo "  quarantine events in window : $(grep -cE '^[0-9]{4}-' "$OUT/07_quarantine_events.txt" 2>/dev/null)"
  echo "  user LaunchAgents           : $(ls "$UHOME/Library/LaunchAgents" 2>/dev/null | wc -l | tr -d ' ')"
  echo "  system LaunchAgents/Daemons : $(ls /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null | grep -c plist)"
  echo "  recent executables found    : $(grep -c 'sha256:' "$OUT/11_recent_executables.txt" 2>/dev/null)"
  echo "  unsigned among them         : $(grep -c "code object is not signed" "$OUT/11_recent_executables.txt" 2>/dev/null)"
  echo "  unsigned running binaries   : $(grep -c "code object is not signed" "$OUT/13_processes.txt" 2>/dev/null)"
  echo "  established connections     : $(grep -c ESTABLISHED "$OUT/14_network.txt" 2>/dev/null)"
  echo "  osascript/display dialog log lines : $(grep -ciE 'display dialog' "$OUT/18_unifiedlog_execution.txt" 2>/dev/null)"
  echo "  XProtect/Gatekeeper log lines      : $(grep -cE 'XProtect|blocked|malware' "$OUT/19_unifiedlog_gatekeeper.txt" 2>/dev/null)"
  echo
  echo "## Caveats"
  echo "  - [exit=1] at the end of a section usually just means the last grep/find matched nothing or hit a permission-denied dir; it is not a script failure."
  echo "  - macOS keeps no default exec audit trail; execution is inferred from quarantine, Gatekeeper/syspolicy, BTM, shell history, file birth times and unified log."
  echo "  - A stealer (e.g. AMOS-type) needs no persistence: one run, exfil keychain/browser/cloud creds, exit. Empty persistence does NOT mean clean."
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
