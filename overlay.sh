#!/bin/bash
set -euo pipefail

# =============================================================================
# SecureVis Overlay Sandbox — FINAL COMPLETE EDITION
#
# Hardening layers (in order of execution):
#
#   LAYER 1  — OverlayFS filesystem isolation (copy-on-write)
#   LAYER 2  — Linux namespace isolation (PID/NET/IPC/UTS via unshare)
#   LAYER 3  — Linux capability dropping (capsh)
#   LAYER 4  — Kernel-enforced resource limits (ulimit)
#   LAYER 5  — Syscall tracing (strace)
#   LAYER 6  — /proc/[pid]/maps rwx region detection (injection detection)
#   LAYER 7  — Honeypot tripwires (inotify, 10 decoy files)
#   LAYER 8  — General filesystem audit (inotify recursive)
#   LAYER 9  — Behavioral anomaly poller (CPU, children, rwx)
#   LAYER 10 — Webcam snapshot on suspicious events
#   LAYER 11 — Pre-session auth gate with attempt limit
#   LAYER 12 — Structured JSON event log (consumed by collector + GUI)
#   LAYER 13 — Forensic diff report (SHA-256, modified files, verdict)
# =============================================================================

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$LOG_DIR" "$PROJECT_DIR"/{lower,upper,work,merged}

# ── Runtime IPC files (read by securevis-collector.py) ───────────────────────
SANDBOX_PID_FILE="/tmp/securevis_sandbox.pid"
EVENTS_FILE="/tmp/securevis_events.json"
FILE_LOG="$LOG_DIR/file_changes.log"
SYSCALL_LOG="$LOG_DIR/syscall_trace.log"
ANOMALY_LOG="$LOG_DIR/anomaly.log"
DIFF_REPORT="$LOG_DIR/session_diff.txt"

touch "$FILE_LOG" "$ANOMALY_LOG"
echo "[]" > "$EVENTS_FILE"

# ── Configuration ─────────────────────────────────────────────────────────────
ENABLE_WEBCAM=false           # Set true only after USB passthrough is confirmed
WEBCAM_TOOL="fswebcam"        # "fswebcam" (preferred) or "ffmpeg"
WEBCAM_DEVICE="/dev/video0"
MAX_ATTEMPTS=2
ANOMALY_POLL_INTERVAL=2       # seconds between behavioral polls
CPU_ANOMALY_THRESHOLD=80      # CPU% to flag as anomaly

# 10 honeypot files — varied types to catch different recon patterns
HONEYPOT_NAMES=(
    "passwords.txt"
    ".ssh_keys.txt"
    "id_rsa"
    ".aws_credentials"
    "secrets.db"
    "deploy_keys"
    "README_FOR_HACKERS"
    ".env"
    "database.conf"
    "api_tokens.json"
)

# Capabilities to drop (requires libcap2-bin)
DROP_CAPS="cap_net_raw,cap_sys_admin,cap_sys_ptrace,cap_sys_module,cap_sys_boot,cap_net_bind_service"

# ── Colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log() {
    echo -e "[$(date '+%F %T')] $*" | tee -a "$FILE_LOG"
}

log_anomaly() {
    echo -e "[$(date '+%F %T')] $*" | tee -a "$ANOMALY_LOG"
}

# Atomically append one event object to the JSON events array
emit_event() {
    local type="$1"
    local detail="${2:-}"
    local snapshot="${3:-}"
    local ts
    ts=$(date +%s.%N)
    local tmp
    tmp=$(mktemp /tmp/sv_evt_XXXXXX)

    python3 - <<PYEOF 2>/dev/null || true
import json
try:
    with open("$EVENTS_FILE") as f:
        arr = json.load(f)
except Exception:
    arr = []
arr.append({
    "timestamp": $ts,
    "type":      "$type",
    "detail":    "$detail",
    "snapshot":  "$snapshot"
})
with open("$tmp", "w") as f:
    json.dump(arr, f)
PYEOF
    mv "$tmp" "$EVENTS_FILE" 2>/dev/null || true
}

# =============================================================================
# LAYER 10 — WEBCAM SNAPSHOT
# =============================================================================
take_snapshot() {
    local reason="${1:-UNKNOWN}"
    local ts out
    ts=$(date '+%F_%H-%M-%S')
    out="$LOG_DIR/snapshot_${ts}.jpg"

    if [[ "$ENABLE_WEBCAM" != "true" ]]; then
        log "SNAPSHOT_SKIPPED ($reason) — set ENABLE_WEBCAM=true to enable"
        emit_event "SNAPSHOT_SKIPPED" "$reason"
        return 0
    fi
    if [[ ! -e "$WEBCAM_DEVICE" ]]; then
        log "${YELLOW}WEBCAM_NOT_FOUND${RESET} $WEBCAM_DEVICE"
        emit_event "WEBCAM_NOT_FOUND" "$WEBCAM_DEVICE"
        return 0
    fi

    if [[ "$WEBCAM_TOOL" == "fswebcam" ]] && command -v fswebcam &>/dev/null; then
        fswebcam -r 1280x720 --no-banner "$out" &>/dev/null \
            && log "${GREEN}SNAPSHOT saved:${RESET} $out" \
            || log "${RED}SNAPSHOT FAILED${RESET} (fswebcam error)"
    elif command -v ffmpeg &>/dev/null; then
        ffmpeg -f v4l2 -video_size 1280x720 -i "$WEBCAM_DEVICE" \
               -frames:v 1 "$out" -y &>/dev/null \
            && log "${GREEN}SNAPSHOT saved:${RESET} $out" \
            || log "${RED}SNAPSHOT FAILED${RESET} (ffmpeg error)"
    else
        log "${RED}SNAPSHOT FAILED${RESET} — install fswebcam: sudo apt install fswebcam"
        return 0
    fi

    [[ -f "$out" ]] && emit_event "WEBCAM_SNAPSHOT" "$reason" "$out"
    return 0
}

# =============================================================================
# LAYER 11 — PRE-SESSION AUTH GATE
# =============================================================================
check_password() {
    local attempt=1
    while (( attempt <= MAX_ATTEMPTS )); do
        echo -ne "${BOLD}Enter sudo password (attempt $attempt/$MAX_ATTEMPTS): ${RESET}"
        read -rs SUDO_PASS; echo
        if echo "$SUDO_PASS" | sudo -k -S true &>/dev/null 2>&1; then
            echo "$SUDO_PASS" | sudo -S true &>/dev/null || true
            unset SUDO_PASS
            echo -e "${GREEN}✅ Password verified.${RESET}"
            return 0
        fi
        echo -e "${RED}❌ Incorrect password.${RESET}"
        (( attempt++ ))
    done
    log "FAILED_PASSWORD_ATTEMPTS — aborting"
    emit_event "AUTH_FAILURE" "max password attempts exceeded"
    take_snapshot "AUTH_FAILURE"
    echo -e "${RED}Too many failed attempts. Session aborted.${RESET}"
    exit 1
}

# =============================================================================
# DEPENDENCY CHECK
# =============================================================================
check_deps() {
    local missing=() optional_missing=()
    for cmd in inotifywait python3 strace; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    for cmd in capsh lsof sha256sum; do
        command -v "$cmd" &>/dev/null || optional_missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        echo -e "${RED}⚠️  Missing required tools: ${missing[*]}${RESET}"
        echo "   Install: sudo apt install inotify-tools strace python3"
    fi
    if (( ${#optional_missing[@]} > 0 )); then
        echo -e "${YELLOW}ℹ️  Optional tools not found: ${optional_missing[*]}${RESET}"
        echo "   Install: sudo apt install libcap2-bin lsof coreutils"
    fi
}

# =============================================================================
# LAYER 8 — GENERAL FILESYSTEM AUDIT WATCHER
# =============================================================================
start_fs_watcher() {
    command -v inotifywait &>/dev/null || return
    (
        inotifywait -m -r \
            -e create,modify,delete,move,attrib \
            --format '%T %e %w%f' --timefmt '%F %T' \
            "$PROJECT_DIR/merged" 2>/dev/null \
        | while read -r line; do
            echo "$line" >> "$FILE_LOG"
            local count
            count=$(grep -c "OPEN\|ACCESS" "$FILE_LOG" 2>/dev/null || echo 0)
            if (( count > 50 )) && (( count % 50 == 0 )); then
                emit_event "MASS_FILE_ACCESS" "count=$count"
            fi
        done
    ) &
    echo $! > "$LOG_DIR/fs_watcher.pid"
    log "FS watcher started (PID $!)"
}

# =============================================================================
# LAYER 7 — HONEYPOT TRIPWIRES
# =============================================================================
plant_honeypots() {
    for name in "${HONEYPOT_NAMES[@]}"; do
        local hp="$PROJECT_DIR/merged/$name"
        [[ -e "$hp" ]] && continue
        case "$name" in
            *.txt|*.conf|deploy_keys)
                printf "# DO NOT SHARE\npassword=S3cur3P@ss!\napi_key=AKIA_DECOY_4B3C2A1D\ndb_pass=hunter2\n" > "$hp" ;;
            id_rsa)
                printf "-----BEGIN RSA PRIVATE KEY-----\nDECOY_KEY_NOT_REAL_DO_NOT_USE\n-----END RSA PRIVATE KEY-----\n" > "$hp" ;;
            *.db)
                printf "SQLite decoy database -- access is monitored and logged\n" > "$hp" ;;
            *.json)
                printf '{"api_key":"DECOY_TOKEN_abc123","secret":"DECOY_SECRET_xyz789"}\n' > "$hp" ;;
            .env)
                printf "DATABASE_URL=postgres://admin:decoy_pass@localhost/prod\nSECRET_KEY=decoy_secret_key_123\n" > "$hp" ;;
            *)
                printf "CONFIDENTIAL — Access to this file is monitored and logged.\n" > "$hp" ;;
        esac
        chmod 600 "$hp" 2>/dev/null || true
    done
    log "Honeypot files planted (${#HONEYPOT_NAMES[@]} files)"
}

start_honeypot_watcher() {
    command -v inotifywait &>/dev/null || {
        log "${YELLOW}inotifywait missing — honeypot monitoring disabled${RESET}"
        return
    }

    local watch_paths=()
    for name in "${HONEYPOT_NAMES[@]}"; do
        local hp="$PROJECT_DIR/merged/$name"
        [[ -f "$hp" ]] && watch_paths+=("$hp")
    done
    (( ${#watch_paths[@]} == 0 )) && return

    (
        inotifywait -m \
            -e open,access,read,modify,create,delete \
            --format '%T %w%f %e' --timefmt '%F %T' \
            "${watch_paths[@]}" 2>/dev/null \
        | while read -r TS FPATH EVENT; do
            log "${RED}HONEYPOT_EVENT${RESET} $EVENT → $FPATH"

            # lsof: who opened the file
            if command -v lsof &>/dev/null; then
                {
                    echo "=== lsof context $TS ==="
                    lsof "$FPATH" 2>/dev/null || echo "(no holders or insufficient perms)"
                    echo "================================"
                } >> "$FILE_LOG"
            fi

            # Running processes at time of access
            {
                echo "=== ps context $TS ==="
                ps auxf --no-header 2>/dev/null | head -20
                echo "================================"
            } >> "$FILE_LOG"

            emit_event "HONEYPOT_ACCESS" "$EVENT:$FPATH"
            take_snapshot "HONEYPOT_ACCESS:$(basename "$FPATH")"
        done
    ) &
    echo $! > "$LOG_DIR/honeypot_watcher.pid"
    log "Honeypot watcher started (PID $!), watching ${#watch_paths[@]} files"
}

# =============================================================================
# LAYER 9 — BEHAVIORAL ANOMALY POLLER
# Background loop — polls sandbox child PIDs every N seconds
# =============================================================================
start_anomaly_poller() {
    (
        while true; do
            sleep "$ANOMALY_POLL_INTERVAL"
            [[ -f "$SANDBOX_PID_FILE" ]] || continue
            local spid
            spid=$(cat "$SANDBOX_PID_FILE" 2>/dev/null) || continue
            [[ -z "$spid" ]] && continue

            local children
            children=$(pgrep -P "$spid" 2>/dev/null || true)
            [[ -z "$children" ]] && children="$spid"

            for pid in $children; do
                [[ -d "/proc/$pid" ]] || continue

                # --- CPU anomaly ---
                if [[ -f "/proc/$pid/stat" ]]; then
                    local utime stime
                    # shellcheck disable=SC2034
                    read -r _a _b _c _d _e _f _g _h _i _j _k _l utime stime _ < "/proc/$pid/stat" 2>/dev/null || continue
                    local t1=$(( utime + stime ))
                    sleep 0.5
                    read -r _a _b _c _d _e _f _g _h _i _j _k _l utime stime _ < "/proc/$pid/stat" 2>/dev/null || continue
                    local t2=$(( utime + stime ))
                    local cpu=$(( (t2 - t1) * 100 / 5 ))
                    if (( cpu > CPU_ANOMALY_THRESHOLD )); then
                        local pname
                        pname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
                        log_anomaly "${RED}HIGH_CPU_ANOMALY${RESET} pid=$pid name=$pname cpu~=${cpu}%"
                        emit_event "HIGH_CPU_ANOMALY" "pid=$pid,name=$pname,cpu=${cpu}%"
                    fi
                fi

                # --- LAYER 6: RWX memory region (process injection indicator T1055) ---
                if [[ -f "/proc/$pid/maps" ]]; then
                    if grep -qP '^[0-9a-f]+-[0-9a-f]+ rwxp' "/proc/$pid/maps" 2>/dev/null; then
                        local pname
                        pname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
                        log_anomaly "${RED}RWX_MEMORY_REGION${RESET} pid=$pid name=$pname — possible process injection (T1055)"
                        emit_event "RWX_MEMORY_REGION" "pid=$pid,name=$pname"
                        take_snapshot "RWX_MEMORY_REGION:pid=$pid"
                    fi
                fi

                # --- Unexpected child spawn ---
                local nchildren
                nchildren=$(pgrep -P "$pid" 2>/dev/null | wc -l || echo 0)
                if (( nchildren > 3 )); then
                    log_anomaly "${YELLOW}UNEXPECTED_CHILD_SPAWN${RESET} pid=$pid spawned $nchildren children"
                    emit_event "UNEXPECTED_CHILD" "pid=$pid,children=$nchildren"
                fi
            done
        done
    ) &
    echo $! > "$LOG_DIR/anomaly_poller.pid"
    log "Behavioral anomaly poller started (PID $!)"
}

# =============================================================================
# LAYER 13 — FORENSIC DIFF REPORT
# =============================================================================
generate_diff_report() {
    local binary_name="$1"
    {
        echo "================================================================"
        echo "  SECUREVIS FORENSIC DIFF REPORT"
        echo "  Session ended : $(date '+%F %T')"
        echo "  Sandboxed file: $binary_name"
        echo "================================================================"
        echo ""
        echo "FILES CREATED OR MODIFIED INSIDE SANDBOX:"
        echo "----------------------------------------------------------------"

        local count=0
        if [[ -d "$PROJECT_DIR/upper" ]]; then
            while IFS= read -r -d '' fpath; do
                local relpath="${fpath#"$PROJECT_DIR/upper/"}"
                local size
                size=$(stat -c%s "$fpath" 2>/dev/null || echo "?")
                local hash="unavailable"
                command -v sha256sum &>/dev/null && hash=$(sha256sum "$fpath" 2>/dev/null | cut -d' ' -f1)
                echo "  [MODIFIED] $relpath"
                echo "    Size  : ${size} bytes"
                echo "    SHA256: $hash"
                echo ""
                (( count++ )) || true
            done < <(find "$PROJECT_DIR/upper" -type f -print0 2>/dev/null)
        fi
        (( count == 0 )) && echo "  No files modified inside sandbox."

        echo ""
        echo "SANDBOX EVENTS (MITRE tagged):"
        echo "----------------------------------------------------------------"
        python3 - <<PYEOF 2>/dev/null || echo "  (could not parse events)"
import json
MITRE = {
    "HONEYPOT_ACCESS"    : ("T1083", "File and Directory Discovery"),
    "RWX_MEMORY_REGION"  : ("T1055", "Process Injection"),
    "HIGH_CPU_ANOMALY"   : ("T1496", "Resource Hijacking"),
    "UNEXPECTED_CHILD"   : ("T1059", "Command and Scripting Interpreter"),
    "MASS_FILE_ACCESS"   : ("T1005", "Data from Local System"),
    "WEBCAM_SNAPSHOT"    : ("T1113", "Screen Capture"),
    "AUTH_FAILURE"       : ("T1110", "Brute Force"),
}
try:
    with open("$EVENTS_FILE") as f:
        events = json.load(f)
    if not events:
        print("  No events recorded.")
    else:
        from datetime import datetime
        for ev in events:
            try:
                ts = datetime.fromtimestamp(float(ev.get("timestamp", 0))).strftime("%H:%M:%S")
            except Exception:
                ts = "??:??:??"
            t = ev.get("type", "UNKNOWN")
            mid, mname = MITRE.get(t, ("T0000", "Unknown"))
            print(f"  [{ts}] {t:30s} {mid} — {mname}")
            if ev.get("detail"):
                print(f"           Detail  : {ev['detail']}")
            if ev.get("snapshot"):
                print(f"           Snapshot: {ev['snapshot']}")
except Exception as e:
    print(f"  Error reading events: {e}")
PYEOF

        echo ""
        echo "VERDICT:"
        echo "----------------------------------------------------------------"
        python3 - <<PYEOF 2>/dev/null || echo "  UNKNOWN"
import json
try:
    with open("$EVENTS_FILE") as f:
        events = json.load(f)
    types = {ev.get("type","") for ev in events}
    high = {"HONEYPOT_ACCESS","RWX_MEMORY_REGION","AUTH_FAILURE"}
    if types & high:
        print("  *** MALICIOUS ***")
    elif events:
        print("  *** SUSPICIOUS ***")
    else:
        print("  CLEAN")
except Exception:
    print("  UNKNOWN")
PYEOF

        echo ""
        echo "SYSCALL SUMMARY:"
        echo "----------------------------------------------------------------"
        if [[ -f "$SYSCALL_LOG" ]]; then
            echo "  Total log lines : $(wc -l < "$SYSCALL_LOG" 2>/dev/null || echo 0)"
            echo "  Network calls   : $(grep -c "connect\|sendto\|recvfrom\|socket" "$SYSCALL_LOG" 2>/dev/null || echo 0)"
            echo "  File I/O calls  : $(grep -c "openat\|read\|write\|unlink" "$SYSCALL_LOG" 2>/dev/null || echo 0)"
            echo "  Exec calls      : $(grep -c "execve" "$SYSCALL_LOG" 2>/dev/null || echo 0)"
        else
            echo "  No syscall log found."
        fi

        echo ""
        echo "================================================================"
        echo "  END OF REPORT"
        echo "================================================================"
    } | tee "$DIFF_REPORT"
    echo ""
    log "Forensic report saved: $DIFF_REPORT"
}

# =============================================================================
# CLEANUP
# =============================================================================
cleanup() {
    log "Cleaning up..."
    rm -f "$SANDBOX_PID_FILE"
    sudo umount -l "$PROJECT_DIR/merged" 2>/dev/null || true
    for pidfile in "$LOG_DIR"/{fs_watcher,honeypot_watcher,strace,anomaly_poller}.pid; do
        if [[ -f "$pidfile" ]]; then
            local p
            p=$(cat "$pidfile" 2>/dev/null || echo "")
            [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
            rm -f "$pidfile"
        fi
    done
}
trap cleanup EXIT

# =============================================================================
# MAIN
# =============================================================================

echo -e ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║         SecureVis Hardened Sandbox — Final Edition       ║${RESET}"
echo -e "${BOLD}${CYAN}║   OverlayFS · Namespaces · Capabilities · strace         ║${RESET}"
echo -e "${BOLD}${CYAN}║   Honeypots · Anomaly Polling · Forensic Report          ║${RESET}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""

check_deps

read -rp "$(echo -e "${BOLD}Absolute path of file/binary to sandbox: ${RESET}")" FILE
[[ -f "$FILE" ]] || { echo -e "${RED}❌ File not found: $FILE${RESET}"; exit 1; }
BNAME="$(basename "$FILE")"
echo -e "  File: ${CYAN}$FILE${RESET}"
echo ""

read -rp "$(echo -e "${BOLD}Sandbox this file? (y/n): ${RESET}")" REPLY
[[ "$REPLY" == "y" ]] || { echo "Aborted."; exit 0; }

check_password

SESSION_START=$(date +%s)

# ── LAYER 1 — OverlayFS setup ─────────────────────────────────────────────────
log "Setting up overlay filesystem..."
sudo umount "$PROJECT_DIR/merged" 2>/dev/null || true
rm -rf "$PROJECT_DIR"/{lower,upper,work,merged}
mkdir -p "$PROJECT_DIR"/{lower,upper,work,merged}
cp "$FILE" "$PROJECT_DIR/lower/$BNAME"

sudo mount -t overlay overlay \
    -o lowerdir="$PROJECT_DIR/lower",upperdir="$PROJECT_DIR/upper",workdir="$PROJECT_DIR/work" \
    "$PROJECT_DIR/merged"
log "${GREEN}Overlay mounted at $PROJECT_DIR/merged${RESET}"

# ── LAYER 7 — Plant honeypots ──────────────────────────────────────────────────
plant_honeypots

# ── Start monitoring ───────────────────────────────────────────────────────────
start_fs_watcher
start_honeypot_watcher

cd "$PROJECT_DIR/merged"

echo ""
echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD} Isolation layers active:${RESET}"
echo -e "  ${GREEN}✓${RESET} OverlayFS (copy-on-write filesystem)"
echo -e "  ${GREEN}✓${RESET} PID namespace  (hidden from host process tree)"
echo -e "  ${GREEN}✓${RESET} NET namespace  (no network access)"
echo -e "  ${GREEN}✓${RESET} IPC namespace  (isolated shared memory)"
echo -e "  ${GREEN}✓${RESET} UTS namespace  (isolated hostname)"
echo -e "  ${GREEN}✓${RESET} ulimit caps    (CPU / memory / fd / procs / filesize)"
echo -e "  ${GREEN}✓${RESET} strace         (syscall logging)"
echo -e "  ${GREEN}✓${RESET} Honeypots      (${#HONEYPOT_NAMES[@]} decoy files, inotify-monitored)"
echo -e "  ${GREEN}✓${RESET} Anomaly poller (CPU / rwx / child spawn)"
if command -v capsh &>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} capsh          (capability dropping)"
else
    echo -e "  ${YELLOW}⚠${RESET}  capsh not found — install libcap2-bin for capability dropping"
fi
echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e " Type ${BOLD}exit${RESET} when done."
echo ""

# ── LAYERS 2-6 — Enter namespace-isolated, capability-dropped sandbox ──────────
(
    # LAYER 4 — Kernel resource limits
    ulimit -t 120       # 120s CPU time hard limit
    ulimit -v 524288    # 512MB virtual memory
    ulimit -n 128       # 128 open file descriptors
    ulimit -f 102400    # 100MB max file write size
    ulimit -u 64        # 64 max user processes

    # LAYER 2 — Namespace isolation + LAYER 3 — Capability dropping
    if command -v capsh &>/dev/null; then
        sudo unshare --pid --net --ipc --uts --fork --mount-proc \
            capsh --drop="$DROP_CAPS" -- -c bash &
    else
        sudo unshare --pid --net --ipc --uts --fork --mount-proc \
            bash --login &
    fi
    SANDBOX_PID=$!

    # Publish PID for collector and anomaly poller
    echo "$SANDBOX_PID" > "$SANDBOX_PID_FILE"
    log "Sandbox shell PID: $SANDBOX_PID"

    # LAYER 5 — Attach strace
    if command -v strace &>/dev/null; then
        strace -f -p "$SANDBOX_PID" \
            -e trace=network,file,process \
            -o "$SYSCALL_LOG" 2>/dev/null &
        echo $! > "$LOG_DIR/strace.pid"
        log "strace attached (PID $(cat "$LOG_DIR/strace.pid"))"
    fi

    # LAYER 9 — Start behavioral anomaly poller
    start_anomaly_poller

    wait "$SANDBOX_PID"
)

# ── Session ended ──────────────────────────────────────────────────────────────
echo ""
SESSION_END=$(date +%s)
DURATION=$(( SESSION_END - SESSION_START ))
log "Sandbox session ended. Duration: ${DURATION}s"
rm -f "$SANDBOX_PID_FILE"

# Stop anomaly poller
if [[ -f "$LOG_DIR/anomaly_poller.pid" ]]; then
    kill "$(cat "$LOG_DIR/anomaly_poller.pid")" 2>/dev/null || true
    rm -f "$LOG_DIR/anomaly_poller.pid"
fi

# Unmount
log "Unmounting overlay filesystem..."
if sudo umount "$PROJECT_DIR/merged" 2>/dev/null; then
    log "${GREEN}Unmount successful.${RESET}"
else
    sudo umount -l "$PROJECT_DIR/merged" 2>/dev/null || true
    log "${YELLOW}Lazy unmount applied.${RESET}"
fi

# ── LAYER 13 — Forensic diff report ──────────────────────────────────────────
echo ""
echo -e "${BOLD}Generating forensic report...${RESET}"
generate_diff_report "$BNAME"

# ── Save or discard changes ───────────────────────────────────────────────────
echo ""
read -rp "$(echo -e "${BOLD}Keep changes to '$BNAME'? (y/N): ${RESET}")" SAVE
if [[ "$SAVE" == "y" ]]; then
    if [[ -f "$PROJECT_DIR/upper/$BNAME" ]]; then
        sudo cp "$PROJECT_DIR/upper/$BNAME" "$FILE"
        log "${GREEN}Changes saved to: $FILE${RESET}"
    else
        log "No modifications to $BNAME found in upper layer."
    fi
else
    sudo rm -rf "$PROJECT_DIR"/{upper,work}/
    mkdir -p "$PROJECT_DIR"/{upper,work}
    log "Changes discarded. Sandbox reset."
fi

echo ""
echo -e "${BOLD}${CYAN}Session complete:${RESET}"
echo -e "  Duration    : ${DURATION}s"
echo -e "  File log    : $FILE_LOG"
echo -e "  Anomaly log : $ANOMALY_LOG"
echo -e "  Events JSON : $EVENTS_FILE"
echo -e "  Diff report : $DIFF_REPORT"
[[ -f "$SYSCALL_LOG" ]] && echo -e "  Syscall log : $SYSCALL_LOG"
echo ""
echo -e "${BOLD}Run the report generator for the full forensic output:${RESET}"
echo -e "  python3 report_generator.py --binary $FILE --started $SESSION_START --output reports/"
echo ""
echo -e "${GREEN}=== SecureVis session complete ===${RESET}"
