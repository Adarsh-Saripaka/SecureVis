#!/bin/bash
set -euo pipefail

# =============================================================================
# SecureVis Overlay Sandbox — Hardened Edition (v2)
#
# WHAT CHANGED FROM v1, AND WHY:
#
#   1. FILESYSTEM CONFINEMENT WAS FAKE. v1 mounted an OverlayFS at
#      $PROJECT_DIR/merged and just `cd`'d into it — the sandboxed process
#      could still read/write anywhere on the host via absolute paths.
#      v2 uses `unshare --mount --root=<merged>` so the sandboxed process
#      genuinely has <merged> as its root filesystem (pivot_root under the
#      hood). Requires util-linux >= 2.36.
#
#   2. THE SANDBOX RAN AS ROOT (UID 0). v1's capability dropping reduced
#      risk but the process was still UID 0. v2 uses `setpriv` to drop to
#      an unprivileged UID/GID (65534, i.e. nobody/nogroup) AND strip the
#      entire capability bounding set, in one step, after entering the
#      new namespaces/root.
#
#   3. PASSWORD HANDLING LEAKED VIA THE PROCESS TABLE. v1 piped a captured
#      password into `sudo -S` via `echo`, which is briefly visible in
#      `ps aux` on the host. v2 never captures the password into a shell
#      variable at all — it calls `sudo -v`, which prompts and reads
#      directly from the controlling terminal.
#
#   4. TWO DISCONNECTED MONITORING SYSTEMS. v1's events only became
#      visible in the end-of-session forensic report. v2 emits every
#      event through securevis_common.py, the same event bus the live
#      GUI reads from, so events show up in the dashboard in real time.
#
#   5. SILENT FAILURES ON CRITICAL STEPS. v1 suppressed stderr and
#      ignored failures (`2>/dev/null || true`) even on steps like the
#      overlay mount or namespace entry — a tool whose job is isolation
#      should never continue silently if the isolation itself failed.
#      v2 hard-fails (via `set -euo pipefail` + explicit checks) on any
#      step that is load-bearing for confinement, and only soft-fails
#      (with a visible warning) on genuinely optional conveniences like
#      `lsof` or webcam capture.
#
# REMAINING KNOWN LIMITATION: this still isn't seccomp-filtered and
# doesn't use a full user namespace with UID mapping (so the "nobody"
# user inside the sandbox is still the real host UID 65534, not a
# remapped one). That's the next hardening step, not yet done here.
# =============================================================================

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
COMMON_PY="$PROJECT_DIR/securevis_common.py"
mkdir -p "$LOG_DIR" "$PROJECT_DIR"/{lower,upper,work,merged}

SANDBOX_PID_FILE="/tmp/securevis_sandbox.pid"
FILE_LOG="$LOG_DIR/file_changes.log"
SYSCALL_LOG="$LOG_DIR/syscall_trace.log"
ANOMALY_LOG="$LOG_DIR/anomaly.log"
DIFF_REPORT="$LOG_DIR/session_diff.txt"

touch "$FILE_LOG" "$ANOMALY_LOG"

# ── Configuration ─────────────────────────────────────────────────────────
ENABLE_WEBCAM=false
WEBCAM_TOOL="fswebcam"
WEBCAM_DEVICE="/dev/video0"
ANOMALY_POLL_INTERVAL=2
CPU_ANOMALY_THRESHOLD=80
SANDBOX_UID=65534   # nobody
SANDBOX_GID=65534   # nogroup

HONEYPOT_NAMES=(
    "passwords.txt" ".ssh_keys.txt" "id_rsa" ".aws_credentials"
    "secrets.db" "deploy_keys" "README_FOR_HACKERS" ".env"
    "database.conf" "api_tokens.json"
)

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# =============================================================================
# UTILITIES
# =============================================================================

log() { echo -e "[$(date '+%F %T')] $*" | tee -a "$FILE_LOG"; }
log_anomaly() { echo -e "[$(date '+%F %T')] $*" | tee -a "$ANOMALY_LOG"; }
log_warn() { echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$FILE_LOG" >&2; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$FILE_LOG" >&2; }

# All events now go through the shared event bus (securevis_common.py)
# instead of a hand-rolled, unlocked JSON read-modify-write. This is
# also what makes events show up live in the GUI, not just in the
# end-of-session report.
emit_event() {
    local type="$1" detail="${2:-}" snapshot="${3:-}"
    python3 "$COMMON_PY" emit "$type" "$detail" sandbox "$snapshot" \
        || log_warn "failed to emit event $type (event bus unreachable)"
}

# =============================================================================
# WEBCAM SNAPSHOT (optional layer — soft-fail is fine here)
# =============================================================================
take_snapshot() {
    local reason="${1:-UNKNOWN}"
    local ts out
    ts=$(date '+%F_%H-%M-%S')
    out="$LOG_DIR/snapshot_${ts}.jpg"

    if [[ "$ENABLE_WEBCAM" != "true" ]]; then
        emit_event "SNAPSHOT_SKIPPED" "$reason"
        return 0
    fi
    if [[ ! -e "$WEBCAM_DEVICE" ]]; then
        log_warn "webcam device not found: $WEBCAM_DEVICE"
        emit_event "WEBCAM_NOT_FOUND" "$WEBCAM_DEVICE"
        return 0
    fi

    if [[ "$WEBCAM_TOOL" == "fswebcam" ]] && command -v fswebcam &>/dev/null; then
        fswebcam -r 1280x720 --no-banner "$out" &>/dev/null \
            && { log "SNAPSHOT saved: $out"; emit_event "WEBCAM_SNAPSHOT" "$reason" "$out"; } \
            || log_warn "snapshot failed (fswebcam error)"
    elif command -v ffmpeg &>/dev/null; then
        ffmpeg -f v4l2 -video_size 1280x720 -i "$WEBCAM_DEVICE" -frames:v 1 "$out" -y &>/dev/null \
            && { log "SNAPSHOT saved: $out"; emit_event "WEBCAM_SNAPSHOT" "$reason" "$out"; } \
            || log_warn "snapshot failed (ffmpeg error)"
    else
        log_warn "no webcam tool available — install fswebcam or ffmpeg"
    fi
}

# =============================================================================
# PRE-SESSION AUTH GATE
#
# FIXED: no longer captures the password into a shell variable and pipes
# it through `echo`. `sudo -v` prompts and reads the password directly
# from the controlling terminal — it never passes through our process's
# argv or environment, so it can't leak via `ps`.
# =============================================================================
check_password() {
    sudo -k   # drop any cached credential so this is a real re-auth
    if sudo -v; then
        log "Sudo credential verified."
        return 0
    fi
    log_error "sudo authentication failed — aborting."
    emit_event "AUTH_FAILURE" "sudo -v failed"
    take_snapshot "AUTH_FAILURE"
    exit 1
}

# =============================================================================
# DEPENDENCY CHECK
#
# FIXED: this now hard-fails on tools that are load-bearing for real
# confinement (unshare with --root support, setpriv) instead of only
# warning. capsh is dropped as a dependency entirely — setpriv can do
# both the UID drop and the capability drop in one call.
# =============================================================================
check_deps() {
    local missing=() optional_missing=()

    for cmd in inotifywait python3 strace unshare setpriv; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    for cmd in lsof sha256sum; do
        command -v "$cmd" &>/dev/null || optional_missing+=("$cmd")
    done

    if (( ${#missing[@]} > 0 )); then
        log_error "Missing required tools: ${missing[*]}"
        echo "   Install: sudo apt install inotify-tools strace python3 util-linux"
        exit 1
    fi

    if ! unshare --help 2>&1 | grep -q -- '--root'; then
        log_error "Your 'unshare' does not support --root (needs util-linux >= 2.36)."
        echo "   Real filesystem confinement is not possible without it — aborting"
        echo "   rather than silently falling back to the old, unconfined mode."
        exit 1
    fi

    if (( ${#optional_missing[@]} > 0 )); then
        log_warn "Optional tools not found: ${optional_missing[*]} (lsof context / SHA-256 hashing will be skipped)"
    fi
}

# =============================================================================
# FILESYSTEM AUDIT WATCHER
# =============================================================================
start_fs_watcher() {
    (
        inotifywait -m -r -e create,modify,delete,move,attrib \
            --format '%T %e %w%f' --timefmt '%F %T' \
            "$PROJECT_DIR/merged" 2>>"$LOG_DIR/watcher_errors.log" \
        | while read -r line; do
            echo "$line" >> "$FILE_LOG"
        done
    ) &
    echo $! > "$LOG_DIR/fs_watcher.pid"
    log "FS watcher started (PID $!)"
}

# =============================================================================
# HONEYPOT TRIPWIRES
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
        chmod 666 "$hp" 2>/dev/null || true  # readable by the unprivileged sandbox user
    done
    log "Honeypot files planted (${#HONEYPOT_NAMES[@]} files)"
}

start_honeypot_watcher() {
    local watch_paths=()
    for name in "${HONEYPOT_NAMES[@]}"; do
        local hp="$PROJECT_DIR/merged/$name"
        [[ -f "$hp" ]] && watch_paths+=("$hp")
    done
    (( ${#watch_paths[@]} == 0 )) && { log_warn "no honeypot files found to watch"; return; }

    (
        inotifywait -m -e open,access,read,modify,create,delete \
            --format '%T %w%f %e' --timefmt '%F %T' \
            "${watch_paths[@]}" 2>>"$LOG_DIR/watcher_errors.log" \
        | while read -r TS FPATH EVENT; do
            log "${RED}HONEYPOT_EVENT${RESET} $EVENT -> $FPATH"

            if command -v lsof &>/dev/null; then
                { echo "=== lsof context $TS ==="; lsof "$FPATH" 2>/dev/null || echo "(no holders)"; } >> "$FILE_LOG"
            fi
            { echo "=== ps context $TS ==="; ps auxf --no-header 2>/dev/null | head -20; } >> "$FILE_LOG"

            emit_event "HONEYPOT_ACCESS" "$EVENT:$FPATH"
            take_snapshot "HONEYPOT_ACCESS:$(basename "$FPATH")"
        done
    ) &
    echo $! > "$LOG_DIR/honeypot_watcher.pid"
    log "Honeypot watcher started (PID $!), watching ${#watch_paths[@]} files"
}

# =============================================================================
# BEHAVIORAL ANOMALY POLLER
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

                if [[ -f "/proc/$pid/stat" ]]; then
                    local utime stime t1 t2 cpu
                    read -r _ _ _ _ _ _ _ _ _ _ _ _ utime stime _ < "/proc/$pid/stat" 2>/dev/null || continue
                    t1=$(( utime + stime ))
                    sleep 0.5
                    read -r _ _ _ _ _ _ _ _ _ _ _ _ utime stime _ < "/proc/$pid/stat" 2>/dev/null || continue
                    t2=$(( utime + stime ))
                    cpu=$(( (t2 - t1) * 100 / 5 ))
                    if (( cpu > CPU_ANOMALY_THRESHOLD )); then
                        local pname; pname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
                        log_anomaly "HIGH_CPU_ANOMALY pid=$pid name=$pname cpu~=${cpu}%"
                        emit_event "HIGH_CPU_ANOMALY" "pid=$pid,name=$pname,cpu=${cpu}%"
                    fi
                fi

                if [[ -f "/proc/$pid/maps" ]] && grep -qP '^[0-9a-f]+-[0-9a-f]+ rwxp' "/proc/$pid/maps" 2>/dev/null; then
                    local pname; pname=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
                    log_anomaly "RWX_MEMORY_REGION pid=$pid name=$pname"
                    emit_event "RWX_MEMORY_REGION" "pid=$pid,name=$pname"
                    take_snapshot "RWX_MEMORY_REGION:pid=$pid"
                fi

                local nchildren
                nchildren=$(pgrep -P "$pid" 2>/dev/null | wc -l || echo 0)
                if (( nchildren > 3 )); then
                    log_anomaly "UNEXPECTED_CHILD_SPAWN pid=$pid spawned $nchildren children"
                    emit_event "UNEXPECTED_CHILD" "pid=$pid,children=$nchildren"
                fi
            done
        done
    ) &
    echo $! > "$LOG_DIR/anomaly_poller.pid"
    log "Behavioral anomaly poller started (PID $!)"
}

# =============================================================================
# FORENSIC DIFF REPORT
# Verdict logic now comes from securevis_common.verdict_for() — the same
# function the live GUI uses — so the two can no longer disagree.
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
                local size hash="unavailable"
                size=$(stat -c%s "$fpath" 2>/dev/null || echo "?")
                command -v sha256sum &>/dev/null && hash=$(sha256sum "$fpath" 2>/dev/null | cut -d' ' -f1)
                echo "  [MODIFIED] $relpath"
                echo "    Size  : ${size} bytes"
                echo "    SHA256: $hash"
                echo ""
                count=$((count + 1))
            done < <(find "$PROJECT_DIR/upper" -type f -print0 2>/dev/null)
        fi
        (( count == 0 )) && echo "  No files modified inside sandbox."

        echo ""
        echo "SANDBOX EVENTS (MITRE tagged, from the shared event bus):"
        echo "----------------------------------------------------------------"
        python3 "$COMMON_PY" read 100 2>/dev/null | python3 -c "
import json, sys
from datetime import datetime
sys.path.insert(0, '$PROJECT_DIR')
from securevis_common import MITRE_MAP, verdict_for
events = [json.loads(l) for l in sys.stdin if l.strip()]
if not events:
    print('  No events recorded.')
for ev in events:
    ts = datetime.fromtimestamp(ev.get('timestamp', 0)).strftime('%H:%M:%S')
    t = ev.get('type', 'UNKNOWN')
    mid, mname = MITRE_MAP.get(t, ('T0000', 'Unknown'))
    print(f\"  [{ts}] {t:24s} {mid} - {mname}  (source: {ev.get('source','?')})\")
    if ev.get('detail'):
        print(f\"           Detail  : {ev['detail']}\")
print()
print('VERDICT:')
print('----------------------------------------------------------------')
print(f'  {verdict_for(events)}')
" || echo "  (could not parse events)"

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
            local p; p=$(cat "$pidfile" 2>/dev/null || echo "")
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
echo -e "${BOLD}${CYAN}+============================================================+${RESET}"
echo -e "${BOLD}${CYAN}|         SecureVis Hardened Sandbox — v2                  |${RESET}"
echo -e "${BOLD}${CYAN}|   pivot_root confinement * unprivileged exec * unified   |${RESET}"
echo -e "${BOLD}${CYAN}|   event bus * honeypots * anomaly polling * forensics    |${RESET}"
echo -e "${BOLD}${CYAN}+============================================================+${RESET}"
echo ""

check_deps

read -rp "$(echo -e "${BOLD}Absolute path of file/binary to sandbox: ${RESET}")" FILE
[[ -f "$FILE" ]] || { log_error "File not found: $FILE"; exit 1; }
BNAME="$(basename "$FILE")"
echo -e "  File: ${CYAN}$FILE${RESET}"
echo ""

read -rp "$(echo -e "${BOLD}Sandbox this file? (y/n): ${RESET}")" REPLY
[[ "$REPLY" == "y" ]] || { echo "Aborted."; exit 0; }

check_password
emit_event "SANDBOX_START" "file=$BNAME"
SESSION_START=$(date +%s)

# ── LAYER 1 — OverlayFS setup ────────────────────────────────────────────
# This step is load-bearing for isolation, so unlike v1 it is NOT allowed
# to fail silently: if the mount fails, we abort instead of continuing
# into a "sandbox" that isn't actually isolated.
log "Setting up overlay filesystem..."
sudo umount "$PROJECT_DIR/merged" 2>/dev/null || true
rm -rf "$PROJECT_DIR"/{lower,upper,work,merged}
mkdir -p "$PROJECT_DIR"/{lower,upper,work,merged}
cp "$FILE" "$PROJECT_DIR/lower/$BNAME"

if ! sudo mount -t overlay overlay \
    -o lowerdir="$PROJECT_DIR/lower",upperdir="$PROJECT_DIR/upper",workdir="$PROJECT_DIR/work" \
    "$PROJECT_DIR/merged"; then
    log_error "OverlayFS mount failed — aborting rather than running unconfined."
    emit_event "SETUP_FAILURE" "overlay mount failed"
    exit 1
fi
log "Overlay mounted at $PROJECT_DIR/merged"

plant_honeypots
start_fs_watcher
start_honeypot_watcher

echo ""
echo -e "${BOLD}${YELLOW}------------------------------------------------------------${RESET}"
echo -e "${BOLD} Isolation layers active:${RESET}"
echo -e "  ${GREEN}v${RESET} OverlayFS (copy-on-write filesystem)"
echo -e "  ${GREEN}v${RESET} Real root confinement (mount namespace + pivot_root via --root)"
echo -e "  ${GREEN}v${RESET} PID / NET / IPC / UTS namespaces"
echo -e "  ${GREEN}v${RESET} Unprivileged execution (UID/GID $SANDBOX_UID, all capabilities dropped)"
echo -e "  ${GREEN}v${RESET} ulimit caps (CPU / memory / fd / procs / filesize)"
echo -e "  ${GREEN}v${RESET} strace (syscall logging, from the host side)"
echo -e "  ${GREEN}v${RESET} Honeypots (${#HONEYPOT_NAMES[@]} decoy files, inotify-monitored)"
echo -e "  ${GREEN}v${RESET} Anomaly poller (CPU / rwx / child spawn)"
echo -e "${BOLD}${YELLOW}------------------------------------------------------------${RESET}"
echo -e " Type ${BOLD}exit${RESET} when done."
echo ""

# ── LAYERS 2-3 — Real confinement + unprivileged execution ──────────────
# `unshare --root=<merged>` performs the namespace unshare AND the
# pivot_root/root-change in one step (util-linux >= 2.36). Inside that
# new root, `setpriv` drops us from root to UID/GID 65534 and strips the
# entire capability bounding set + inheritable set before bash ever runs.
(
    ulimit -t 120       # 120s CPU time hard limit
    ulimit -v 524288    # 512MB virtual memory
    ulimit -n 128       # 128 open file descriptors
    ulimit -f 102400    # 100MB max file write size
    ulimit -u 64         # 64 max user processes

    sudo unshare --mount --pid --net --ipc --uts --fork --mount-proc \
        --root="$PROJECT_DIR/merged" -- \
        setpriv --reuid="$SANDBOX_UID" --regid="$SANDBOX_GID" --clear-groups \
                --bounding-set=-all --inh-caps=-all --no-new-privs \
                -- /bin/bash --login &
    SANDBOX_PID=$!
    echo "$SANDBOX_PID" > "$SANDBOX_PID_FILE"
    log "Sandbox PID: $SANDBOX_PID (confined root, UID $SANDBOX_UID, no capabilities)"

    if command -v strace &>/dev/null; then
        sudo strace -f -p "$SANDBOX_PID" -e trace=network,file,process \
            -o "$SYSCALL_LOG" 2>/dev/null &
        echo $! > "$LOG_DIR/strace.pid"
        log "strace attached (PID $(cat "$LOG_DIR/strace.pid"))"
    else
        log_warn "strace not available — syscall log will be empty"
    fi

    start_anomaly_poller
    wait "$SANDBOX_PID"
)

# ── Session ended ──────────────────────────────────────────────────────
echo ""
SESSION_END=$(date +%s)
DURATION=$(( SESSION_END - SESSION_START ))
log "Sandbox session ended. Duration: ${DURATION}s"
emit_event "SANDBOX_END" "file=$BNAME,duration=${DURATION}s"
rm -f "$SANDBOX_PID_FILE"

if [[ -f "$LOG_DIR/anomaly_poller.pid" ]]; then
    kill "$(cat "$LOG_DIR/anomaly_poller.pid")" 2>/dev/null || true
    rm -f "$LOG_DIR/anomaly_poller.pid"
fi

log "Unmounting overlay filesystem..."
if sudo umount "$PROJECT_DIR/merged" 2>/dev/null; then
    log "Unmount successful."
else
    sudo umount -l "$PROJECT_DIR/merged" 2>/dev/null || true
    log_warn "Lazy unmount applied — a normal unmount failed."
fi

echo ""
echo -e "${BOLD}Generating forensic report...${RESET}"
generate_diff_report "$BNAME"

echo ""
read -rp "$(echo -e "${BOLD}Keep changes to '$BNAME'? (y/N): ${RESET}")" SAVE
if [[ "$SAVE" == "y" ]]; then
    if [[ -f "$PROJECT_DIR/upper/$BNAME" ]]; then
        sudo cp "$PROJECT_DIR/upper/$BNAME" "$FILE"
        log "Changes saved to: $FILE"
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
echo -e "  Diff report : $DIFF_REPORT"
[[ -f "$SYSCALL_LOG" ]] && echo -e "  Syscall log : $SYSCALL_LOG"
echo ""
echo -e "${GREEN}=== SecureVis session complete ===${RESET}"