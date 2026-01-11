#!/bin/bash
set -euo pipefail

# === SecureVis Overlay Sandbox (honeypot + optional webcam + pre-sandbox password check) ===
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$PROJECT_DIR"/{lower,upper,work,merged,logs}
LOG_FILE="$PROJECT_DIR/logs/file_changes.log"
touch "$LOG_FILE"

# --- CONFIGURATION ---
# Set to "true" only if you understand legal/privacy implications and
# have explicit permission to record the webcam on this machine.
ENABLE_WEBCAM=false

# Which tool to use for snapshots if ENABLE_WEBCAM=true:
# "fswebcam" (preferred) or "ffmpeg" (fallback). Ensure installed.
WEBCAM_TOOL="fswebcam"
WEBCAM_DEVICE="/dev/video0"
WEBCAM_SAVE_DIR="$PROJECT_DIR/logs"

# Which honeypot files to create inside sandbox
HONEYPOT_NAMES=( ".ssh_keys.txt" "passwords.txt" "secrets.db" "README_FOR_HACKERS" "deploy_keys" )

# Max allowed sudo password attempts before triggering snapshot + abort
MAX_ATTEMPTS=2

# --- End configuration ---

echo "=== SecureVis Overlay Sandbox (honeypot-aware) ==="
read -p "Absolute path of file to sandbox (example: /home/ubuntu/test.c): " FILE

# --- Validate file path ---
if [[ ! -f "$FILE" ]]; then
  echo "❌ Error: file not found: $FILE"
  exit 1
fi

BNAME="$(basename "$FILE")"
echo
echo "File selected for sandboxing: $FILE"
echo

# Confirm sandboxing
read -p "Do you want to sandbox this file in overlay mode? (y/n): " REPLY
[[ "$REPLY" == "y" ]] || { echo "Aborted."; exit 0; }

# ---------------------------
# Pre-sandbox sudo password check (MAX_ATTEMPTS). If failed -> snapshot + abort
# ---------------------------
attempt=1
while (( attempt <= MAX_ATTEMPTS )); do
    echo -n "Enter your sudo password to proceed with sandboxing (attempt $attempt/$MAX_ATTEMPTS): "
    # read password silently
    read -s SUDO_PASS
    echo
    # Force sudo to ignore any cached credentials (-k) and read password from stdin (-S).
    if echo "$SUDO_PASS" | sudo -k -S true >/dev/null 2>&1; then
        # cache credentials a bit for subsequent sudo uses (optional)
        echo "$SUDO_PASS" | sudo -S true >/dev/null 2>&1 || true
        # clear SUDO_PASS variable from memory asap
        unset SUDO_PASS
        echo "✅ Password verified."
        break
    else
        echo "❌ Incorrect password."
        ((attempt++))
    fi
done

if (( attempt > MAX_ATTEMPTS )); then
    echo "⚠️  Too many failed password attempts!"
    echo "$(date '+%F %T') FAILED_PASSWORD_ATTEMPTS for $FILE" >> "$LOG_FILE"

    # Attempt to take intruder snapshot (respects ENABLE_WEBCAM)
    TS="$(date '+%F_%H-%M-%S')"
    OUT="$WEBCAM_SAVE_DIR/intruder_${TS}.jpg"
    if [[ "$ENABLE_WEBCAM" == "true" ]]; then
      if [[ ! -e "$WEBCAM_DEVICE" ]]; then
        echo "$(date '+%F %T') WEBCAM_DEVICE_NOT_FOUND $WEBCAM_DEVICE" >> "$LOG_FILE"
      else
        if [[ "$WEBCAM_TOOL" == "fswebcam" ]] && command -v fswebcam >/dev/null 2>&1; then
          fswebcam -r 1280x720 --no-banner "$OUT" >/dev/null 2>&1 || echo "$(date '+%F %T') WEBCAM_SNAPSHOT_FAILED fswebcam" >> "$LOG_FILE"
        elif command -v ffmpeg >/dev/null 2>&1; then
          ffmpeg -f v4l2 -video_size 1280x720 -i "$WEBCAM_DEVICE" -frames:v 1 "$OUT" -y >/dev/null 2>&1 || echo "$(date '+%F %T') WEBCAM_SNAPSHOT_FAILED ffmpeg" >> "$LOG_FILE"
        else
          echo "$(date '+%F %T') WEBCAM_TOOL_NOT_AVAILABLE" >> "$LOG_FILE"
        fi

        if [[ -f "$OUT" ]]; then
          echo "$(date '+%F %T') SNAPSHOT $OUT" >> "$LOG_FILE"
        fi
      fi
    else
      echo "$(date '+%F %T') SNAPSHOT_SKIPPED_WEBCAM_DISABLED" >> "$LOG_FILE"
    fi

    echo "Aborting sandbox."
    exit 1
fi

# --- Prepare environment ---
echo "Setting up isolated layers..."
sudo umount "$PROJECT_DIR/merged" 2>/dev/null || true
rm -rf "$PROJECT_DIR"/{lower,upper,work,merged}
mkdir -p "$PROJECT_DIR"/{lower,upper,work,merged}
cp "$FILE" "$PROJECT_DIR/lower/$BNAME"

# --- Mount overlay ---
echo "Mounting overlay filesystem..."
sudo mount -t overlay overlay \
  -o lowerdir="$PROJECT_DIR/lower",upperdir="$PROJECT_DIR/upper",workdir="$PROJECT_DIR/work" \
  "$PROJECT_DIR/merged"

echo "✅ Overlay mounted at: $PROJECT_DIR/merged"
echo

# --- Create honeypot files inside the merged (sandbox) layer ---
echo "Creating honeypot files inside sandbox..."
for name in "${HONEYPOT_NAMES[@]}"; do
  hp="$PROJECT_DIR/merged/$name"
  if [[ ! -e "$hp" ]]; then
    printf "This is a decoy file. Do not edit.\n" > "$hp"
    # set permissions to look attractive to a snooper
    chmod 600 "$hp" || true
  fi
done
echo "Honeypot files created: ${HONEYPOT_NAMES[*]}"
echo

# --- Helper: take webcam snapshot (if enabled) ---
take_snapshot() {
  TS="$(date '+%F_%H-%M-%S')"
  OUT="$WEBCAM_SAVE_DIR/intruder_${TS}.jpg"
  if [[ "$ENABLE_WEBCAM" != "true" ]]; then
    echo "$(date '+%F %T') SNAPSHOT_SKIPPED_WEBCAM_DISABLED" >> "$LOG_FILE"
    return 0
  fi
  if [[ ! -e "$WEBCAM_DEVICE" ]]; then
    echo "$(date '+%F %T') WEBCAM_DEVICE_NOT_FOUND $WEBCAM_DEVICE" >> "$LOG_FILE"
    return 0
  fi
  if [[ "$WEBCAM_TOOL" == "fswebcam" ]]; then
    if command -v fswebcam >/dev/null 2>&1; then
      fswebcam -r 1280x720 --no-banner "$OUT" >/dev/null 2>&1 || echo "$(date '+%F %T') WEBCAM_SNAPSHOT_FAILED fswebcam" >> "$LOG_FILE"
    else
      echo "$(date '+%F %T') FSWEBCAM_NOT_INSTALLED" >> "$LOG_FILE"
    fi
  else
    if command -v ffmpeg >/dev/null 2>&1; then
      ffmpeg -f v4l2 -video_size 1280x720 -i "$WEBCAM_DEVICE" -frames:v 1 "$OUT" -y >/dev/null 2>&1 || echo "$(date '+%F %T') WEBCAM_SNAPSHOT_FAILED ffmpeg" >> "$LOG_FILE"
    else
      echo "$(date '+%F %T') FFMPEG_NOT_INSTALLED" >> "$LOG_FILE"
    fi
  fi

  if [[ -f "$OUT" ]]; then
    echo "$(date '+%F %T') SNAPSHOT $OUT" >> "$LOG_FILE"
  fi
}

# --- Start general filesystem change watcher (for merged/ overall) ---
( inotifywait -m -r -e create,modify,delete \
  --format '%T %w%f %e' --timefmt '%F %T' "$PROJECT_DIR/merged" >> "$LOG_FILE" 2>/dev/null ) &

GEN_WATCH_PID=$!

# --- Start honeypot-specific watcher ---
start_honeypot_watcher() {
  if ! command -v inotifywait >/dev/null 2>&1; then
    echo "❗ inotifywait is not installed. Install 'inotify-tools' to enable honeypot monitoring."
    return 1
  fi

  WATCH_PATHS=()
  for name in "${HONEYPOT_NAMES[@]}"; do
    WATCH_PATHS+=("$PROJECT_DIR/merged/$name")
  done

  (
    inotifywait -m -e open,access,modify,create,delete --format '%T %w%f %e' --timefmt '%F %T' "${WATCH_PATHS[@]}" 2>/dev/null \
    | while read -r TIMESTAMP PATH EVENT; do
        echo "$TIMESTAMP HONEYPOT_EVENT $EVENT $PATH" >> "$LOG_FILE"

        echo "---- context at $TIMESTAMP ----" >> "$LOG_FILE"
        if command -v lsof >/dev/null 2>&1; then
          lsof "$PATH" >> "$LOG_FILE" 2>/dev/null || echo "lsof: no holders or insufficient perms" >> "$LOG_FILE"
        else
          ps aux --sort=-%cpu | head -n 10 >> "$LOG_FILE"
        fi
        echo "--------------------------------" >> "$LOG_FILE"

        take_snapshot
    done
  ) &

  echo $! > "$PROJECT_DIR/logs/honeypot_watcher.pid"
  echo "Honeypot watcher started (PID $(cat "$PROJECT_DIR/logs/honeypot_watcher.pid")). Logging to $LOG_FILE"
  return 0
}

start_honeypot_watcher || true
HP_WATCH_PID="$(cat "$PROJECT_DIR/logs/honeypot_watcher.pid" 2>/dev/null || echo "")"

# --- Clean-up trap ---
trap 'echo "Cleaning up..."; sudo umount -l "'"$PROJECT_DIR/merged"'" 2>/dev/null || true; kill '"$GEN_WATCH_PID"' 2>/dev/null || true; if [[ -n "'"$HP_WATCH_PID"'" ]]; then kill "'"$HP_WATCH_PID"'" 2>/dev/null || true; fi' EXIT

# --- Enter sandbox ---
cd "$PROJECT_DIR/merged"
echo "You are now inside the sandbox directory."
echo "Edit $BNAME as needed (e.g. nano $BNAME)."
echo "When done, type 'exit' to return."
echo
bash

# --- On exit ---
echo
echo "Sandbox session ended."
echo "Unmounting overlay filesystem..."
if sudo umount "$PROJECT_DIR/merged"; then
  echo "✅ Unmount successful."
else
  echo "⚠️  Lazy unmounting..."
  sudo umount -l "$PROJECT_DIR/merged" || true
fi

# --- Ask whether to keep or discard changes ---
echo
read -p "Do you want to KEEP the changes made to '$BNAME'? (y/N): " SAVE
if [[ "$SAVE" == "y" ]]; then
  if [[ -f "$PROJECT_DIR/upper/$BNAME" ]]; then
    sudo cp "$PROJECT_DIR/upper/$BNAME" "$FILE"
    echo "✅ Changes saved to original file: $FILE"
  else
    echo "⚠️  No modified version found in upper/. Nothing saved."
  fi
else
  sudo rm -rf "$PROJECT_DIR"/{upper,work}/
  mkdir -p "$PROJECT_DIR"/{upper,work}
  echo "🧹 Changes discarded and sandbox reset."
fi

echo "Logs available at: $LOG_FILE"
echo "=== SecureVis Sandbox Session Complete ==="
