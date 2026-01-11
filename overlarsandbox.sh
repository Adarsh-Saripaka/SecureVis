#!/bin/bash
set -euo pipefail

# === SecureVis Overlay Sandbox ===
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$PROJECT_DIR"/{lower,upper,work,merged,logs}
LOG_FILE="$PROJECT_DIR/logs/file_changes.log"
touch "$LOG_FILE"

echo "=== SecureVis Overlay Sandbox ==="
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

# --- Ask user if they want to sandbox ---
read -p "Do you want to sandbox this file in overlay mode? (y/n): " REPLY
[[ "$REPLY" == "y" ]] || { echo "Aborted."; exit 0; }

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

# --- Start file watcher (logs file edits) ---
( inotifywait -m -r -e create,modify,delete \
  --format '%T %w%f %e' --timefmt '%F %T' "$PROJECT_DIR/merged" >> "$LOG_FILE" 2>/dev/null ) &

WATCH_PID=$!
trap "sudo umount -l '$PROJECT_DIR/merged' 2>/dev/null; kill $WATCH_PID 2>/dev/null || true" EXIT

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
