#!/bin/bash
# Install Ensphere security assessment skills for Claude Code and Codex.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ACTION="install"
TARGET="all"

usage() {
  echo "Usage: $0 [--uninstall] [--target claude|codex|all]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --uninstall)
      ACTION="uninstall"
      ;;
    --target)
      shift
      if [ -z "$1" ]; then
        usage >&2
        exit 1
      fi
      TARGET="$1"
      ;;
    --target=*)
      TARGET="${1#--target=}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

target_dirs() {
  case "$TARGET" in
    claude)
      printf '%s\n' "$HOME/.claude/skills/ensphere"
      ;;
    codex)
      printf '%s\n' "$HOME/.codex/skills/ensphere"
      ;;
    all)
      printf '%s\n' "$HOME/.claude/skills/ensphere"
      printf '%s\n' "$HOME/.codex/skills/ensphere"
      ;;
    *)
      echo "Error: unsupported target $TARGET. Use claude, codex, or all." >&2
      exit 1
      ;;
  esac
}

install_to() {
  local skill_dir="$1"

  rm -rf "$skill_dir"
  mkdir -p "$skill_dir"
  cp -R "$SCRIPT_DIR/skills/ensphere/." "$skill_dir/"

  local file_count
  file_count=$(find "$skill_dir" -name "*.md" | wc -l | tr -d ' ')
  echo "Ensphere skills installed to $skill_dir ($file_count files)"
}

uninstall_from() {
  local skill_dir="$1"

  if [ -d "$skill_dir" ]; then
    rm -rf "$skill_dir"
    echo "Ensphere skills removed from $skill_dir"
  else
    echo "Nothing to remove: $skill_dir does not exist"
  fi
}

# Verify source files exist
if [ ! -f "$SCRIPT_DIR/skills/ensphere/SKILL.md" ]; then
  echo "Error: skills/ensphere/SKILL.md not found. Run this script from the ensphere repo root." >&2
  exit 1
fi

if [ "$ACTION" = "uninstall" ]; then
  target_dirs | while read -r skill_dir; do
    uninstall_from "$skill_dir"
  done
  exit 0
fi

echo "Installing Ensphere skills..."
target_dirs | while read -r skill_dir; do
  install_to "$skill_dir"
done

echo ""
echo "Config template: templates/config.md (copy to your project's ensphere-pentest/config.md)"
echo "Claude usage: Open Claude Code in your project directory and say '/ensphere' or 'Run session 01'"
echo "Codex usage: Open Codex in your project directory and say 'ensphere'"
echo "Uninstall: $0 --uninstall [--target claude|codex|all]"

# Optional: build CLI if Go is available
if command -v go >/dev/null 2>&1; then
  echo ""
  echo "Go detected: building ensphere CLI..."
  if (cd "$SCRIPT_DIR" && make build); then
    echo "CLI built at $SCRIPT_DIR/bin/ensphere"
    echo "Run 'make install' from the repo to install to /usr/local/bin"
  else
    echo "CLI build failed (non-fatal). Install Go 1.26.4+ and run 'make build' manually."
  fi
else
  echo ""
  echo "Go not found: skipping CLI build. Install Go 1.26.4+ and run 'make build' to build the payload database CLI."
fi
