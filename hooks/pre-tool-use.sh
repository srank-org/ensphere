#!/bin/sh
# Ensphere PreToolUse guard for Bash. The decision lives in the ensphere
# binary (ensphere hook pre-tool-use), which reads the hook JSON on stdin and
# has no opinion unless an ensphere-pentest workspace exists in the project.
# This wrapper only finds the binary. With a workspace and no binary it
# refuses, because an assessment without the CLI has no scope enforcement.
set -eu
if [ "${ENSPHERE_GUARD:-on}" = "off" ]; then
  cat >/dev/null
  exit 0
fi
if command -v ensphere >/dev/null 2>&1; then
  exec ensphere hook pre-tool-use
fi
for dir in "${CLAUDE_PROJECT_DIR:-}" "$PWD"; do
  if [ -n "$dir" ] && [ -f "$dir/ensphere-pentest/config.md" ]; then
    cat >/dev/null
    echo "Ensphere: this project has an assessment workspace but the ensphere binary is not on PATH, so scope cannot be enforced. Run the ensphere-setup skill (or make install from the Ensphere repository), or set ENSPHERE_GUARD=off to run without the guard." >&2
    exit 2
  fi
done
cat >/dev/null
exit 0
