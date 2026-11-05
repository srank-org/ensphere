#!/bin/sh
# Ensphere SessionStart hook. Hands the plugin version to the binary, which
# prints the context a session should start from: next-action.md when a
# workspace exists, and a note when the binary and the plugin disagree.
set -eu
cat >/dev/null
version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json" | head -1)
if command -v ensphere >/dev/null 2>&1; then
  exec ensphere hook session-start --plugin-version "${version:-unknown}"
fi
for dir in "${CLAUDE_PROJECT_DIR:-}" "$PWD"; do
  if [ -n "$dir" ] && [ -f "$dir/ensphere-pentest/config.md" ]; then
    printf '%s\n' "Ensphere plugin ${version:-unknown} is installed and this project has an assessment workspace, but the ensphere binary is not on PATH. Run the ensphere-setup skill before continuing the assessment."
    exit 0
  fi
done
exit 0
