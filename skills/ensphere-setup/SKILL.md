---
name: ensphere-setup
description: Install or update the ensphere CLI so it matches this plugin's version, and check that an assessment can run on this machine. Use before the first assessment, after a plugin update, or when a session starts with a note that the binary and the plugin disagree.
---

# Ensphere setup

The plugin carries the method; the `ensphere` binary carries the boundary,
the ledger, and the gate. An assessment needs both at the same version.

1. Read the plugin version from `${CLAUDE_PLUGIN_ROOT}/.claude-plugin/plugin.json`.
2. Run `ensphere --version`. If the binary is missing, or its version is not
   `v<plugin version>`, install it:
   - If `gh` is available and a release `v<plugin version>` exists at
     https://github.com/srank-org/ensphere/releases, download the archive
     for this platform with `gh release download v<version> --repo
     srank-org/ensphere --pattern '*<os>_<arch>*'` together with
     `checksums.txt`, check the archive against the checksum file, run
     `gh attestation verify <archive> --owner srank-org`, and install the
     binary to `/usr/local/bin` or another directory on `PATH`.
   - Otherwise build from source: clone
     https://github.com/srank-org/ensphere at tag `v<version>` into a
     temporary directory and run `make install` there. This needs Go 1.26
     or newer. Say which path was taken.
   A binary that reports a bare commit hash was built from an untagged
   checkout; say so and let the operator decide whether to keep it.
3. Run `ensphere --version` again and confirm it matches the plugin.
4. For each provider CLI the operator's platforms need (`aws`, `gcloud`,
   `az`, `wrangler`, `supabase`), report whether it is installed and logged
   in using a read-only identity command. Never log in on their behalf.
5. Run `ensphere run doctor --plugin-version <plugin version>` from the
   project directory and include its checks in the report. It compares the
   binary with the plugin, reads the workspace when one exists, checks the
   source tree, the map, the invariants, the target, the sandbox commands,
   the provider CLIs, and the evidence chains, and writes nothing.
6. Report in one short list what is ready and what is not, with the exact
   command for anything missing.

Run this skill from a directory without an `ensphere-pentest/` workspace,
or set `ENSPHERE_GUARD=off` for the shell commands it needs: inside a
workspace the assessment guard refuses download tools by design.
