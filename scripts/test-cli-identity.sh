#!/usr/bin/env bash
#
# Self-test for which program is called `ghost-cli` (#1028).
#
# Two different programs carried the name. On the fleet, and in every runbook, `ghost-cli` is
# the Ghost Core RPC client (`ghost-cli -conf=… getblockcount`). In the release tarball it was
# the Rust administration tool, which answers that command with "unexpected argument '-c'".
# So a fresh install got an admin tool at the RPC client's path and no RPC client at all, and
# an auto-updating node would have had its working RPC client replaced by the admin tool.
#
# The names are now separate: the RPC client is `ghost-cli`, the admin tool is `ghost-admin`.
# Releases up to v1.11.45 still carry the admin tool as `ghost-cli`, and the installer follows
# `releases/latest`, so the installer and the updater must also tell the two apart by asking
# the binary — a name in an old tarball proves nothing.
#
# Asserted here:
#   1. `is_core_rpc_client` — the same function in the installer and the updater — accepts the
#      RPC client and refuses the admin tool, a missing file, and a binary that hangs;
#   2. neither script puts a `ghost-cli` in place without asking it first;
#   3. the release build takes `ghost-cli` from ghost-core and `ghost-admin` from cargo.
#
# Hermetic: the "binaries" are stubs in a temp directory. Nothing here touches a node.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2
G=/usr/bin/grep
INSTALLER=scripts/install-node.sh
UPDATER=scripts/ghost-auto-update.sh
RELEASE=.github/workflows/release.yml
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

# --- stub binaries ---------------------------------------------------------------------------
# What each really prints: the first is the fleet's /opt/ghost/bin/ghost-cli, the second is the
# `ghost-cli` extracted from the v1.11.45 tarball.
cat > "$TMP/rpc-client" <<'B'
#!/usr/bin/env bash
[ "$1" = "-version" ] && { echo "Ghost Core RPC client version v1.0.0"; echo "Copyright (C) 2009-2025 The Ghost Core developers"; exit 0; }
exit 1
B
cat > "$TMP/admin-tool" <<'B'
#!/usr/bin/env bash
echo "error: unexpected argument '-v' found" >&2
echo "Usage: ghost-cli [OPTIONS] <COMMAND>" >&2
exit 2
B
# Says the right words on stderr only, and fails: must not be accepted.
cat > "$TMP/liar" <<'B'
#!/usr/bin/env bash
echo "not an RPC client" >&2; exit 1
B
printf '#!/usr/bin/env bash\nsleep 600\n' > "$TMP/hangs"
printf '#!/usr/bin/env bash\necho "Ghost Core RPC client version v1.0.0"\n' > "$TMP/not-executable"
chmod +x "$TMP/rpc-client" "$TMP/admin-tool" "$TMP/liar" "$TMP/hangs"

# Pull the function out of a script, so the script itself is never run.
fn_of() { awk '/^is_core_rpc_client\(\) \{/{on=1} on{print} on&&/^\}/{exit}' "$1"; }

echo "1. is_core_rpc_client"
for src in "$UPDATER" "$INSTALLER"; do
    body="$(fn_of "$src")"
    is "$src defines the function" yes "$([ -n "$body" ] && echo yes)"
    [ -n "$body" ] || continue
    ask() { ( eval "$body"; CLI_IDENTITY_TIMEOUT=2; is_core_rpc_client "$1" ) >/dev/null 2>&1; echo $?; }
    is "$src: accepts the Core RPC client"          0 "$(ask "$TMP/rpc-client")"
    is "$src: refuses the admin tool"               1 "$(ask "$TMP/admin-tool")"
    is "$src: refuses a binary that only fails"     1 "$(ask "$TMP/liar")"
    is "$src: refuses a binary that hangs"          1 "$(ask "$TMP/hangs")"
    is "$src: refuses a file that is not executable" 1 "$(ask "$TMP/not-executable")"
    is "$src: refuses a path that does not exist"   1 "$(ask "$TMP/absent")"
done
is "the installer and the updater carry the same function" \
   "$(fn_of "$UPDATER" | sha256sum | cut -c1-16)" "$(fn_of "$INSTALLER" | sha256sum | cut -c1-16)"

echo "2. nothing installs a ghost-cli without asking it"
# The installer's own install line (its inlined copy of the updater is checked as the updater).
inst_line="$($G -nE '^[[:space:]]*install .*"\$cli_bin" /opt/ghost/bin/ghost-cli' "$INSTALLER" | head -1 | cut -d: -f1)"
is "the installer has a ghost-cli install line to check" yes "$([ -n "$inst_line" ] && echo yes)"
if [ -n "$inst_line" ]; then
    is "and it sits under an is_core_rpc_client test" 1 \
       "$(sed -n "$((inst_line - 3)),$((inst_line - 1))p" "$INSTALLER" | $G -cE 'if .*is_core_rpc_client "\$cli_bin"' || true)"
fi
swap_line="$($G -nE 'SWAP_DEST\+=\("\$BIN_DIR/ghost-cli"\)' "$UPDATER" | head -1 | cut -d: -f1)"
is "the updater has a ghost-cli swap line to check" yes "$([ -n "$swap_line" ] && echo yes)"
if [ -n "$swap_line" ]; then
    is "and it sits under an is_core_rpc_client test" 1 \
       "$(sed -n "$((swap_line - 3)),$((swap_line - 1))p" "$UPDATER" | $G -cE 'is_core_rpc_client "\$new_cli"' || true)"
fi

echo "3. the release build"
is "the admin tool's binary is named ghost-admin" 1 \
   "$(awk '/^\[\[bin\]\]/{on=1} on&&/^name *= *"ghost-admin"/{print; exit}' bins/ghost-cli/Cargo.toml | $G -c . || true)"
is "no cargo binary in the workspace is named ghost-cli" 0 \
   "$(git ls-files '*Cargo.toml' | $G -v '^ghost-core/' | xargs awk '/^\[\[bin\]\]/{on=1;next} /^\[/{on=0} on&&/^name *= *"ghost-cli"/' | $G -c . || true)"
is "the package loop stages ghost-admin, not a cargo-built ghost-cli" "ghost-admin" \
   "$($G -E '^[[:space:]]*for bin in ghost-mining ' "$RELEASE" | tr ' ' '\n' | $G -xE 'ghost-(cli|admin);?' | tr -d ';' | tr '\n' ' ' | sed 's/ $//')"
is "ghost-core's ghost-cli target is built" 1 \
   "$($G -cE 'cmake --build ghost-core/build --target ghostd ghost-cli( |$)' "$RELEASE" || true)"
is "and staged into the archive" 1 "$($G -cE 'cp "ghost-core/build/bin/ghost-cli" dist/' "$RELEASE" || true)"
is "BUILD_CLI is not switched off" 0 "$($G -cE 'DBUILD_CLI=OFF' "$RELEASE" || true)"
is "the archive is read back and its ghost-cli asked what it is" 1 \
   "$($G -cE 'ghost-cli" -version .*RPC client' "$RELEASE" || true)"
is "and a wrong answer fails the build" 1 \
   "$($G -cE 'case "\$cli_says" in \*"RPC client"\*\) ;; \*\) echo "::error::.*exit 1' "$RELEASE" || true)"

echo
echo "test-cli-identity: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
