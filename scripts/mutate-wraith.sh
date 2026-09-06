#!/usr/bin/env bash
#
# Does each refusal in wraith-protocol actually refuse?
#
# A check whose failure produces no observable output is not a check — and a
# test that passes with the logic removed is not a test. This gutts each
# safety-critical function in turn and asserts the suite notices.
#
# Deliberately not `cargo-mutants`: this targets the specific refusals the
# design depends on, and runs in seconds rather than hours.
#
# ⚠ Restores every file it touches, including on interrupt. It still refuses to
#   run against a dirty tree — a mutation harness and uncommitted work are a bad
#   combination, and that lesson was learnt the expensive way.

set -uo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain crates/)" ]; then
  echo "refusing to run: crates/ has uncommitted changes — commit first" >&2
  exit 2
fi

BAK=$(mktemp -d)
# Restore only over files that already exist — a backup whose name does not map
# back to a real source file means the harness invented one, and writing it would
# leave litter in the tree rather than restoring anything.
trap 'for f in "$BAK"/*.bak; do [ -e "$f" ] || continue; n=$(basename "$f" .bak); t="crates/wraith-protocol/src/${n//__//}"; [ -e "$t" ] && cp "$f" "$t"; done; rm -rf "$BAK"' EXIT INT TERM

survivors=0
checked=0

mutate() {
  local name="$1" rel="$2" find="$3" repl="$4" filter="$5"
  local file="crates/wraith-protocol/src/$rel"
  cp "$file" "$BAK/${rel//\//__}.bak"

  python3 - "$file" "$find" "$repl" <<'PY' || { printf '  %-38s ANCHOR MISSING (stale mutation)\n' "$name"; cp "$BAK/${rel//\//__}.bak" "$file"; return 1; }
import sys
p, f, r = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if f not in s:
    sys.exit(1)
open(p, "w").write(s.replace(f, r, 1))
PY

  # Classify on EXIT CODE, not on grepping the summary. `cargo test` prints
  # several `test result` lines (lib, doctests) and none at all when the build
  # fails, so a grep picks the wrong one or nothing — which produced a control
  # mutation reporting "caught" when a no-op must survive. A guard that
  # misreports is worse than no guard.
  # Confirm the mutation actually landed. A harness that silently fails to
  # mutate reports everything as "survived" and looks like a catastrophe, or
  # reports everything "caught" and looks like success — both are lies.
  if ! grep -qF "$repl" "$file"; then
    printf '  %-38s MUTATION DID NOT APPLY\n' "$name"
    cp "$BAK/${rel//\//__}.bak" "$file"
    return 1
  fi

  # Cargo fingerprints on mtime with one-second granularity, and a
  # mutate/test/restore cycle completes well inside that. Without this the test
  # runs against the PREVIOUS build and reports "survived" for a mutation that
  # was applied and would have been caught — which is how this harness spent
  # several runs producing different answers to the same question.
  # Drop the crate's fingerprint so cargo must rebuild.
  #
  # Cargo fingerprints on mtime with one-second granularity, and a
  # mutate/test/restore cycle races it — an early version of this harness gave
  # three different answers to the same question across consecutive runs,
  # because the test ran against the previous build. A `touch` and a `sleep`
  # narrowed the window without closing it; deleting the fingerprint closes it,
  # and costs one crate rebuild rather than the two full-suite runs it replaces.
  rm -rf target/debug/.fingerprint/wraith-protocol-* 2>/dev/null

  local rc rc2
  timeout 300 cargo test -j2 -p wraith-protocol --lib "$filter" >/dev/null 2>&1
  rc=$?
  # Second run confirms the answer is stable. Cheap now: nothing rebuilds.
  timeout 300 cargo test -j2 -p wraith-protocol --lib "$filter" >/dev/null 2>&1
  rc2=$?
  cp "$BAK/${rel//\//__}.bak" "$file"
  checked=$((checked + 1))

  if [ "$rc" -ne "$rc2" ]; then
    printf '  %-38s INDETERMINATE (%s then %s)\n' "$name" "$rc" "$rc2"
    survivors=$((survivors + 1))
  elif [ "$rc" -eq 0 ]; then
    printf '  %-38s *** SURVIVED ***\n' "$name"
    survivors=$((survivors + 1))
  else
    printf '  %-38s caught\n' "$name"
  fi
}

echo "mutating the refusals wraith-protocol depends on:"

mutate "once-per-coin never refuses" signing_ledger.rs \
'            Some(existing) => {
                self.refusals += 1;
                Err(LedgerError::Conflict {
                    existing_txid: existing,
                })
            }' \
'            Some(_existing) => Ok(Decision::Sign),' signing_ledger

mutate "pre-sign approves everything" pre_sign.rs \
'    let mut refusals = Vec::new();' \
'    let mut refusals = Vec::new();
    if true { return refusals; }' pre_sign

# --- composition + entity counting: the structural Sybil rules -------------
# Each of these is a rule the round is sold on. A rule nothing detects the
# absence of is not enforced, it is merely written down.

mutate "LP allowance is unlimited" composition.rs \
'            if held >= policy.max_inputs_per_lp {' \
'            if false {' composition

mutate "mixing slots never run out" composition.rs \
'            if taken >= policy.max_mixing_slots {' \
'            if false {' composition

mutate "a thin round can be padded" composition.rs \
'            if (payers as f64) < policy.min_payer_fraction * total as f64 {' \
'            if false {' composition

mutate "entity count is just the seat count" anonymity_set.rs \
'    let entities = roots.len();' \
'    let entities = seats.len();' anonymity_set

mutate "unverified distinctness is not declared" anonymity_set.rs \
'        if !has_evidence {' \
'        if false {' anonymity_set

mutate "an unanalysed set signs anyway" pre_sign.rs \
'        None => refusals.push(RefuseToSign::SetUnverified {' \
'        None => drop(RefuseToSign::SetUnverified {' pre_sign

mutate "consolidation sees no risk" consolidation.rs \
'    let mut risks = Vec::new();' \
'    let mut risks = Vec::new();
    if true { return risks; }' consolidation

mutate "admission accepts any age" admission.rs \
'        let age = tip_height.saturating_sub(c.confirmed_height);' \
'        let age = u32::MAX;' admission

mutate "admission ignores clusters" admission.rs \
'            if *n >= policy.max_seats_per_cluster {' \
'            if false {' admission

mutate "amount attack goes blind" privacy.rs \
'    if unique > 0 {' \
'    if false {' privacy

mutate "marker scan finds nothing" privacy.rs \
'        .filter(|(_, o)| o.script_pubkey.is_op_return())' \
'        .filter(|(_, _o)| false)' privacy

mutate "bond ceiling never refuses" liquidity.rs \
'        if would_be > self.bond_sats {' \
'        if false {' liquidity

mutate "effective set ignores dominance" privacy_level.rs \
'        let dominated = (dominance.clamp(0.0, 1.0) * self.nominal_set as f64).ceil() as u64;' \
'        let dominated = 0u64;' privacy_level

mutate "exit analysis sees no risk" exit_availability.rs \
'    if cfg.remix_interval_blocks <= cfg.exit_delay_blocks {' \
'    if false {' exit_availability

mutate "mailbox accepts any tag width" mailbox.rs \
'        if (set as u64) < self.min_anonymity_set {' \
'        if false {' mailbox

mutate "ladder accepts non-rungs" ladder_round.rs \
'        if self.ladder.rungs().contains(&value) {' \
'        if true {' ladder_round

# Control: a no-op edit must SURVIVE. If this reports "caught", the harness is
# misclassifying and every result above is suspect.
cp crates/wraith-protocol/src/mailbox.rs "$BAK/mailbox.rs.bak"
printf '\n// harness control\n' >> crates/wraith-protocol/src/mailbox.rs
rm -rf target/debug/.fingerprint/wraith-protocol-* 2>/dev/null
timeout 300 cargo test -j2 -p wraith-protocol --lib mailbox >/dev/null 2>&1
control_rc=$?
cp "$BAK/mailbox.rs.bak" crates/wraith-protocol/src/mailbox.rs
echo "  control rc=$control_rc"
if [ "$control_rc" -ne 0 ]; then
  echo
  echo "CONTROL FAILED: a no-op mutation was reported as caught — results above are not trustworthy"
  exit 3
fi

echo
if [ "$survivors" -gt 0 ]; then
  echo "$survivors of $checked mutations SURVIVED — those tests do not test what they claim"
  exit 1
fi
echo "all $checked mutations caught"
