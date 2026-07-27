#!/usr/bin/env bash
# Post-deploy attribution check for a node carrying real miners.
#
# The failure mode this guards against is SILENT: shares keep flowing, they just land on the
# node's configured operator identity instead of the miner's own. Nothing on the wire shows it
# — only the shares ledger does. That is how ~395 shares (6,913 on vm8) were misattributed
# twice before anyone noticed.
#
# Exit: 0 = verified clean, 1 = misattribution detected, 2 = INCONCLUSIVE (no shares to judge).
# The 2 matters: it used to return 0 on a node with no miners, which is every canary, so the
# post-deploy check reported PASS having examined nothing (#461, #464).
#
# Usage: verify_attribution.sh <node> [window_secs]
set -uo pipefail
NODE="${1:?usage: verify_attribution.sh <node> [window_secs]}"
WINDOW="${2:-300}"

read -r OP < <(ssh -o ConnectTimeout=10 "$NODE" 'grep -hE "^user_identity" /etc/ghost/translator-config.toml | cut -d\" -f2' 2>/dev/null)
echo "  node=$NODE  operator_identity=$OP  window=${WINDOW}s"

SQL_PREFIX='sudo -u ghost sqlite3'
ssh -o ConnectTimeout=10 "$NODE" "$SQL_PREFIX -separator '|' /home/ghost/.ghost/ghost.db \"
  select miner_id, count(*), round(sum(work),1), datetime(max(timestamp),'unixepoch')
  from shares where timestamp > strftime('%s','now') - $WINDOW
  group by miner_id order by 2 desc;\"" 2>/dev/null | awk -F'|' '{printf "    %-62s %5s shares  work=%-14s %s\n",$1,$2,$3,$4}'

BAD=$(ssh -o ConnectTimeout=10 "$NODE" "$SQL_PREFIX /home/ghost/.ghost/ghost.db \"
  select count(*) from shares where miner_id like '${OP}%'
  and timestamp > strftime('%s','now') - $WINDOW;\"" 2>/dev/null)
BAD="${BAD:-0}"

# Total locally-submitted shares in the window. Without this the check passes VACUOUSLY on any
# node with no miners — "0 credited to the operator identity" is trivially true when nothing was
# credited to anyone. Every canary (vm5-8) is in exactly that state, which is why a 60-minute
# soak there proves nothing about attribution (#461, #464). Say so rather than reporting PASS.
TOTAL=$(ssh -o ConnectTimeout=10 "$NODE" "$SQL_PREFIX /home/ghost/.ghost/ghost.db \
  \"select count(*) from shares where timestamp > strftime('%s','now') - $WINDOW
     and length(received_by) > 8;\"" 2>/dev/null)
TOTAL="${TOTAL:-0}"

echo
if [ "$TOTAL" = "0" ]; then
    echo "  INCONCLUSIVE: no locally-submitted shares on $NODE in the last ${WINDOW}s."
    echo "  There is nothing to attribute, so this proves nothing either way."
    echo "  Attribution can only be checked on a node carrying real miners (vm3/vm4 today)."
    exit 2
fi

if [ "$BAD" = "0" ]; then
    echo "  PASS: 0 of $TOTAL locally-submitted shares credited to the operator identity"
    echo "        in the last ${WINDOW}s"
    exit 0
fi
echo "  *** FAIL: $BAD of $TOTAL share(s) credited to $OP in the last ${WINDOW}s ***"
echo "  *** This is the misattribution failure. ROLL BACK NOW: ***"
echo "  ***   ssh $NODE 'ls -t /opt/ghost/bin/*.bak.* | head -3' ***"
exit 1
