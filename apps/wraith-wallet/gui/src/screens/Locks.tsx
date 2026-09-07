/**
 * The Locks screen.
 *
 * This was 650 lines of Ghost Pay P2WSH lock management — prepare, confirm,
 * jump, unilateral recovery. That primitive is gone: nobody ever created one
 * (`ghost_locks` held zero rows on every fleet node, checked against a control
 * query that could see 22,562 shares in the same database), so there was nothing
 * to migrate and nothing to strand.
 *
 * What remains is the replacement: the four-lane Ghost Lock.
 */

import { useEffect, useState } from "react";
import { GhostLockPanel } from "../components/GhostLockPanel";
import { EscapePanel } from "../components/EscapePanel";
import { ghostLockList, type GhostLockRecord } from "../lib/tauri";
import { HelpTip } from "../components/HelpTip";
import { HELP_TOPICS } from "../lib/help";

export function Locks() {
  // Loaded here rather than inside the panel: the escape flow is the one a
  // person reaches for when something has gone wrong, and it should not open
  // with an empty dropdown and a button to press.
  const [locks, setLocks] = useState<GhostLockRecord[]>([]);
  useEffect(() => {
    ghostLockList()
      .then(setLocks)
      .catch(() => setLocks([]));
  }, []);

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">custody</span>
          <h1>
            Ghost Lock{" "}
            <HelpTip title={HELP_TOPICS.locks.title} label="About Ghost Locks">
              {HELP_TOPICS.locks.body}
            </HelpTip>
          </h1>
          <p className="lead">
            One account, four compartments. Savings is cold and needs your
            backup device; Spending co-signs with the Wraith quorum; Cash is
            yours alone and deliberately not private; Investments earns by
            supplying liquidity, and is the one lane the quorum can move without
            you.
          </p>
        </div>
      </div>

      <GhostLockPanel />

      <EscapePanel locks={locks} />
    </div>
  );
}
