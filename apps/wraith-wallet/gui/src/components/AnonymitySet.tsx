/**
 * The anonymity figure, and the working behind it.
 *
 * This panel is the product. Every other mixer reports how many participants
 * were in the round; that number is wrong exactly when it matters, because one
 * party holding forty-nine of fifty seats is an anonymity set of two. So the
 * headline here is DISTINCT ENTITIES, and the seats are shown beside it — the
 * gap between the two is what tells someone the round was padded, and either
 * number alone hides it.
 *
 * Everything shown is derived by the wallet from the round transaction and the
 * chain, never taken from the coordinator's word. `verified` says so plainly,
 * because a figure the user cannot check is a figure they are asked to trust.
 */

export type SetReport = {
  /** Seats in the round — what a naive mixer would call the set. */
  seats: number;
  /** Distinct entities. **This is the anonymity set.** */
  entities: number;
  /** Seats that collapsed into another entity. */
  discounted: number;
  /** Entities distinct only because no linkage was found. */
  unverified: number;
  /** Real payers among the entities. */
  payers: number;
};

export type SetProblem =
  | { kind: "thin"; floor: number }
  | { kind: "over_claimed"; claimed: number };

type Props = {
  report: SetReport;
  /** What the coordinator claimed, when it claimed anything. */
  claimed?: number;
  /** Whether the wallet recomputed this itself. */
  verified: boolean;
  problem?: SetProblem;
};

/** Judgement is on entities, never seats — seats are what a padded round has plenty of. */
function tone(report: SetReport, problem?: SetProblem): "pass" | "warn" | "fail" {
  if (problem?.kind === "over_claimed") return "fail";
  if (problem?.kind === "thin") return "warn";
  return report.entities >= 10 ? "pass" : "warn";
}

export function AnonymitySet({ report, claimed, verified, problem }: Props) {
  const t = tone(report, problem);

  return (
    <div className={`card anon-card anon-${t}`}>
      <div className="anon-headline">
        <span className="eyebrow">Anonymity set</span>
        <span className="anon-figure mono">{report.entities}</span>
        <span className="muted anon-of">
          across {report.seats} {report.seats === 1 ? "seat" : "seats"}
        </span>
      </div>

      <dl className="anon-breakdown">
        <div className="kv">
          <dt className="k">Distinct entities</dt>
          <dd className="mono">{report.entities}</dd>
        </div>
        {report.discounted > 0 && (
          <div className="kv">
            <dt className="k">
              Discounted
              <span className="muted"> — coins traced to another participant</span>
            </dt>
            <dd className="mono">{report.discounted}</dd>
          </div>
        )}
        {report.unverified > 0 && (
          <div className="kv">
            <dt className="k">
              Unverified
              <span className="muted"> — no link found, not proof of independence</span>
            </dt>
            <dd className="mono">{report.unverified}</dd>
          </div>
        )}
        <div className="kv">
          <dt className="k">
            Real payments
            <span className="muted"> — cover that behaves like you</span>
          </dt>
          <dd className="mono">{report.payers}</dd>
        </div>
      </dl>

      {problem?.kind === "over_claimed" && (
        <p className="anon-alert">
          <strong>The coordinator claimed {problem.claimed}.</strong> The round&rsquo;s own
          coins support at most {report.entities}. There is no honest reading of
          that difference — reporting fewer than you count is normal caution,
          reporting more is not derivable from the chain at all.
        </p>
      )}

      {problem?.kind === "thin" && (
        <p className="anon-alert">
          This round is smaller than your minimum of {problem.floor}. Nothing is
          wrong with it — there simply are not many people paying right now.
          Waiting for a fuller round costs you time and nothing else.
        </p>
      )}

      <p className={verified ? "anon-proof mono" : "anon-proof mono anon-unchecked"}>
        {verified
          ? "✓ Counted by this wallet from the chain"
          : "⚠ Not independently checked"}
        {claimed !== undefined && verified && claimed !== report.entities && (
          <span className="muted"> · coordinator said {claimed}</span>
        )}
      </p>
    </div>
  );
}
