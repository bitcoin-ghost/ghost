import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import type { PoolFoundBlock, PoolStatus } from "@/lib/api/pool";
import { fmtAgo, fmtBtc, fmtInt, shortHash, submitSummary } from "@/lib/pool/view";
import { LevelBadge, Loading, Note, Table, Td, Unavailable } from "./parts";
import { minerHref } from "./MinersView";

export interface BlocksViewProps {
  status?: PoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  now: number;
}

function explorer(network: string, hash: string): string | null {
  if (!/^[0-9a-f]{64}$/.test(hash)) return null;
  if (network === "mainnet") return `https://mempool.space/block/${hash}`;
  if (network === "signet") return `https://mempool.space/signet/block/${hash}`;
  return null;
}

function CheckBadge({ b }: { b: PoolFoundBlock }) {
  if (b.check === null) return <LevelBadge level="unknown">not checked yet</LevelBadge>;
  if (b.check === "ok") return <LevelBadge level="ok">ok</LevelBadge>;
  return <LevelBadge level="error">{b.check}</LevelBadge>;
}

/** Every block this node's miners found, newest first. */
export function BlocksView({ status, statusError, statusLoading, now }: BlocksViewProps) {
  const blocks = status ? [...status.blocks_found].reverse() : [];
  return (
    <Card>
      <CardHeader
        title="Blocks found"
        subtitle={status ? `${fmtInt(blocks.length)} found by miners on this node` : undefined}
      />
      {statusLoading && !status ? <Loading what="the blocks found" /> : null}
      {!status && statusError ? <Unavailable what="Blocks found" error={statusError} /> : null}
      {status && blocks.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--dim)" }} data-testid="no-blocks">
          No block found yet. Solo mining is a lottery: this list can stay empty for a long time.
        </p>
      ) : null}
      {blocks.length > 0 ? (
        <Table head={["Height", "Block", "Found by", "Paid to the miner", "Fees", "Treasury", "Coinbase check", "Other nodes", "Found"]}>
          {blocks.map((b) => {
            const url = explorer(status?.network ?? "", b.hash);
            return (
              <tr key={b.hash} data-testid="block-row">
                <Td>{fmtInt(b.height)}</Td>
                <Td mono>
                  {url ? (
                    <a href={url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--accent)" }}>
                      {shortHash(b.hash)}
                    </a>
                  ) : (
                    shortHash(b.hash)
                  )}
                </Td>
                <Td mono>
                  <Link href={minerHref(b.address)} style={{ color: "var(--accent)" }}>
                    {shortHash(b.address, 6)}
                  </Link>
                  {b.worker ? `.${b.worker}` : ""}
                </Td>
                <Td>{fmtBtc(b.reward_sats)}</Td>
                <Td>{fmtBtc(b.fees_sats)}</Td>
                <Td>{fmtBtc(b.treasury_sats)}</Td>
                <Td>
                  <CheckBadge b={b} />
                </Td>
                <Td>{submitSummary(b)}</Td>
                <Td>{fmtAgo(b.found_at, now)}</Td>
              </tr>
            );
          })}
        </Table>
      ) : null}
      <Note>
        A block is listed when this node submits it, before the network decides: an orphaned block is
        still listed. Check it on an explorer. Its coinbase can be spent after 100 more blocks. A failed
        coinbase check is the alarm <code>SOLO_COINBASE_MISMATCH</code> in pool_sv2&apos;s log.
      </Note>
    </Card>
  );
}
