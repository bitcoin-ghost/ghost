"use client";

import { useMemo, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { MinersView, minerHref, type PerAddress } from "@/components/pool/MinersView";
import { usePoolMinerList, usePoolMiners, usePoolStatus } from "@/hooks/queries/usePoolQueries";
import type { PoolMiner } from "@/lib/api/pool";
import { addressesFromBlocks } from "@/lib/pool/view";
import { useNow } from "@/hooks/useNow";

// Addresses looked up on this page, kept in this browser only (a convenience: the active ones are
// listed from `/api/v1/pool/miners` anyway; this keeps inactive ones a click away).
const SAVED_KEY = "ghost-pool-looked-up";
const CHANGE_EVENT = "ghost-pool-looked-up-change";

/** The raw stored JSON: a string, so the snapshot is stable between reads. */
function readRaw(): string {
  try {
    return window.localStorage.getItem(SAVED_KEY) ?? "[]";
  } catch {
    return "[]";
  }
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("storage", onChange);
  window.addEventListener(CHANGE_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(CHANGE_EVENT, onChange);
  };
}

function parseSaved(raw: string): string[] {
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((a): a is string => typeof a === "string").slice(0, 50) : [];
  } catch {
    return [];
  }
}

function writeSaved(list: string[]) {
  try {
    window.localStorage.setItem(SAVED_KEY, JSON.stringify(list.slice(0, 50)));
  } catch {
    /* private window or storage blocked: the list is just not remembered */
  }
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

export default function MinersPage() {
  const router = useRouter();
  const { data, error, isLoading } = usePoolStatus();
  const list = usePoolMinerList();
  const raw = useSyncExternalStore(subscribe, readRaw, () => "[]");
  const saved = useMemo(() => parseSaved(raw), [raw]);
  const [input, setInput] = useState("");
  const now = useNow();
  const addresses = useMemo(() => {
    const out = addressesFromBlocks(data?.blocks_found);
    for (const a of saved) if (!out.includes(a)) out.push(a);
    return out;
  }, [data, saved]);
  // Per-address answers only for the addresses the active list does not already cover.
  const others = useMemo(() => {
    const listed = new Set((list.data?.miners ?? []).map((m) => m.address));
    return addresses.filter((a) => !listed.has(a));
  }, [addresses, list.data]);
  const results = usePoolMiners(others);
  const miners: Record<string, PerAddress<PoolMiner>> = {};
  others.forEach((a, i) => {
    miners[a] = { data: results[i]?.data, error: results[i]?.error ?? undefined };
  });

  function lookUp(e: React.FormEvent) {
    e.preventDefault();
    const a = input.trim().split(".")[0];
    if (!a) return;
    writeSaved([a, ...saved.filter((s) => s !== a)]);
    router.push(minerHref(a));
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost pool"
        title="Miners."
        subtitle="Workers, hashrate, shares, best share, blocks found and the expected time to a block, by payout address"
      />
      <Card>
        <CardHeader title="Look up a miner" subtitle="The Bitcoin address a miner uses as its username" />
        <form onSubmit={lookUp} className="flex flex-wrap gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="bc1q…, bc1p… or 3…"
            spellCheck={false}
            autoComplete="off"
            aria-label="Payout address"
            className="flex-1 min-w-0 px-3 py-2 rounded font-mono text-sm"
            style={{ background: "var(--surface)", border: "1px solid var(--rule-strong)", color: "var(--fg)" }}
          />
          <Button type="submit" size="sm">
            Look up
          </Button>
        </form>
      </Card>
      <SectionErrorBoundary section="Miners">
        <MinersView
          status={data}
          statusError={error ?? undefined}
          statusLoading={isLoading}
          list={list.data}
          listError={list.error ?? undefined}
          listLoading={list.isLoading}
          addresses={others}
          miners={miners}
          now={now}
        />
      </SectionErrorBoundary>
    </div>
  );
}
