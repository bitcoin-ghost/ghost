"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Search, Info, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { StatCard } from "@/components/ui/StatCard";
import { CopyButton } from "@/components/ui/CopyButton";
import { EmptyState } from "@/components/ui/EmptyState";
import {
  getAddressInfo,
  scanDescriptor,
  type AddressInfo,
  type DescriptorScan,
  type AddressUtxo,
} from "@/lib/api/address";

type Mode = "address" | "descriptor";

function formatSats(satoshis: number | null | undefined): string {
  if (satoshis == null) return "—";
  if (Math.abs(satoshis) >= 100_000_000) {
    return `${(satoshis / 100_000_000).toFixed(8).replace(/0+$/, "").replace(/\.$/, "")} BTC`;
  }
  return `${satoshis.toLocaleString()} sats`;
}

function shortTxid(txid: string): string {
  return txid.length > 20 ? `${txid.slice(0, 10)}…${txid.slice(-8)}` : txid;
}

/** Friendly panel for the `{ available: false, reason }` shape. */
function Unavailable({ reason }: { reason: string }) {
  const indexOff = reason.toLowerCase().includes("not enabled");
  return (
    <Card className="p-6">
      <div className="flex items-start gap-3">
        <AlertTriangle size={18} strokeWidth={1.75} style={{ color: "var(--accent)", marginTop: 2 }} />
        <div>
          <div className="t-body" style={{ color: "var(--fg)", fontWeight: 500 }}>
            {indexOff ? "Address index is off" : "Lookup unavailable"}
          </div>
          <p className="t-small mt-1" style={{ color: "var(--dim)", maxWidth: "60ch" }}>
            {reason}
          </p>
          {indexOff && (
            <p className="t-small mt-2" style={{ color: "var(--fainter)", fontFamily: "var(--font-mono)" }}>
              Add <span style={{ color: "var(--accent)" }}>-addressindex</span> to ghostd and restart. On an
              already-pruned node only blocks still on disk are back-indexed.
            </p>
          )}
        </div>
      </div>
    </Card>
  );
}

function UtxoTable({ utxos }: { utxos: AddressUtxo[] }) {
  if (utxos.length === 0) {
    return (
      <p className="t-small" style={{ color: "var(--fainter)", padding: "12px 0" }}>
        No unspent outputs.
      </p>
    );
  }
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="w-full" style={{ borderCollapse: "collapse", fontFamily: "var(--font-mono)", fontSize: "12px" }}>
        <thead>
          <tr style={{ color: "var(--fainter)", textAlign: "left" }}>
            <th style={{ padding: "6px 12px 6px 0", fontWeight: 500 }}>Output</th>
            {utxos.some((u) => u.address) && (
              <th style={{ padding: "6px 12px", fontWeight: 500 }}>Address</th>
            )}
            <th style={{ padding: "6px 12px", fontWeight: 500, textAlign: "right" }}>Height</th>
            <th style={{ padding: "6px 0 6px 12px", fontWeight: 500, textAlign: "right" }}>Amount</th>
          </tr>
        </thead>
        <tbody>
          {utxos.map((u) => (
            <tr key={`${u.txid}:${u.outputIndex}`} style={{ borderTop: "1px solid var(--rule)" }}>
              <td style={{ padding: "8px 12px 8px 0", color: "var(--dim)" }}>
                <span className="inline-flex items-center gap-1.5">
                  {shortTxid(u.txid)}:{u.outputIndex}
                  <CopyButton text={`${u.txid}:${u.outputIndex}`} />
                </span>
              </td>
              {utxos.some((x) => x.address) && (
                <td style={{ padding: "8px 12px", color: "var(--dim)" }}>
                  {u.address ? shortTxid(u.address) : "—"}
                </td>
              )}
              <td style={{ padding: "8px 12px", color: "var(--fainter)", textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                {u.height.toLocaleString()}
              </td>
              <td style={{ padding: "8px 0 8px 12px", color: "var(--fg)", textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
                {formatSats(u.satoshis)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TxidList({ txids }: { txids: string[] }) {
  if (txids.length === 0) return null;
  return (
    <Card className="p-5">
      <div className="t-eyebrow mb-3" style={{ color: "var(--accent)" }}>
        transaction history · {txids.length}
      </div>
      <div className="flex flex-col gap-1.5">
        {txids.map((txid) => (
          <div
            key={txid}
            className="inline-flex items-center gap-1.5"
            style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--dim)" }}
          >
            {shortTxid(txid)}
            <CopyButton text={txid} />
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function AddressLookupPage() {
  const [mode, setMode] = useState<Mode>("address");
  const [address, setAddress] = useState("");
  const [descriptor, setDescriptor] = useState("");
  const [range, setRange] = useState("");

  const addressQuery = useMutation<AddressInfo, Error, string>({
    mutationFn: (addr) => getAddressInfo(addr),
  });
  const scanQuery = useMutation<DescriptorScan, Error, { desc: string; range?: number }>({
    mutationFn: ({ desc, range }) => scanDescriptor(desc, range),
  });

  const submitAddress = () => {
    if (address.trim()) addressQuery.mutate(address.trim());
  };
  const submitScan = () => {
    if (!descriptor.trim()) return;
    const parsed = range.trim() ? Number(range.trim()) : undefined;
    scanQuery.mutate({ desc: descriptor.trim(), range: Number.isFinite(parsed) ? parsed : undefined });
  };

  const addrResult = addressQuery.data;
  const scanResult = scanQuery.data;

  return (
    <div className="p-6 md:p-8 max-w-5xl">
      <PageHeader
        eyebrow="node storage"
        title="Address lookup"
        subtitle="Query this node's address index for balance, history and UTXOs. Built from structural block data, so it works on pruned and hazed nodes — no witness or signature data required."
      />

      {/* Mode switch */}
      <div className="flex gap-1 mb-6" role="tablist">
        {(["address", "descriptor"] as Mode[]).map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className="t-small"
            style={{
              padding: "6px 14px",
              borderRadius: "4px",
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              fontSize: "11px",
              border: "1px solid",
              borderColor: mode === m ? "var(--accent)" : "var(--rule)",
              color: mode === m ? "var(--accent)" : "var(--dim)",
              background: mode === m ? "color-mix(in srgb, var(--accent) 10%, transparent)" : "transparent",
              cursor: "pointer",
            }}
          >
            {m === "address" ? "Single address" : "Descriptor / xpub"}
          </button>
        ))}
      </div>

      {/* Address mode */}
      {mode === "address" && (
        <>
          <Card className="p-5 mb-6">
            <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
              <div className="flex-1">
                <Input
                  label="Address"
                  placeholder="bc1q… / 1… / 3…"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && submitAddress()}
                />
              </div>
              <Button
                variant="primary"
                onClick={submitAddress}
                loading={addressQuery.isPending}
                disabled={!address.trim()}
              >
                <Search size={15} strokeWidth={2} className="mr-1.5" />
                Look up
              </Button>
            </div>
          </Card>

          {addressQuery.isError && <Unavailable reason={addressQuery.error.message} />}
          {addrResult && addrResult.available === false && <Unavailable reason={addrResult.reason} />}
          {addrResult && addrResult.available && (
            <div className="flex flex-col gap-6">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <StatCard label="Balance" value={formatSats(addrResult.balance)} />
                <StatCard label="Total received" value={formatSats(addrResult.received)} />
                <StatCard label="UTXOs" value={addrResult.utxos.length} />
                <StatCard label="Transactions" value={addrResult.txids.length} />
              </div>
              <Card className="p-5">
                <div className="t-eyebrow mb-3" style={{ color: "var(--accent)" }}>
                  unspent outputs
                </div>
                <UtxoTable utxos={addrResult.utxos} />
              </Card>
              <TxidList txids={addrResult.txids} />
            </div>
          )}
          {!addrResult && !addressQuery.isPending && !addressQuery.isError && (
            <EmptyState
              icon={<Info size={20} strokeWidth={1.5} />}
              title="Enter an address"
              description="Balance, UTXOs and full transaction history from the local address index."
            />
          )}
        </>
      )}

      {/* Descriptor mode */}
      {mode === "descriptor" && (
        <>
          <Card className="p-5 mb-6">
            <div className="flex flex-col gap-3">
              <Input
                label="Descriptor"
                placeholder="wpkh(xpub6C…/0/*)"
                value={descriptor}
                onChange={(e) => setDescriptor(e.target.value)}
                helperText="A ranged descriptor sweeps a whole xpub. Wrap the key in its script type (wpkh / pkh / tr)."
              />
              <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
                <div style={{ maxWidth: "180px" }}>
                  <Input
                    label="Gap limit"
                    placeholder="1000"
                    value={range}
                    onChange={(e) => setRange(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && submitScan()}
                  />
                </div>
                <Button
                  variant="primary"
                  onClick={submitScan}
                  loading={scanQuery.isPending}
                  disabled={!descriptor.trim()}
                >
                  <Search size={15} strokeWidth={2} className="mr-1.5" />
                  Scan
                </Button>
              </div>
            </div>
          </Card>

          {scanQuery.isError && <Unavailable reason={scanQuery.error.message} />}
          {scanResult && scanResult.available === false && <Unavailable reason={scanResult.reason} />}
          {scanResult && scanResult.available && (
            <div className="flex flex-col gap-6">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <StatCard label="Balance" value={formatSats(scanResult.balance)} />
                <StatCard label="Total received" value={formatSats(scanResult.received)} />
                <StatCard
                  label="Addresses used"
                  value={`${scanResult.used} / ${scanResult.scanned}`}
                  sublabel="active / derived"
                />
                <StatCard label="Transactions" value={scanResult.txids.length} />
              </div>
              <Card className="p-5">
                <div className="t-eyebrow mb-3" style={{ color: "var(--accent)" }}>
                  unspent outputs
                </div>
                <UtxoTable utxos={scanResult.utxos} />
              </Card>
              <TxidList txids={scanResult.txids} />
            </div>
          )}
          {!scanResult && !scanQuery.isPending && !scanQuery.isError && (
            <EmptyState
              icon={<Info size={20} strokeWidth={1.5} />}
              title="Scan a descriptor"
              description="Aggregate balance, UTXOs and history across an xpub — the trusted-mode equivalent of an xpub rescan."
            />
          )}
        </>
      )}
    </div>
  );
}
