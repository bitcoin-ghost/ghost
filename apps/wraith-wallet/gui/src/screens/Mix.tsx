import { useEffect, useMemo, useState } from "react";
import {
  lightL1Utxos,
  lightReceive,
  walletGhostId,
  wraithCoordinatorDiscover,
  wraithResolveCoordinator,
  wraithMixRun,
  type LightL1UtxoEntry,
  type WraithDiscoverTier,
  type WraithMixCompleted,
} from "../lib/tauri";

interface MixProps {
  activeWallet: string | null;
}

interface Tier {
  id: string;
  label: string;
  denom_sats: number;
  bond_sats: number;
  min_participants?: number;
}

/// Fallback tiers when the coordinator is offline or unreachable.
/// Matches the canonical Wraith Lite v1 set (DESIGN_LITE.md §11).
/// When discover succeeds, the screen replaces this with the live
/// list — the coordinator may add tiers in future without a wallet
/// rebuild.
const FALLBACK_TIERS: Tier[] = [
  { id: "100k_sats", label: "Tiny", denom_sats: 100_000, bond_sats: 500 },
  { id: "1m_sats", label: "Small", denom_sats: 1_000_000, bond_sats: 5_000 },
  { id: "10m_sats", label: "Medium", denom_sats: 10_000_000, bond_sats: 50_000 },
  { id: "100m_sats", label: "Large", denom_sats: 100_000_000, bond_sats: 500_000 },
];

function tierLabelFor(denom_sats: number): string {
  if (denom_sats >= 100_000_000) return "Large";
  if (denom_sats >= 10_000_000) return "Medium";
  if (denom_sats >= 1_000_000) return "Small";
  return "Tiny";
}

function tiersFromDiscover(rows: WraithDiscoverTier[]): Tier[] {
  return rows.map((t) => ({
    id: t.id,
    label: tierLabelFor(t.denomination_sats),
    denom_sats: t.denomination_sats,
    bond_sats: t.bond_sats,
    min_participants: t.min_participants,
  }));
}

const DEFAULT_COORDINATOR = "http://127.0.0.1:9100";

export function Mix({ activeWallet }: MixProps) {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [coordinator, setCoordinator] = useState(DEFAULT_COORDINATOR);
  const [coordinatorPeersText, setCoordinatorPeersText] = useState("");

  // Network-elected coordinator: when on, the wallet resolves the coordinator
  // for the selected tier from the node's decentralised election (via ghost-pay)
  // instead of using the manual URL. Off by default so the manual flow is
  // unchanged until the operator opts in.
  const [useNetworkCoordinator, setUseNetworkCoordinator] = useState(false);
  const [resolvedEndpoint, setResolvedEndpoint] = useState<string | null>(null);
  const [resolvedEpoch, setResolvedEpoch] = useState<number | null>(null);
  const [resolving, setResolving] = useState(false);
  const [resolveErr, setResolveErr] = useState<string | null>(null);
  const [tiers, setTiers] = useState<Tier[]>(FALLBACK_TIERS);
  const [tierId, setTierId] = useState(FALLBACK_TIERS[0].id);
  const [discoverInfo, setDiscoverInfo] = useState<{
    answered_by: string;
    network: string;
    pool_id: string;
  } | null>(null);
  const [discoverErr, setDiscoverErr] = useState<string | null>(null);

  const [utxoTxid, setUtxoTxid] = useState("");
  const [utxoVout, setUtxoVout] = useState("");
  const [utxoValue, setUtxoValue] = useState("");
  const [utxoScript, setUtxoScript] = useState("");
  const [bip86Index, setBip86Index] = useState("");
  const [mixOutAddr, setMixOutAddr] = useState("");
  const [changeAddr, setChangeAddr] = useState("");

  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<WraithMixCompleted | null>(null);

  const [utxos, setUtxos] = useState<LightL1UtxoEntry[]>([]);
  const [chainHeight, setChainHeight] = useState<number | null>(null);
  const [scanMax, setScanMax] = useState(32);

  const tier = useMemo(
    () => tiers.find((t) => t.id === tierId) ?? tiers[0],
    [tiers, tierId],
  );

  // The coordinator URL actually used for discovery + the mix: the network-
  // elected endpoint when the toggle is on and one resolved, else the manual URL.
  const effectiveCoordinator = useMemo(
    () =>
      useNetworkCoordinator && resolvedEndpoint
        ? resolvedEndpoint
        : coordinator.trim(),
    [useNetworkCoordinator, resolvedEndpoint, coordinator],
  );

  // Resolve the elected coordinator for the selected tier whenever the toggle is
  // enabled or the tier changes. Sharding on (tier, epoch) means every wallet
  // mixing this tier this epoch converges on one seat (larger anonymity set). A
  // null endpoint (election off/pending) leaves the manual URL in effect.
  useEffect(() => {
    if (!useNetworkCoordinator) {
      setResolvedEndpoint(null);
      setResolvedEpoch(null);
      setResolveErr(null);
      return;
    }
    let alive = true;
    setResolving(true);
    (async () => {
      try {
        const r = await wraithResolveCoordinator(tierId);
        if (!alive) return;
        setResolvedEndpoint(r.endpoint);
        setResolvedEpoch(r.epoch);
        setResolveErr(
          r.endpoint
            ? null
            : "No elected coordinator available yet — using the manual URL.",
        );
      } catch (e) {
        if (!alive) return;
        setResolvedEndpoint(null);
        setResolvedEpoch(null);
        setResolveErr((e as Error).message ?? String(e));
      } finally {
        if (alive) setResolving(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [useNetworkCoordinator, tierId]);

  // Discover the coordinator's tier set + identity. Re-runs when
  // the user changes the coordinator URL or peer list (debounced
  // by the controlled-input pattern: every keystroke triggers a
  // fetch, but reqwest's 5s connect-timeout bounds the
  // misconfiguration cost). On success, replace the tier dropdown
  // with the live list. On failure, keep the fallback tiers and
  // surface the error so the user knows discovery didn't succeed.
  useEffect(() => {
    let alive = true;
    const peers = coordinatorPeersText
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    (async () => {
      try {
        const r = await wraithCoordinatorDiscover(effectiveCoordinator, peers);
        if (!alive) return;
        const next = tiersFromDiscover(r.tiers);
        if (next.length > 0) {
          setTiers(next);
          // Keep current selection if still present, otherwise pick
          // the smallest tier (matching the previous default).
          if (!next.some((t) => t.id === tierId)) {
            setTierId(next[0].id);
          }
        }
        setDiscoverInfo({
          answered_by: r.answered_by,
          network: r.network,
          pool_id: r.pool_id,
        });
        setDiscoverErr(null);
      } catch (e) {
        if (!alive) return;
        setDiscoverInfo(null);
        setDiscoverErr((e as Error).message ?? String(e));
        setTiers(FALLBACK_TIERS);
      }
    })();
    return () => {
      alive = false;
    };
  }, [effectiveCoordinator, coordinatorPeersText]);

  // On mount: pull ghost_id + auto-derive a fresh mix-output and
  // change address from the wallet's BIP86 keys. Indices 90 / 91
  // are arbitrary "high" gaps unlikely to collide with the user's
  // recent receive activity at index 0.
  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    (async () => {
      try {
        const id = await walletGhostId();
        if (!alive) return;
        setGhostId(id.ghost_id);
        const mix = await lightReceive(90);
        const change = await lightReceive(91);
        if (!alive) return;
        if (!mixOutAddr) setMixOutAddr(mix.address);
        if (!changeAddr) setChangeAddr(change.address);
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeWallet]);

  const onRotateAddresses = async () => {
    setErr(null);
    setBusy(true);
    try {
      const baseIndex = 90 + Math.floor(Math.random() * 1000);
      const mix = await lightReceive(baseIndex);
      const change = await lightReceive(baseIndex + 1);
      setMixOutAddr(mix.address);
      setChangeAddr(change.address);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onScan = async () => {
    setErr(null);
    setScanning(true);
    try {
      const r = await lightL1Utxos(scanMax, 0);
      setUtxos(r.utxos);
      setChainHeight(r.chain_height);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setScanning(false);
    }
  };

  const onPick = (u: LightL1UtxoEntry) => {
    setUtxoTxid(u.txid);
    setUtxoVout(String(u.vout));
    setUtxoValue(String(u.amount_sats));
    setUtxoScript(u.scriptpubkey_hex);
    setBip86Index(String(u.bip86_index));
  };

  const onRun = async () => {
    setErr(null);
    setResult(null);

    if (!activeWallet) {
      setErr("No active wallet.");
      return;
    }
    if (!ghostId) {
      setErr("Ghost ID not loaded yet — try again in a second.");
      return;
    }
    const vout = Number(utxoVout);
    const value = Number(utxoValue);
    if (!utxoTxid || !Number.isInteger(vout) || vout < 0) {
      setErr("UTXO txid and a non-negative vout are required.");
      return;
    }
    if (!Number.isFinite(value) || value <= 0) {
      setErr("UTXO value (sats) must be positive.");
      return;
    }
    if (!utxoScript) {
      setErr("UTXO scriptPubKey (hex) is required for sighash.");
      return;
    }
    if (value < tier.denom_sats + tier.bond_sats) {
      setErr(
        `UTXO value (${value.toLocaleString()}) is below ` +
          `tier denom + bond (${(tier.denom_sats + tier.bond_sats).toLocaleString()}).`,
      );
      return;
    }
    if (!mixOutAddr) {
      setErr("Mix output address is required.");
      return;
    }

    const peers = coordinatorPeersText
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const idx = bip86Index.trim() ? Number(bip86Index) : undefined;
    if (idx !== undefined && (!Number.isInteger(idx) || idx < 0)) {
      setErr("BIP86 index must be a non-negative integer.");
      return;
    }

    setBusy(true);
    try {
      const r = await wraithMixRun({
        coordinator_url: effectiveCoordinator,
        coordinator_peers: peers,
        tier_id: tierId,
        ghost_id: ghostId,
        utxo_txid: utxoTxid.trim(),
        utxo_vout: vout,
        utxo_value_sats: value,
        utxo_scriptpubkey_hex: utxoScript.trim(),
        change_address: changeAddr.trim() || undefined,
        mix_output_address: mixOutAddr.trim(),
        bip86_index: idx,
      });
      setResult(r);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <h1>Mix</h1>
        <div className="card muted">
          Select and unlock a wallet first to run a Wraith CoinJoin.
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">privacy · l1 coinjoin</span>
          <h1>Wraith mix</h1>
          <p className="lead">
            One round, five denom-sized outputs, no input→output
            linkage. The coordinator can't link your input UTXO to
            your mix-output address — chain analysts see a generic
            CoinJoin.
          </p>
        </div>
      </div>

      {err && <div className="card error-card">{err}</div>}

      {result && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          <h2>Mix broadcast ✓</h2>
          <p className="muted" style={{ margin: 0 }}>
            The CoinJoin transaction hit the network. Once it
            confirms, your denom-sized output lands at the mix
            address — unlinked from the input UTXO.
          </p>
          <div className="kv">
            <div className="k">Session</div>
            <div className="v mono">{result.session_id}</div>
            <div className="k">Broadcast txid</div>
            <div className="v mono">{result.broadcast_txid}</div>
            <div className="k">Your output index</div>
            <div className="v">{result.mixed_output_tx_index}</div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2>Coordinator</h2>
          {discoverInfo ? (
            <span
              className="pill pass"
              title={`pool ${discoverInfo.pool_id}, network ${discoverInfo.network}, answered by ${discoverInfo.answered_by}`}
            >
              connected · {discoverInfo.network}
            </span>
          ) : discoverErr ? (
            <span className="pill fail" title={discoverErr}>
              unreachable — using fallback tiers
            </span>
          ) : (
            <span className="pill mute">checking…</span>
          )}
        </div>
        <div className="col">
          <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={useNetworkCoordinator}
              onChange={(e) => setUseNetworkCoordinator(e.target.checked)}
              disabled={busy}
            />
            Use the network-elected coordinator
          </label>
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            Resolve the coordinator for this tier from the node&apos;s
            decentralised election (via ghost-pay). Wallets mixing the same tier
            this epoch converge on one coordinator, for a larger anonymity set.
          </p>
          {useNetworkCoordinator && (
            <p className="muted" style={{ margin: 0, fontSize: 12 }}>
              {resolving
                ? "Resolving elected coordinator…"
                : resolvedEndpoint
                  ? `→ using elected coordinator ${resolvedEndpoint}${
                      resolvedEpoch != null ? ` (epoch ${resolvedEpoch})` : ""
                    }`
                  : (resolveErr ??
                    "No elected coordinator — using the manual URL below.")}
            </p>
          )}
        </div>

        <div className="col">
          <label>
            Coordinator URL
            {useNetworkCoordinator && resolvedEndpoint ? " (fallback)" : ""}
          </label>
          <input
            className="mono"
            value={coordinator}
            onChange={(e) => setCoordinator(e.target.value)}
            disabled={busy}
            placeholder={DEFAULT_COORDINATOR}
          />
        </div>
        <div className="col">
          <label>
            Failover peer URLs (optional, comma- or space-separated)
          </label>
          <input
            className="mono"
            value={coordinatorPeersText}
            onChange={(e) => setCoordinatorPeersText(e.target.value)}
            disabled={busy}
            placeholder="http://standby-1.example:9100, http://standby-2.example:9100"
          />
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>
            Used in order if the primary is unreachable. HTTP errors
            from the primary do not trigger failover.
          </p>
        </div>
        <div className="col">
          <label>Tier</label>
          <div className="tier-grid">
            {tiers.map((t) => (
              <button
                key={t.id}
                type="button"
                className={`tier-card${tierId === t.id ? " active" : ""}`}
                onClick={() => !busy && setTierId(t.id)}
                disabled={busy}
              >
                <div className="tier-label">{t.label}</div>
                <div className="tier-denom">
                  {t.denom_sats.toLocaleString()}{" "}
                  <span className="muted">sats</span>
                </div>
                <div className="tier-meta">
                  bond {t.bond_sats.toLocaleString()}
                  {t.min_participants ? ` · min ${t.min_participants}` : ""}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Wallet UTXOs</h2>
          <div className="row">
            <label style={{ margin: 0 }}>Scan up to index</label>
            <input
              type="number"
              min={1}
              max={1024}
              value={scanMax}
              onChange={(e) =>
                setScanMax(Math.max(1, Math.min(1024, Number(e.target.value) || 32)))
              }
              style={{ width: 80 }}
              disabled={scanning || busy}
            />
            <button
              className="secondary"
              onClick={onScan}
              disabled={scanning || busy}
              title="Ask ghost-pay to run scantxoutset against this wallet's BIP86 receive addresses"
            >
              {scanning ? "Scanning…" : "Scan L1"}
            </button>
          </div>
        </div>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Unspent outputs at this wallet's BIP86 receive addresses
          0..{scanMax}. Backed by Bitcoin Core's{" "}
          <code>scantxoutset</code> via ghost-pay
          {chainHeight != null && (
            <> (chain height {chainHeight.toLocaleString()})</>
          )}
          . Mainnet scans take 5-15s; signet/regtest are sub-second.
        </p>
        {utxos.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Index</th>
                <th>Outpoint</th>
                <th>Amount (sats)</th>
                <th>Conf</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {utxos.map((u) => {
                const enough =
                  u.amount_sats >= tier.denom_sats + tier.bond_sats;
                return (
                  <tr key={`${u.txid}:${u.vout}`}>
                    <td className="mono">{u.bip86_index}</td>
                    <td className="mono muted">
                      {u.txid.slice(0, 12)}…:{u.vout}
                    </td>
                    <td>
                      {u.amount_sats.toLocaleString()}{" "}
                      {!enough && (
                        <span
                          className="pill warn"
                          title={`Needs ≥ ${(
                            tier.denom_sats + tier.bond_sats
                          ).toLocaleString()} for current tier`}
                        >
                          too small
                        </span>
                      )}
                    </td>
                    <td>{u.confirmations}</td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="secondary"
                        onClick={() => onPick(u)}
                        disabled={busy}
                      >
                        Use
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {!scanning && utxos.length === 0 && chainHeight !== null && (
          <p className="muted" style={{ margin: 0 }}>
            No unspent outputs found at indices 0..{scanMax}.
          </p>
        )}
      </div>

      {/* Selected UTXO summary — shows once Use is clicked or
          fields are populated. Value-aware: highlights if the UTXO
          covers denom + bond, warns otherwise. */}
      {(utxoTxid || utxoValue) && (
        <div
          className="card"
          style={{ borderColor: "var(--accent)", borderLeftWidth: 3 }}
        >
          <div className="card-header">
            <h2>Selected UTXO</h2>
            <button
              className="btn-secondary btn-sm"
              onClick={() => {
                setUtxoTxid("");
                setUtxoVout("");
                setUtxoValue("");
                setUtxoScript("");
                setBip86Index("");
              }}
              disabled={busy}
            >
              Clear
            </button>
          </div>
          <div className="kv">
            <div className="k">Outpoint</div>
            <div className="v mono" style={{ wordBreak: "break-all" }}>
              {utxoTxid || "—"}
              {utxoVout && (
                <span className="muted">:{utxoVout}</span>
              )}
            </div>
            <div className="k">Value</div>
            <div className="v">
              {utxoValue
                ? `${Number(utxoValue).toLocaleString()} sats`
                : "—"}
              {Number(utxoValue) > 0 &&
                Number(utxoValue) < tier.denom_sats + tier.bond_sats && (
                  <span
                    className="pill warn"
                    style={{ marginLeft: 8 }}
                    title={`needs ≥ ${(tier.denom_sats + tier.bond_sats).toLocaleString()} for ${tier.label}`}
                  >
                    too small for {tier.label}
                  </span>
                )}
            </div>
            {bip86Index && (
              <>
                <div className="k">BIP86 index</div>
                <div className="v mono">{bip86Index}</div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Output addresses summary — auto-derived; the user almost
          never wants to edit these. Tucked into a compact card with
          a Rotate button. */}
      <div className="card">
        <div className="card-header">
          <h2>Receive these into your wallet</h2>
          <button
            className="btn-secondary btn-sm"
            onClick={onRotateAddresses}
            disabled={busy}
            title="Re-derive at fresh BIP86 indices"
          >
            Rotate
          </button>
        </div>
        <div className="kv">
          <div className="k">Mix output</div>
          <div className="v mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
            {mixOutAddr || "—"}
          </div>
          <div className="k">Change</div>
          <div className="v mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
            {changeAddr || "—"}
          </div>
        </div>
      </div>

      {/* Run button — primary CTA, full-width feel. */}
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button
          className="btn-primary"
          onClick={onRun}
          disabled={busy}
          style={{ padding: "12px 28px", fontSize: 15 }}
        >
          {busy ? "Running mix…" : "Run mix →"}
        </button>
      </div>

      {/* Advanced / manual entry — disclosure for power users who
          need to override the UTXO scan or paste a UTXO from
          another wallet. Hidden by default. */}
      <details className="card" style={{ paddingTop: 14 }}>
        <summary
          style={{
            cursor: "pointer",
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            textTransform: "uppercase",
            letterSpacing: "0.14em",
            color: "var(--dim)",
          }}
        >
          Advanced — manual UTXO entry
        </summary>
        <p className="muted" style={{ margin: "12px 0", fontSize: 13 }}>
          Override the scanner for cross-wallet UTXOs or surgical
          control. Value must cover denom + bond + dust for the
          chosen tier.
        </p>
        <div className="row">
          <div className="col" style={{ flex: 3 }}>
            <label>txid</label>
            <input
              className="mono"
              value={utxoTxid}
              onChange={(e) => setUtxoTxid(e.target.value)}
              disabled={busy}
              placeholder="64-hex-char txid"
            />
          </div>
          <div className="col" style={{ flex: 1 }}>
            <label>vout</label>
            <input
              type="number"
              min={0}
              value={utxoVout}
              onChange={(e) => setUtxoVout(e.target.value)}
              disabled={busy}
            />
          </div>
        </div>
        <div className="row">
          <div className="col" style={{ flex: 1 }}>
            <label>value (sats)</label>
            <input
              type="number"
              min={1}
              value={utxoValue}
              onChange={(e) => setUtxoValue(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="col" style={{ flex: 1 }}>
            <label>BIP86 index</label>
            <input
              type="number"
              min={0}
              value={bip86Index}
              onChange={(e) => setBip86Index(e.target.value)}
              disabled={busy}
              placeholder="auto-scan if blank"
            />
          </div>
        </div>
        <div className="col">
          <label>scriptPubKey (hex)</label>
          <input
            className="mono"
            value={utxoScript}
            onChange={(e) => setUtxoScript(e.target.value)}
            disabled={busy}
            placeholder="P2TR scriptPubKey of the input"
          />
        </div>
        <div className="col">
          <label>Mix output address (override)</label>
          <input
            className="mono"
            value={mixOutAddr}
            onChange={(e) => setMixOutAddr(e.target.value)}
            disabled={busy}
          />
        </div>
        <div className="col">
          <label>Change address (override)</label>
          <input
            className="mono"
            value={changeAddr}
            onChange={(e) => setChangeAddr(e.target.value)}
            disabled={busy}
          />
        </div>
      </details>
    </div>
  );
}
