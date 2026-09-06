/**
 * The new four-lane Ghost Lock, viewed.
 *
 * # Why this needs a form at all
 *
 * A Lock is built from five public keys, two of which are MuSig2 aggregates —
 * one of owner and backup, one of owner and quorum. Those are products of an
 * interactive ceremony with the other party, and MuSig2 is not in this
 * workspace, so the wallet cannot derive them. It also has nowhere to store a
 * Lock yet.
 *
 * So this views a Lock whose keys already exist, and the form is where they come
 * from. That is a real limitation rather than an interim shortcut: **creating** a
 * Lock needs the ceremony, which is not built.
 *
 * The keys are public, so they are remembered locally to save retyping. Nothing
 * secret is stored here — the owner key never leaves the keystore, and the
 * daemon derives it there.
 */

import { useEffect, useState } from "react";
import { ghostLockLanes, type GhostLockLanes } from "../lib/tauri";
import { LockLanes } from "./LockLanes";

const STORE_KEY = "ghost-lock-keys";

type Keys = {
  backup_pubkey: string;
  heir_pubkey: string;
  quorum_pubkey: string;
  owner_backup_aggregate: string;
  owner_quorum_aggregate: string;
  inherit_height: string;
  anchor_height: string;
};

const EMPTY: Keys = {
  backup_pubkey: "",
  heir_pubkey: "",
  quorum_pubkey: "",
  owner_backup_aggregate: "",
  owner_quorum_aggregate: "",
  inherit_height: "",
  anchor_height: "",
};

const FIELDS: { key: keyof Keys; label: string; hint: string }[] = [
  {
    key: "owner_backup_aggregate",
    label: "Owner + backup aggregate",
    hint: "MuSig2 aggregate. Spends Savings without a script path.",
  },
  {
    key: "owner_quorum_aggregate",
    label: "Owner + quorum aggregate",
    hint: "MuSig2 aggregate. Spends Spending without a script path.",
  },
  { key: "backup_pubkey", label: "Backup key", hint: "Your second device." },
  {
    key: "heir_pubkey",
    label: "Heir key",
    hint: "Inherits Savings after the inheritance height.",
  },
  {
    key: "quorum_pubkey",
    label: "Quorum key",
    hint: "The Wraith quorum. Spends Investments alone.",
  },
];

function load(): Keys {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return raw ? { ...EMPTY, ...JSON.parse(raw) } : EMPTY;
  } catch {
    // A corrupt or unavailable store is not worth failing the screen for.
    return EMPTY;
  }
}

export function GhostLockPanel() {
  const [keys, setKeys] = useState<Keys>(EMPTY);
  const [data, setData] = useState<GhostLockLanes | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setKeys(load());
  }, []);

  const complete = FIELDS.every((f) => keys[f.key].trim().length > 0);

  const view = async () => {
    setBusy(true);
    setErr(null);
    try {
      const inherit = Number(keys.inherit_height);
      const anchor = Number(keys.anchor_height);
      if (!Number.isFinite(inherit) || !Number.isFinite(anchor)) {
        throw new Error("Heights must be numbers");
      }
      const r = await ghostLockLanes({
        backup_pubkey: keys.backup_pubkey.trim(),
        heir_pubkey: keys.heir_pubkey.trim(),
        quorum_pubkey: keys.quorum_pubkey.trim(),
        owner_backup_aggregate: keys.owner_backup_aggregate.trim(),
        owner_quorum_aggregate: keys.owner_quorum_aggregate.trim(),
        inherit_height: inherit,
        anchor_height: anchor,
      });
      try {
        localStorage.setItem(STORE_KEY, JSON.stringify(keys));
      } catch {
        // Not being able to remember them is a nuisance, not a failure.
      }
      setData(r);
      setOpen(false);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="ghost-lock-panel">
      <div className="card">
        <div className="card-header">
          <h2>Ghost Lock — four lanes</h2>
          <button className="btn-secondary btn-sm" onClick={() => setOpen(!open)}>
            {open ? "Hide keys" : data ? "Change keys" : "Enter keys"}
          </button>
        </div>
        <p className="muted" style={{ marginTop: 0 }}>
          Savings, Spending, Cash and Investments under one set of keys. This is
          the replacement for the Ghost Pay locks listed below — the two are
          different things and both are shown while the old one is retired.
        </p>

        {open && (
          <>
            <p className="muted">
              A Lock is viewed, not created, here. Two of these keys are MuSig2
              aggregates produced by a ceremony with your backup device and the
              quorum, which the wallet cannot perform on its own yet.
            </p>
            <div className="lock-key-form">
              {FIELDS.map((f) => (
                <label key={f.key} className="lock-key-field">
                  <span className="k">{f.label}</span>
                  <input
                    className="mono"
                    value={keys[f.key]}
                    placeholder="x-only public key, hex"
                    onChange={(e) =>
                      setKeys({ ...keys, [f.key]: e.target.value })
                    }
                  />
                  <span className="muted lock-key-hint">{f.hint}</span>
                </label>
              ))}
              <label className="lock-key-field">
                <span className="k">Anchor height</span>
                <input
                  className="mono"
                  value={keys.anchor_height}
                  placeholder="current tip"
                  onChange={(e) =>
                    setKeys({ ...keys, anchor_height: e.target.value })
                  }
                />
                <span className="muted lock-key-hint">
                  The height the Lock was anchored at.
                </span>
              </label>
              <label className="lock-key-field">
                <span className="k">Inheritance height</span>
                <input
                  className="mono"
                  value={keys.inherit_height}
                  placeholder="absolute block height"
                  onChange={(e) =>
                    setKeys({ ...keys, inherit_height: e.target.value })
                  }
                />
                <span className="muted lock-key-hint">
                  When the heir leaf matures. Must be beyond the anchor.
                </span>
              </label>
            </div>
            <button
              className="btn-primary"
              onClick={view}
              disabled={busy || !complete}
            >
              {busy ? "Reading…" : "View lanes"}
            </button>
            {!complete && (
              <p className="muted lock-key-hint">
                All five keys are needed — a Lock missing a lane is not a Lock.
              </p>
            )}
          </>
        )}
      </div>

      {err && <div className="card error-card">{err}</div>}
      {data && <LockLanes data={data} />}
    </div>
  );
}
