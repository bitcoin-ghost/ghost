import { useEffect, useMemo, useState } from "react";
import {
  checkGlyph,
  claimGlyph,
  getGlyph,
  walletGhostId,
  type GlyphInfo,
} from "../lib/tauri";

interface GlyphProps {
  activeWallet: string | null;
}

const GRID = 16;
const PIXELS = GRID * GRID; // 256

/// The 26-colour Ghost Glyph palette. Index → [r, g, b]. Copied
/// byte-for-byte from `crates/ghost-glyph/src/palette.rs` — palette
/// indices are what the bitmap (and its hash) are built from, so this
/// must never drift from the crate.
const PALETTE: [number, number, number][] = [
  [0, 0, 0],
  [255, 255, 255],
  [28, 28, 36],
  [48, 48, 64],
  [80, 80, 104],
  [128, 128, 160],
  [192, 192, 212],
  [24, 32, 80],
  [40, 60, 140],
  [64, 100, 200],
  [120, 160, 230],
  [16, 48, 32],
  [32, 100, 64],
  [80, 200, 120],
  [160, 240, 180],
  [80, 16, 16],
  [160, 40, 24],
  [220, 80, 40],
  [255, 160, 80],
  [48, 16, 80],
  [100, 40, 160],
  [160, 80, 220],
  [200, 160, 255],
  [255, 220, 60],
  [0, 200, 200],
  [255, 100, 160],
];

function rgb(idx: number): string {
  const c = PALETTE[idx] ?? PALETTE[0];
  return `rgb(${c[0]}, ${c[1]}, ${c[2]})`;
}

function blankPixels(): number[] {
  return new Array<number>(PIXELS).fill(0);
}

function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  return h.length > 20 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h;
}

export function Glyph({ activeWallet }: GlyphProps) {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [pixels, setPixels] = useState<number[]>(blankPixels);
  const [selected, setSelected] = useState<number>(1); // white by default
  const [info, setInfo] = useState<GlyphInfo | null>(null);
  const [designed, setDesigned] = useState(false);

  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [avail, setAvail] = useState<boolean | null>(null);
  const [claimMsg, setClaimMsg] = useState<string | null>(null);
  const [painting, setPainting] = useState(false);

  // Load the wallet's ghost_id, then its existing glyph (if any). A
  // daemon error on getGlyph (ghost-pay 404 — no glyph registered)
  // is the expected "not yet designed" path: start from a blank grid.
  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    setLoading(true);
    setErr(null);
    setAvail(null);
    setClaimMsg(null);
    (async () => {
      try {
        const id = await walletGhostId();
        if (!alive) return;
        setGhostId(id.ghost_id);
        try {
          const g = await getGlyph(id.ghost_id);
          if (!alive) return;
          if (g.pixels && g.pixels.length === PIXELS && g.status !== "none") {
            setInfo(g);
            setPixels(g.pixels.slice());
            setDesigned(true);
          } else {
            setInfo(g.status === "none" ? null : g);
            setPixels(blankPixels());
            setDesigned(false);
          }
        } catch {
          // No glyph registered yet — blank canvas.
          if (!alive) return;
          setInfo(null);
          setPixels(blankPixels());
          setDesigned(false);
        }
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeWallet]);

  const paint = (i: number) => {
    setPixels((prev) => {
      if (prev[i] === selected) return prev;
      const next = prev.slice();
      next[i] = selected;
      return next;
    });
    // Editing invalidates any prior availability / claim result.
    setAvail(null);
    setClaimMsg(null);
  };

  const onClear = () => {
    setPixels(blankPixels());
    setAvail(null);
    setClaimMsg(null);
  };

  const onCheck = async () => {
    setErr(null);
    setAvail(null);
    setClaimMsg(null);
    setBusy(true);
    try {
      const r = await checkGlyph(pixels);
      setAvail(r.available);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onClaim = async () => {
    setErr(null);
    setClaimMsg(null);
    if (!ghostId) {
      setErr("Ghost ID not loaded yet — try again in a second.");
      return;
    }
    setBusy(true);
    try {
      const r = await claimGlyph(ghostId, pixels);
      setInfo((prev) => ({
        ghost_id: ghostId,
        pixels: pixels.slice(),
        bitmap_hash: r.bitmap_hash,
        commitment: r.commitment,
        funding_txid: prev?.funding_txid ?? null,
        registered_at: prev?.registered_at ?? null,
        status: r.status,
      }));
      setDesigned(true);
      setClaimMsg(
        `Claimed — status ${r.status}. Pending until the lock funds (see Locks).`,
      );
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const statusLabel = useMemo(() => {
    const s = info?.status ?? (designed ? "pending" : "none");
    if (s === "registered") return "registered";
    if (s === "pending") return "pending";
    return "not yet designed";
  }, [info, designed]);

  if (!activeWallet) {
    return (
      <div className="screen">
        <h1>Glyph</h1>
        <div className="card muted">
          Select and unlock a wallet first to view or design its Ghost
          Glyph.
        </div>
      </div>
    );
  }

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">identity · visual</span>
          <h1>Ghost Glyph</h1>
          <p className="lead">
            A 16×16, 26-colour mark bound to your Ghost ID. Design one,
            check it's unclaimed, then claim it — it locks in once its
            funding lock confirms.
          </p>
        </div>
      </div>

      {err && <div className="card error-card">{err}</div>}

      {claimMsg && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          <p className="muted" style={{ margin: 0 }}>
            {claimMsg}
          </p>
        </div>
      )}

      <div className="row" style={{ alignItems: "flex-start", gap: 16 }}>
        {/* Editor */}
        <div className="card" style={{ flex: 2 }}>
          <div className="card-header">
            <h2>Pixel editor</h2>
            <span className="pill mute" title={`status: ${statusLabel}`}>
              {statusLabel}
            </span>
          </div>
          <p className="muted" style={{ margin: "0 0 12px", fontSize: 13 }}>
            Click — or click and drag — to paint with the selected colour.
          </p>
          <div
            className="glyph-grid"
            style={{
              display: "grid",
              gridTemplateColumns: `repeat(${GRID}, 1fr)`,
              gap: 1,
              width: "100%",
              maxWidth: 384,
              aspectRatio: "1 / 1",
              background: "var(--border, #333)",
              border: "1px solid var(--border, #333)",
              userSelect: "none",
            }}
            onMouseLeave={() => setPainting(false)}
          >
            {pixels.map((p, i) => (
              <button
                key={i}
                type="button"
                aria-label={`pixel ${i}`}
                onMouseDown={() => {
                  if (loading || busy) return;
                  setPainting(true);
                  paint(i);
                }}
                onMouseEnter={() => {
                  if (painting && !loading && !busy) paint(i);
                }}
                onMouseUp={() => setPainting(false)}
                disabled={loading || busy}
                style={{
                  background: rgb(p),
                  border: 0,
                  padding: 0,
                  margin: 0,
                  cursor: loading || busy ? "default" : "pointer",
                  aspectRatio: "1 / 1",
                }}
              />
            ))}
          </div>

          <div className="col" style={{ marginTop: 16 }}>
            <label>Palette</label>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(13, 1fr)",
                gap: 4,
                maxWidth: 384,
              }}
            >
              {PALETTE.map((_, idx) => (
                <button
                  key={idx}
                  type="button"
                  title={`colour ${idx}`}
                  aria-label={`palette colour ${idx}`}
                  onClick={() => setSelected(idx)}
                  disabled={busy}
                  style={{
                    background: rgb(idx),
                    aspectRatio: "1 / 1",
                    border:
                      selected === idx
                        ? "2px solid var(--accent, #fff)"
                        : "1px solid var(--border, #333)",
                    borderRadius: 3,
                    padding: 0,
                    cursor: busy ? "default" : "pointer",
                  }}
                />
              ))}
            </div>
            <p className="muted" style={{ margin: "8px 0 0", fontSize: 12 }}>
              Selected: colour {selected}
            </p>
          </div>

          <div className="row" style={{ marginTop: 16, gap: 8 }}>
            <button
              className="secondary"
              onClick={onClear}
              disabled={busy || loading}
            >
              Clear
            </button>
            <button
              className="secondary"
              onClick={onCheck}
              disabled={busy || loading}
            >
              {busy ? "Working…" : "Check availability"}
            </button>
            <button
              className="btn-primary"
              onClick={onClaim}
              disabled={busy || loading}
            >
              {busy ? "Working…" : "Claim glyph"}
            </button>
          </div>

          {avail !== null && (
            <p
              className={`pill ${avail ? "pass" : "fail"}`}
              style={{ marginTop: 12, display: "inline-block" }}
            >
              {avail ? "available — unclaimed" : "taken — pick another design"}
            </p>
          )}
        </div>

        {/* Preview + info */}
        <div className="col" style={{ flex: 1, gap: 16 }}>
          <div className="card">
            <h2>Preview</h2>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: `repeat(${GRID}, 1fr)`,
                width: "100%",
                maxWidth: 256,
                aspectRatio: "1 / 1",
                imageRendering: "pixelated",
                border: "1px solid var(--border, #333)",
              }}
            >
              {pixels.map((p, i) => (
                <div
                  key={i}
                  style={{ background: rgb(p), aspectRatio: "1 / 1" }}
                />
              ))}
            </div>
          </div>

          <div className="card">
            <h2>Details</h2>
            <div className="kv">
              <div className="k">Ghost ID</div>
              <div
                className="v mono"
                style={{ fontSize: 12, wordBreak: "break-all" }}
              >
                {ghostId ?? (loading ? "loading…" : "—")}
              </div>
              <div className="k">Status</div>
              <div className="v">{statusLabel}</div>
              <div className="k">Bitmap hash</div>
              <div className="v mono" title={info?.bitmap_hash ?? ""}>
                {shortHash(info?.bitmap_hash)}
              </div>
              <div className="k">Commitment</div>
              <div className="v mono" title={info?.commitment ?? ""}>
                {shortHash(info?.commitment)}
              </div>
              {info?.funding_txid && (
                <>
                  <div className="k">Funding txid</div>
                  <div
                    className="v mono"
                    style={{ fontSize: 12, wordBreak: "break-all" }}
                  >
                    {info.funding_txid}
                  </div>
                </>
              )}
              {info?.registered_at != null && (
                <>
                  <div className="k">Registered</div>
                  <div className="v">
                    {new Date(info.registered_at * 1000).toLocaleString()}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
