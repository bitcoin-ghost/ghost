"use client";

import { useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { useToast } from "@/components/ui/Toast";
import {
  checkGlyphAvailability,
  claimGlyph,
  getGhostId,
  getGlyph,
  GLYPH_GRID,
  GLYPH_PIXELS,
  type GlyphInfo,
} from "@/lib/api/ghostpay";

/// The 26-colour Ghost Glyph palette. Index -> [r, g, b]. Copied byte-for-byte
/// from crates/ghost-glyph/src/palette.rs — palette indices are what the bitmap
/// (and its uniqueness hash) are built from, so this must never drift.
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
  return new Array<number>(GLYPH_PIXELS).fill(0);
}

function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  return h.length > 20 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h;
}

export default function GlyphPage() {
  const toast = useToast();

  const [ghostId, setGhostId] = useState<string | null>(null);
  const [pixels, setPixels] = useState<number[]>(blankPixels);
  const [selected, setSelected] = useState<number>(1); // white by default
  const [info, setInfo] = useState<GlyphInfo | null>(null);
  const [designed, setDesigned] = useState(false);

  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [avail, setAvail] = useState<boolean | null>(null);
  const [painting, setPainting] = useState(false);

  // Load the node's ghost_id, then its existing glyph (if any). getGlyph
  // resolves to null on a 404 — the expected "not yet designed" path.
  useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(null);
    (async () => {
      try {
        const id = await getGhostId();
        if (!alive) return;
        const gid = id.ghost_id?.trim() || null;
        setGhostId(gid);
        if (!gid) {
          setErr("The node did not return a Ghost ID. Ghost Pay may be disabled on this node.");
          return;
        }
        const g = await getGlyph(gid);
        if (!alive) return;
        if (g && Array.isArray(g.pixels) && g.pixels.length === GLYPH_PIXELS) {
          setInfo(g);
          setPixels(g.pixels.slice());
          setDesigned(true);
        } else {
          setInfo(null);
          setPixels(blankPixels());
          setDesigned(false);
        }
      } catch (e) {
        if (!alive) return;
        setErr(e instanceof Error ? e.message : String(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const paint = (i: number) => {
    setPixels((prev) => {
      if (prev[i] === selected) return prev;
      const next = prev.slice();
      next[i] = selected;
      return next;
    });
    // Editing invalidates any prior availability result.
    setAvail(null);
  };

  const onClear = () => {
    setPixels(blankPixels());
    setAvail(null);
  };

  const onCheck = async () => {
    setErr(null);
    setAvail(null);
    setBusy(true);
    try {
      const available = await checkGlyphAvailability(pixels);
      setAvail(available);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onClaim = async () => {
    setErr(null);
    if (!ghostId) {
      setErr("Ghost ID not loaded yet — try again in a moment.");
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
      toast.success(
        "Glyph claimed",
        `Status ${r.status}. Pending until the funding lock confirms (see Locks).`,
      );
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
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

  const statusVariant = statusLabel === "registered" ? "success" : statusLabel === "pending" ? "warning" : "default";

  return (
    <div>
      <PageHeader
        eyebrow="identity · visual"
        title="Ghost Glyph"
        subtitle="A 16×16, 26-colour mark bound to your node's Ghost ID. Design one, check that it's unclaimed, then claim it — it locks in once its funding lock confirms."
      />

      {err && (
        <div
          className="mb-6 p-4 rounded"
          style={{ background: "rgba(220, 38, 38, 0.1)", border: "1px solid rgba(220, 38, 38, 0.4)", color: "#fca5a5" }}
        >
          {err}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Editor */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader
              title="Pixel editor"
              action={<Badge variant={statusVariant}>{statusLabel}</Badge>}
            />
            <p style={{ color: "var(--dim)", fontSize: "13px", margin: "0 0 12px" }}>
              Click — or click and drag — to paint with the selected colour.
            </p>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: `repeat(${GLYPH_GRID}, 1fr)`,
                gap: 1,
                width: "100%",
                maxWidth: 384,
                aspectRatio: "1 / 1",
                background: "var(--rule)",
                border: "1px solid var(--rule)",
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

            <div style={{ marginTop: 16 }}>
              <label style={{ color: "var(--dim)", fontSize: "13px" }}>Palette</label>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(13, 1fr)",
                  gap: 4,
                  maxWidth: 384,
                  marginTop: 6,
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
                      border: selected === idx ? "2px solid var(--accent)" : "1px solid var(--rule)",
                      borderRadius: 3,
                      padding: 0,
                      cursor: busy ? "default" : "pointer",
                    }}
                  />
                ))}
              </div>
              <p style={{ color: "var(--dim)", fontSize: "12px", margin: "8px 0 0" }}>
                Selected: colour {selected}
              </p>
            </div>

            <div className="flex flex-wrap gap-2" style={{ marginTop: 16 }}>
              <Button variant="outline" onClick={onClear} disabled={busy || loading}>
                Clear
              </Button>
              <Button variant="default" onClick={onCheck} loading={busy} disabled={loading}>
                Check availability
              </Button>
              <Button variant="primary" onClick={onClaim} loading={busy} disabled={loading || !ghostId}>
                Claim glyph
              </Button>
            </div>

            {avail !== null && (
              <div style={{ marginTop: 12 }}>
                <Badge variant={avail ? "success" : "error"}>
                  {avail ? "available — unclaimed" : "taken — pick another design"}
                </Badge>
              </div>
            )}
          </Card>
        </div>

        {/* Preview + details */}
        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader title="Preview" />
            <div
              style={{
                display: "grid",
                gridTemplateColumns: `repeat(${GLYPH_GRID}, 1fr)`,
                width: "100%",
                maxWidth: 256,
                aspectRatio: "1 / 1",
                imageRendering: "pixelated",
                border: "1px solid var(--rule)",
              }}
            >
              {pixels.map((p, i) => (
                <div key={i} style={{ background: rgb(p), aspectRatio: "1 / 1" }} />
              ))}
            </div>
          </Card>

          <Card>
            <CardHeader title="Details" />
            <dl style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "8px 16px", fontSize: 13 }}>
              <dt style={{ color: "var(--dim)" }}>Ghost ID</dt>
              <dd className="font-mono" style={{ wordBreak: "break-all", color: "var(--fg)" }}>
                {ghostId ?? (loading ? "loading…" : "—")}
              </dd>
              <dt style={{ color: "var(--dim)" }}>Status</dt>
              <dd style={{ color: "var(--fg)" }}>{statusLabel}</dd>
              <dt style={{ color: "var(--dim)" }}>Bitmap hash</dt>
              <dd className="font-mono" title={info?.bitmap_hash ?? ""} style={{ color: "var(--fg)" }}>
                {shortHash(info?.bitmap_hash)}
              </dd>
              <dt style={{ color: "var(--dim)" }}>Commitment</dt>
              <dd className="font-mono" title={info?.commitment ?? ""} style={{ color: "var(--fg)" }}>
                {shortHash(info?.commitment)}
              </dd>
              {info?.funding_txid && (
                <>
                  <dt style={{ color: "var(--dim)" }}>Funding txid</dt>
                  <dd className="font-mono" style={{ wordBreak: "break-all", color: "var(--fg)" }}>
                    {info.funding_txid}
                  </dd>
                </>
              )}
              {info?.registered_at != null && (
                <>
                  <dt style={{ color: "var(--dim)" }}>Registered</dt>
                  <dd style={{ color: "var(--fg)" }}>
                    {new Date(info.registered_at * 1000).toLocaleString()}
                  </dd>
                </>
              )}
            </dl>
          </Card>
        </div>
      </div>
    </div>
  );
}
