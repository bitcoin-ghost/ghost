"use client";

import { Button } from "@/components/ui/Button";

// ---------------------------------------------------------------------------
// StickySaveBar — a bottom-anchored "unsaved changes" bar that keeps a Save /
// Reset affordance reachable no matter how far the operator has scrolled.
//
// It uses `position: sticky; bottom: 0` so it floats at the bottom of the
// dashboard scroll container (the <main overflow-auto>) while any part of its
// host panel is on screen, then comes to rest flush with the panel's bottom
// edge. Negative horizontal/bottom margins cancel the host Card's `p-6`
// padding so the bar spans the card width like a real footer.
//
// It renders nothing when there are no pending edits, so the panel returns to
// a clean/hidden state after a successful save.
// ---------------------------------------------------------------------------

export function StickySaveBar({
  dirty,
  saving,
  onSave,
  onReset,
  saveLabel = "Save changes",
}: {
  dirty: boolean;
  saving: boolean;
  onSave: () => void;
  onReset: () => void;
  saveLabel?: string;
}) {
  if (!dirty) return null;

  return (
    <div
      className="animate-slide-up"
      style={{
        position: "sticky",
        bottom: 0,
        zIndex: 20,
        // Cancel the host Card's 24px padding so the bar sits flush with its edges.
        margin: "16px -24px -24px",
        padding: "12px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "16px",
        flexWrap: "wrap",
        background: "var(--surface)",
        borderTop: "1px solid var(--accent)",
        borderBottomLeftRadius: "4px",
        borderBottomRightRadius: "4px",
        boxShadow: "0 -6px 20px -8px rgba(0, 0, 0, 0.35)",
      }}
    >
      <div className="flex items-center gap-2">
        <span
          aria-hidden
          style={{
            width: "8px",
            height: "8px",
            borderRadius: "50%",
            background: "var(--accent)",
            flex: "0 0 auto",
          }}
        />
        <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 600 }}>
          Unsaved changes
        </span>
      </div>
      <div className="flex items-center gap-2" style={{ flex: "0 0 auto" }}>
        <Button variant="ghost" size="sm" onClick={onReset} disabled={saving}>
          Reset
        </Button>
        <Button variant="primary" size="sm" onClick={onSave} loading={saving} disabled={saving}>
          {saveLabel}
        </Button>
      </div>
    </div>
  );
}
