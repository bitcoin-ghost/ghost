import { useEffect, useId, useRef, useState, type ReactNode } from "react";

interface HelpTipProps {
  /// Heading shown at the top of the revealed popover.
  title: string;
  /// The explanation itself — a string (2–4 plain-language sentences)
  /// or richer nodes if a caller ever needs them.
  children: ReactNode;
  /// Accessible label for the trigger button. Defaults to a generic
  /// "What's this?" so every instance reads sensibly to a screen reader.
  label?: string;
  /// Which side of the trigger the popover opens toward. Defaults to
  /// "right"; use "left" near the right edge of a screen so it stays
  /// on-screen.
  align?: "left" | "right";
}

/// The one contextual-help affordance used across the wallet: a small
/// round "?" the user can click to reveal a concise explanation, and
/// click again (or press Escape, or click away) to dismiss. Purely
/// presentational and self-contained — no library, no portal — so it
/// drops in beside any heading or label without extra wiring.
export function HelpTip({ title, children, label, align = "right" }: HelpTipProps) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const panelId = useId();

  // Dismiss on outside click / Escape while open. Registered only when
  // open so we don't hold global listeners for every dormant tip.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <span className="helptip" ref={wrapRef}>
      <button
        type="button"
        className={`helptip-btn${open ? " open" : ""}`}
        aria-label={label ?? "What's this?"}
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((v) => !v)}
      >
        ?
      </button>
      {open && (
        <span
          id={panelId}
          role="tooltip"
          className={`helptip-panel ${align === "left" ? "align-left" : "align-right"}`}
        >
          <strong className="helptip-title">{title}</strong>
          <span className="helptip-body">{children}</span>
        </span>
      )}
    </span>
  );
}
