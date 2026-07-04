import { useState } from "react";
import { Logo } from "./Logo";
import { CATEGORY_HELP } from "../lib/help";

interface FirstRunTourProps {
  /// Called when the user finishes or skips. The parent persists the
  /// "seen" flag and unmounts the tour — see App.tsx `dismissTour`.
  onClose: () => void;
}

interface TourStep {
  eyebrow: string;
  title: string;
  body: string;
}

// A short, linear walk-through of the four nav categories plus the two
// things a newcomer reaches for first: the connection indicator and
// sending money. Category copy is pulled straight from CATEGORY_HELP so
// the tour never contradicts the sidebar "?" text.
const STEPS: TourStep[] = [
  {
    eyebrow: "welcome",
    title: "Welcome to Ghost Wallet",
    body: "A quick tour of where everything lives. It takes about a minute, and you can skip it any time — you'll find it again under Settings.",
  },
  {
    eyebrow: "category · 1 of 4",
    title: "Wallet",
    body: CATEGORY_HELP.Wallet,
  },
  {
    eyebrow: "category · 2 of 4",
    title: "Payments",
    body: CATEGORY_HELP.Payments,
  },
  {
    eyebrow: "category · 3 of 4",
    title: "Merchant",
    body: CATEGORY_HELP.Merchant,
  },
  {
    eyebrow: "category · 4 of 4",
    title: "System",
    body: CATEGORY_HELP.System,
  },
  {
    eyebrow: "staying connected",
    title: "Connection status",
    body: "Look to the top-right of the window. A small indicator there shows whether the wallet is talking to a Ghost node. If it ever reads offline, open Network or Settings to check your connection — nothing can send or receive until it's green.",
  },
  {
    eyebrow: "your first payment",
    title: "Sending money",
    body: "Open Payments, then Send. Paste a ghost-id or a Bitcoin address, enter an amount, and choose Ghost Pay for an instant fee-free transfer or on-chain for a normal Bitcoin payment. The little ? on each screen explains the choices as you go.",
  },
];

/// First-launch guided tour. A plain modal built on the existing
/// modal styles — skippable at every step, and shown only until the
/// user finishes or skips once (the parent stores the flag). Kept
/// deliberately light: no spotlight/overlay-pointer machinery, just
/// clear words and a progress rail.
export function FirstRunTour({ onClose }: FirstRunTourProps) {
  const [idx, setIdx] = useState(0);
  const step = STEPS[idx];
  const isLast = idx === STEPS.length - 1;

  return (
    <div className="modal-overlay">
      <div className="modal-card tour-card" onClick={(e) => e.stopPropagation()}>
        <div className="card-header">
          <div className="row" style={{ gap: 10, alignItems: "center" }}>
            <Logo size={22} />
            <span className="eyebrow eyebrow-dim">{step.eyebrow}</span>
          </div>
          <button className="btn-secondary btn-sm" onClick={onClose}>
            Skip tour
          </button>
        </div>

        {/* TODO(design): a small illustrated diagram per step goes here
            (e.g. an annotated screenshot of the relevant nav category or
            the connection indicator). Text-only for now by design. */}

        <h2 style={{ margin: 0 }}>{step.title}</h2>
        <p className="muted" style={{ margin: 0 }}>
          {step.body}
        </p>

        <div className="tour-dots" aria-hidden="true">
          {STEPS.map((_, i) => (
            <span
              key={i}
              className={`tour-dot${i === idx ? " active" : ""}`}
            />
          ))}
        </div>

        <div className="row" style={{ justifyContent: "space-between", gap: 8 }}>
          <button
            className="btn-secondary"
            onClick={() => setIdx((i) => Math.max(0, i - 1))}
            disabled={idx === 0}
          >
            Back
          </button>
          {isLast ? (
            <button className="btn-primary" onClick={onClose}>
              Get started
            </button>
          ) : (
            <button
              className="btn-primary"
              onClick={() => setIdx((i) => Math.min(STEPS.length - 1, i + 1))}
            >
              Next →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
