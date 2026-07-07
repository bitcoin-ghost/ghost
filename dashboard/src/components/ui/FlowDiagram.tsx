interface FlowDiagramStep {
  label: string;
  sublabel: string;
  accent?: boolean;
}

const ACCENT_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  orange: { bg: "bg-[color-mix(in_srgb,var(--accent)_10%,transparent)]", border: "border-[color-mix(in_srgb,var(--accent)_30%,transparent)]", text: "text-[color:var(--accent)]" },
  blue:   { bg: "bg-blue-900/10",   border: "border-blue-600/30",   text: "text-blue-400" },
  red:    { bg: "bg-[color-mix(in_srgb,var(--red)_10%,transparent)]",    border: "border-[color-mix(in_srgb,var(--red)_30%,transparent)]",    text: "text-[color:var(--red)]" },
  green:  { bg: "bg-[color-mix(in_srgb,var(--green)_10%,transparent)]",  border: "border-[color-mix(in_srgb,var(--green)_30%,transparent)]",  text: "text-[color:var(--green)]" },
  purple: { bg: "bg-purple-900/10", border: "border-purple-600/30", text: "text-purple-400" },
};

function FlowArrow() {
  return (
    <div className="flex items-center px-1 text-[color:var(--fainter)] flex-shrink-0">
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
    </div>
  );
}

interface FlowDiagramProps {
  steps: FlowDiagramStep[];
  accentColor?: string;
}

export function FlowDiagram({ steps, accentColor = "blue" }: FlowDiagramProps) {
  const colors = ACCENT_COLORS[accentColor] ?? ACCENT_COLORS.blue;

  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-2">
      {steps.map((step, i) => (
        <div key={i} className="contents">
          {i > 0 && <FlowArrow />}
          <div className={`flex-1 text-center px-3 py-4 rounded-lg border ${
            step.accent
              ? `${colors.bg} ${colors.border}`
              : "bg-[var(--surface)]/50 border-[color:var(--rule-strong)]"
          }`}>
            <div className={`text-sm font-medium ${step.accent ? colors.text : "text-[color:var(--fg)]"}`}>
              {step.label}
            </div>
            <div className="text-xs text-[color:var(--fainter)] mt-1">{step.sublabel}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
