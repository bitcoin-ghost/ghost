import { ReactNode } from "react";
import { Badge } from "@/components/ui/Badge";
import { errorText, UNKNOWN, type Level } from "@/lib/pool/view";

/** Shown in place of data the node did not give: says what is missing and why. */
export function Unavailable({ what, error }: { what: string; error?: unknown }) {
  return (
    <div
      role="alert"
      data-testid="unavailable"
      className="p-4 rounded text-sm"
      style={{
        border: "1px solid color-mix(in srgb, var(--red) 40%, transparent)",
        background: "color-mix(in srgb, var(--red) 8%, transparent)",
        color: "var(--fg)",
      }}
    >
      <div style={{ color: "var(--red)" }} className="font-medium mb-1">
        {what} unavailable
      </div>
      <div style={{ color: "var(--dim)" }}>
        {errorText(error)}. Nothing below is shown as healthy or zero while this is so.
      </div>
    </div>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <div className="p-4 text-sm" style={{ color: "var(--dim)" }}>
      Loading {what}…
    </div>
  );
}

const VARIANT: Record<Level, "success" | "warning" | "error" | "default"> = {
  ok: "success",
  warn: "warning",
  error: "error",
  unknown: "default",
};

export function LevelBadge({ level, children }: { level: Level; children: ReactNode }) {
  return <Badge variant={VARIANT[level]}>{children}</Badge>;
}

/** One labelled value. A string equal to `UNKNOWN` is dimmed so it never reads as a reading. */
export function Kv({
  label,
  value,
  mono,
  hint,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  hint?: string;
}) {
  const unknown = value === UNKNOWN;
  return (
    <div className="p-3 rounded" style={{ background: "var(--surface)", border: "1px solid var(--rule)" }}>
      <div className="text-xs mb-1" style={{ color: "var(--fainter)" }} title={hint}>
        {label}
      </div>
      <div
        className={`text-sm break-all ${mono ? "font-mono" : ""}`}
        style={{ color: unknown ? "var(--fainter)" : "var(--fg)", fontStyle: unknown ? "italic" : undefined }}
      >
        {value}
      </div>
    </div>
  );
}

export function Grid({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">{children}</div>;
}

/** A plain table with a horizontal scroll on narrow screens. */
export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ color: "var(--fainter)", borderBottom: "1px solid var(--rule)" }}>
            {head.map((h) => (
              <th key={h} className="text-left font-normal py-2 pr-4 whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody style={{ color: "var(--fg)" }}>{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, mono }: { children: ReactNode; mono?: boolean }) {
  return (
    <td
      className={`py-2 pr-4 align-top ${mono ? "font-mono text-xs" : ""}`}
      style={{ borderBottom: "1px solid var(--rule)" }}
    >
      {children}
    </td>
  );
}

export function Note({ children }: { children: ReactNode }) {
  return (
    <p className="text-xs mt-3 leading-relaxed" style={{ color: "var(--fainter)" }}>
      {children}
    </p>
  );
}
