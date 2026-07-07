"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";

export function SettingsSection({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader title={title} subtitle={subtitle} />
      <div className="space-y-4">{children}</div>
    </Card>
  );
}

export function ToggleRow({
  label,
  description,
  enabled,
  onChange,
  disabled = false,
  badge,
}: {
  label: string;
  description: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  badge?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="text-[color:var(--fg)] font-medium">{label}</span>
          {badge}
        </div>
        <div className="text-sm text-[color:var(--dim)]">{description}</div>
      </div>
      <Toggle enabled={enabled} onChange={onChange} label={label} disabled={disabled} />
    </div>
  );
}

export function StatusRow({ label, description, badge }: { label: string; description: string; badge: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="text-[color:var(--fg)] font-medium">{label}</span>
          {badge}
        </div>
        <div className="text-sm text-[color:var(--dim)]">{description}</div>
      </div>
    </div>
  );
}

export function NumberInput({
  label,
  value,
  onChange,
  min,
  max,
  step = 1,
  unit,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
  unit?: string;
}) {
  return (
    <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
      <span className="text-[color:var(--fg)]">{label}</span>
      <div className="flex items-center gap-2">
        <Input
          type="number"
          value={value}
          onChange={(e) => onChange(Number(e.target.value))}
          min={min}
          max={max}
          step={step}
          className="w-24 text-right"
        />
        {unit && <span className="text-[color:var(--dim)] text-sm w-12">{unit}</span>}
      </div>
    </div>
  );
}
