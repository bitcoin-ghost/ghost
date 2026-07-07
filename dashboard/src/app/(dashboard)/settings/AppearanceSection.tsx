"use client";

import { useUIStore, ACCENT_COLORS, type AccentColorKey } from "@/stores";
import { SettingsSection, ToggleRow } from "./shared";

export function AppearanceSection() {
  const accentColor = useUIStore((s) => s.accentColor);
  const setAccentColor = useUIStore((s) => s.setAccentColor);
  const tooltipsEnabled = useUIStore((s) => s.tooltipsEnabled);
  const setTooltipsEnabled = useUIStore((s) => s.setTooltipsEnabled);

  return (
    <SettingsSection title="Appearance" subtitle="Customize the dashboard theme">
      <div className="space-y-4">
        <div>
          <label className="block text-sm text-[color:var(--dim)] mb-3">Accent Color</label>
          <div className="grid grid-cols-4 sm:grid-cols-8 gap-3">
            {(Object.entries(ACCENT_COLORS) as [AccentColorKey, typeof ACCENT_COLORS[AccentColorKey]][]).map(
              ([key, color]) => (
                <button
                  key={key}
                  onClick={() => setAccentColor(key)}
                  className={`
                    relative h-10 w-10 rounded-lg transition-all duration-200
                    ${accentColor === key
                      ? 'ring-2 ring-[var(--fg)] ring-offset-2 ring-offset-[var(--bg)] scale-110'
                      : 'hover:scale-105'
                    }
                  `}
                  style={{ backgroundColor: color.hex }}
                  title={color.name}
                >
                  {accentColor === key && (
                    <div className="absolute inset-0 flex items-center justify-center">
                      <svg className="w-5 h-5 text-white drop-shadow-lg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                  )}
                </button>
              )
            )}
          </div>
          <p className="text-xs text-[color:var(--fainter)] mt-3">
            Current: <span style={{ color: ACCENT_COLORS[accentColor].hex }}>{ACCENT_COLORS[accentColor].name}</span>
          </p>
        </div>

        <ToggleRow
          label="Tooltips"
          description="Show helpful tooltips when hovering over elements"
          enabled={tooltipsEnabled}
          onChange={setTooltipsEnabled}
        />
      </div>
    </SettingsSection>
  );
}
