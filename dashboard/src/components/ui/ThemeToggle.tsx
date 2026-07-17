"use client";

import { useCallback, useSyncExternalStore } from "react";

type Theme = "light" | "dark";

const THEME_EVENT = "ghost-theme-change";

// The `<html data-theme>` attribute is external mutable state (set on first
// paint by the bootstrap script in layout.tsx). Read it via useSyncExternalStore
// — the SSR-safe, render-pure way to subscribe to external state — instead of an
// effect that copies it into local state.
function subscribeTheme(onChange: () => void): () => void {
  window.addEventListener(THEME_EVENT, onChange);
  return () => window.removeEventListener(THEME_EVENT, onChange);
}

function readTheme(): Theme {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

/** Reads the current theme from `<html data-theme>` (set on first paint by
 *  the bootstrap script in layout.tsx) and writes the chosen theme to both
 *  the attribute and localStorage so it survives reloads. */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const theme = useSyncExternalStore<Theme>(subscribeTheme, readTheme, () => "dark");

  const toggle = useCallback(() => {
    const next: Theme = readTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("ghost-theme", next);
    } catch {
      /* localStorage may be unavailable (private mode) — best effort only */
    }
    // Notify all subscribers (this toggle + any other mounted readers).
    window.dispatchEvent(new Event(THEME_EVENT));
  }, []);

  return (
    <button
      onClick={toggle}
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      title={theme === "dark" ? "Light theme" : "Dark theme"}
      className={`inline-flex items-center justify-center w-8 h-8 rounded transition-colors hover:bg-[var(--surface)] ${className}`}
      style={{ color: "var(--dim)" }}
    >
      {theme === "dark" ? (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
        </svg>
      ) : (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      )}
    </button>
  );
}
