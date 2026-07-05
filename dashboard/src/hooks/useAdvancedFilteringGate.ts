"use client";

import { useCallback, useSyncExternalStore } from "react";

// Per-browser UI gate (not a backend field) for the Filtering › Advanced page.
// Keeps the advanced reaper + custom-policy controls hidden until an operator
// deliberately opts in. Persisted in localStorage so the choice survives reloads
// and is shared across the Advanced page (read + write) and the Overview (read).
const ADVANCED_ENABLED_KEY = "ghost.filtering.advancedEnabled";
// Same-tab change signal — the `storage` event only fires in OTHER tabs, so a
// write dispatches this to notify subscribers in the current tab too.
const CHANGE_EVENT = "ghost-advanced-filtering-change";

function readGate(): boolean {
  try {
    return window.localStorage.getItem(ADVANCED_ENABLED_KEY) === "true";
  } catch {
    return false;
  }
}

function subscribe(onChange: () => void): () => void {
  window.addEventListener("storage", onChange);
  window.addEventListener(CHANGE_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(CHANGE_EVENT, onChange);
  };
}

/**
 * Reactive accessor for the advanced-controls gate. Returns the current value
 * (false during SSR / first paint) and a setter that persists + notifies every
 * subscriber in this tab.
 */
export function useAdvancedFilteringGate(): [boolean, (value: boolean) => void] {
  const enabled = useSyncExternalStore(subscribe, readGate, () => false);

  const setEnabled = useCallback((value: boolean) => {
    try {
      window.localStorage.setItem(ADVANCED_ENABLED_KEY, value ? "true" : "false");
    } catch {
      /* storage unavailable — the in-tab dispatch below still updates the UI */
    }
    window.dispatchEvent(new Event(CHANGE_EVENT));
  }, []);

  return [enabled, setEnabled];
}
