// Shared BUDS class (T0–T3) colours — the single source of truth reused by the
// "four classes" cards, the "Your mempool by class" bar and the mining-policy
// preset pills. Keep these in sync in ONE place so surfaces never drift.

export type BudsTierKey = "T0" | "T1" | "T2" | "T3";

export const BUDS_TIER_COLORS: Record<BudsTierKey, string> = {
  T0: "#3fb950", // Financial — green
  T1: "#58a6ff", // Extended — blue
  T2: "#d29922", // Data — amber
  T3: "#f85149", // Abusive — red
};

// Ordered list of the four BUDS classes for iterating pills/legends.
export const BUDS_TIER_KEYS: BudsTierKey[] = ["T0", "T1", "T2", "T3"];
