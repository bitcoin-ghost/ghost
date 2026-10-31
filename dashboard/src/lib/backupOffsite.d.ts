/** Types for the shared off-node backup validator (#1016). */
export declare function validateOffsiteSetting(body: {
  kind?: unknown;
  target?: unknown;
  keep?: unknown;
  port?: unknown;
}): { ok: true; input: string } | { ok: false; error: string };
export declare function isValidPath(p: string): boolean;
export declare function isValidHost(h: string): boolean;
export declare const OFFSITE_ACTIONS: readonly ["set", "disable", "keygen", "test"];
export declare const DEFAULT_KEEP: number;
