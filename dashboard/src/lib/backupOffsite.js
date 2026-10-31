"use strict";

/**
 * Validation for the OPTIONAL off-node backup destination (#1016).
 *
 * The authority is the root helper `/opt/ghost/bin/ghost-backup-offsite`, which re-validates every
 * value against the same whitelists and refuses anything else. This copy exists so the route can
 * refuse bad input with a 400 before anything privileged runs, and so the form can say what is
 * wrong at the point of entry. It must never be LOOSER than the helper; scripts/test-backup-offsite.sh
 * drives the helper with the same hostile strings tests/backup-offsite.test.js drives this with.
 *
 * Values are matched, never repaired: stripping the bad characters out of `/mnt/x;rm -rf /` leaves
 * a different path the operator never asked for.
 */

const PATH_RE = /^\/[A-Za-z0-9._/-]{1,254}$/;
const USER_RE = /^[A-Za-z_][A-Za-z0-9._-]{0,31}$/;
const HOST_RE =
  /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const SSH_TARGET_RE = /^([^@:/]+)@([^@:/]+):(\/.*)$/;
const DEFAULT_KEEP = 7;

/** @param {string} p */
function isValidPath(p) {
  if (typeof p !== "string" || !PATH_RE.test(p) || p === "/") return false;
  if (p.includes("//")) return false;
  const withSlash = `${p}/`;
  return !withSlash.includes("/./") && !withSlash.includes("/../");
}

/** @param {string} h */
function isValidHost(h) {
  return typeof h === "string" && h.length <= 253 && HOST_RE.test(h);
}

/**
 * Validate a requested setting.
 *
 * @param {{kind?: unknown, target?: unknown, keep?: unknown, port?: unknown}} body
 * @returns {{ok: true, input: string} | {ok: false, error: string}}
 *   `input` is the exact stdin for `ghost-backup-offsite set`: built from the validated values
 *   only, one `key=value` per line, so no field the caller sent is ever passed through as-is.
 */
function validateOffsiteSetting(body) {
  const b = body && typeof body === "object" ? body : {};
  const { kind, target } = b;
  const keep = b.keep === undefined || b.keep === null || b.keep === "" ? DEFAULT_KEEP : b.keep;
  const port = b.port === undefined || b.port === null || b.port === "" ? undefined : b.port;

  if (kind !== "local" && kind !== "ssh") {
    return { ok: false, error: "kind must be 'local' or 'ssh'" };
  }
  if (typeof target !== "string") {
    return { ok: false, error: "target is required" };
  }
  if (!Number.isInteger(keep) || keep < 1 || keep > 365) {
    return { ok: false, error: "keep must be a whole number from 1 to 365" };
  }

  const lines = [`kind=${kind}`, `target=${target}`, `keep=${keep}`];
  if (kind === "local") {
    if (!isValidPath(target)) {
      return {
        ok: false,
        error:
          "local target must be an absolute path of letters, digits and . _ - / only (no spaces, no '..')",
      };
    }
    if (port !== undefined) {
      return { ok: false, error: "a port applies to an ssh destination only" };
    }
  } else {
    const m = SSH_TARGET_RE.exec(target);
    if (!m || !USER_RE.test(m[1]) || !isValidHost(m[2]) || !isValidPath(m[3])) {
      return {
        ok: false,
        error:
          "ssh target must be user@host:/absolute/path — user and host of letters, digits and . _ -, path of letters, digits and . _ - /",
      };
    }
    const p = port === undefined ? 22 : port;
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      return { ok: false, error: "port must be a whole number from 1 to 65535" };
    }
    lines.push(`port=${p}`);
  }
  return { ok: true, input: `${lines.join("\n")}\n` };
}

/** The actions the route accepts, each mapped to the helper subcommand sudoers allows. */
const OFFSITE_ACTIONS = Object.freeze(["set", "disable", "keygen", "test"]);

module.exports = { validateOffsiteSetting, isValidPath, isValidHost, OFFSITE_ACTIONS, DEFAULT_KEEP };
