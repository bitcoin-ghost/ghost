import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { validateOffsiteSetting } from "@/lib/backupOffsite";

// ---------------------------------------------------------------------------
// Optional off-node backup destination (#1016) — read + configure
// ---------------------------------------------------------------------------
// The nightly database backup writes to /var/backups/ghost/db on the node's own
// disk. An operator MAY point a copy at a second place they control: a local
// directory on another filesystem (USB drive, NFS share) or an SFTP server.
// It is OFF by default and never mandatory.
//
// The dashboard is NOT root and touches none of the files involved. Every call
// goes through the root-owned helper `ghost-backup-offsite`, which sudoers
// (/etc/sudoers.d/ghost-backup-offsite) lets the dashboard user run with
// exactly one of five argvs: show | set | disable | keygen | test. Settings for
// `set` travel on the helper's STDIN as `key=value` lines built from values this
// route has already validated; the helper validates them again and is the
// authority. Nothing the client sends reaches an argv.
//
//   GET  — `show`: enabled, kind, target, port, keep, PUBLIC key, pinned host
//          key, last off-node result, newest local backup. The private key is
//          never read by this route or returned by the helper.
//   POST — { action: "set", kind, target, keep?, port? } | { action: "disable" }
//          | { action: "keygen" } | { action: "test" }. Returns the helper's
//          answer for the action plus the fresh `show` state.
//
// Auth-gated by middleware.ts (valid JWT session required) like every other
// /api path — this route adds no bypass. Node.js runtime (child_process).
// ---------------------------------------------------------------------------

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const HELPER_BIN = process.env.GHOST_BACKUP_OFFSITE_BIN ?? "/opt/ghost/bin/ghost-backup-offsite";
const SUDO_BIN = process.env.GHOST_SUDO_BIN ?? "sudo";

type Subcommand = "show" | "set" | "disable" | "keygen" | "test";

// `test` may wait on an SFTP connect (20s) and a small upload.
const TIMEOUTS: Record<Subcommand, number> = {
  show: 15_000,
  set: 30_000,
  disable: 15_000,
  keygen: 30_000,
  test: 90_000,
};

interface HelperResult {
  ok: boolean;
  error?: string;
  message?: string;
  [key: string]: unknown;
}

class HelperError extends Error {}

// Runs `sudo -n <helper> <sub>`, optionally writing `input` to its stdin, and
// parses the ONE JSON object it prints. A non-zero exit with a JSON answer is a
// refusal (returned, ok:false); anything without JSON is a HelperError.
function runHelper(sub: Subcommand, input?: string): Promise<HelperResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(SUDO_BIN, ["-n", HELPER_BIN, sub], {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: TIMEOUTS[sub],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      if (stdout.length < 65_536) stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      if (stderr.length < 4_096) stderr += d.toString();
    });
    child.on("error", (e) => reject(new HelperError(`could not run the backup helper: ${e.message}`)));
    child.on("close", (code, signal) => {
      const line = stdout.trim().split("\n").pop() ?? "";
      try {
        const parsed = JSON.parse(line) as HelperResult;
        if (parsed && typeof parsed === "object" && typeof parsed.ok === "boolean") {
          resolve(parsed);
          return;
        }
      } catch {
        // fall through
      }
      const why = signal ? `killed by ${signal}` : `exit ${code}`;
      reject(new HelperError(`backup helper '${sub}' gave no answer (${why}): ${stderr.trim().slice(0, 300)}`));
    });
    child.stdin.on("error", () => {
      // The helper may exit before reading stdin (e.g. sudo refused); reported via close.
    });
    child.stdin.end(input ?? "");
  });
}

function failure(error: unknown, status = 500) {
  const msg = error instanceof Error ? error.message : "unknown error";
  return NextResponse.json({ error: msg }, { status });
}

export async function GET() {
  try {
    const state = await runHelper("show");
    if (!state.ok) return NextResponse.json({ error: state.error ?? "show failed" }, { status: 500 });
    return NextResponse.json(state);
  } catch (error) {
    return failure(error);
  }
}

export async function POST(request: NextRequest) {
  let body: Record<string, unknown>;
  try {
    const parsed: unknown = await request.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    body = parsed as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const action = body.action;
  let result: HelperResult;
  try {
    switch (action) {
      case "set": {
        const v = validateOffsiteSetting(body);
        if (!v.ok) return NextResponse.json({ error: v.error }, { status: 400 });
        result = await runHelper("set", v.input);
        // The helper's refusals (a same-filesystem directory, one it cannot write) are the
        // operator's to fix, not a server fault.
        if (!result.ok) return NextResponse.json({ error: result.error ?? "refused" }, { status: 400 });
        break;
      }
      case "disable":
      case "keygen":
      case "test":
        // A failed `test` is an answer (the server's error, verbatim), not a route failure.
        result = await runHelper(action);
        break;
      default:
        return NextResponse.json(
          { error: "action must be one of: set, disable, keygen, test" },
          { status: 400 },
        );
    }
  } catch (error) {
    return failure(error);
  }

  try {
    const state = await runHelper("show");
    return NextResponse.json({ result, state });
  } catch {
    return NextResponse.json({ result, state: null });
  }
}
