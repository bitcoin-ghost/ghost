import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { execFile } from "child_process";
import { promisify } from "util";

// ---------------------------------------------------------------------------
// Auto-update opt-in (read + toggle)
// ---------------------------------------------------------------------------
// The node updater is gated by /etc/ghost/auto-update.conf (AUTO_UPDATE=true|
// false). The dashboard is NOT root and never writes that file directly.
//
//   GET  — reads the (world-readable) opt-in conf, the installed-version marker,
//          and the updater's last-run status file. Pure reads, no privilege.
//   POST — flips the opt-in by shelling out to the root-owned, sudoers-scoped
//          helper `ghost-autoupdate-toggle on|off`. The sudoers rule
//          (/etc/sudoers.d/ghost-autoupdate) pins the exact argument, so this
//          route can do nothing else as root.
//
// This route is auth-gated by middleware.ts (valid JWT session required) like
// every other /api path. It must run on the Node.js runtime (fs + child_process).
// ---------------------------------------------------------------------------

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const execFileAsync = promisify(execFile);

const CONF_PATH = process.env.GHOST_AUTOUPDATE_CONF ?? "/etc/ghost/auto-update.conf";
const VERSION_PATH = process.env.GHOST_VERSION_FILE ?? "/etc/ghost/version";
const STATUS_PATH = process.env.GHOST_AUTOUPDATE_STATUS ?? "/var/lib/ghost/auto-update.status";
const TOGGLE_BIN = process.env.GHOST_AUTOUPDATE_TOGGLE ?? "/opt/ghost/bin/ghost-autoupdate-toggle";

interface AutoUpdateStatus {
  last_run?: string;
  result?: string;
  message?: string;
  installed_version?: string;
  latest_version?: string;
}

interface AutoUpdateState {
  enabled: boolean;
  installed_version: string | null;
  latest_version: string | null;
  last_status: AutoUpdateStatus | null;
}

// AUTO_UPDATE is "on" ONLY when the conf says exactly `true` — mirrors the
// updater's own gate, so the UI can never imply opted-in when it isn't.
async function readEnabled(): Promise<boolean> {
  try {
    const raw = await readFile(CONF_PATH, "utf8");
    const m = raw.match(/^[ \t]*AUTO_UPDATE[ \t]*=[ \t]*([A-Za-z]+)/m);
    return m?.[1] === "true";
  } catch {
    return false; // missing/unreadable conf => treated as opted-out
  }
}

async function readInstalledVersion(): Promise<string | null> {
  try {
    const v = (await readFile(VERSION_PATH, "utf8")).trim();
    return v || null;
  } catch {
    return null;
  }
}

async function readStatus(): Promise<AutoUpdateStatus | null> {
  try {
    return JSON.parse(await readFile(STATUS_PATH, "utf8")) as AutoUpdateStatus;
  } catch {
    return null;
  }
}

async function buildState(): Promise<AutoUpdateState> {
  const [enabled, installed, status] = await Promise.all([
    readEnabled(),
    readInstalledVersion(),
    readStatus(),
  ]);
  return {
    enabled,
    installed_version: installed,
    latest_version: status?.latest_version ?? null,
    last_status: status,
  };
}

export async function GET() {
  try {
    return NextResponse.json(await buildState());
  } catch (error) {
    return NextResponse.json(
      { error: `Failed to read auto-update state: ${error instanceof Error ? error.message : "unknown"}` },
      { status: 500 },
    );
  }
}

export async function POST(request: NextRequest) {
  let body: { enabled?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  if (typeof body.enabled !== "boolean") {
    return NextResponse.json({ error: "Body must be { enabled: boolean }" }, { status: 400 });
  }

  // The ONLY two argv values are the fixed literals "on"/"off" — never user
  // text — so there is nothing to inject through the privileged helper.
  const arg = body.enabled ? "on" : "off";

  try {
    await execFileAsync("sudo", ["-n", TOGGLE_BIN, arg], { timeout: 15_000 });
  } catch (error) {
    const msg = error instanceof Error ? error.message : "unknown";
    return NextResponse.json(
      { error: `Failed to set auto-update (${arg}): ${msg}` },
      { status: 500 },
    );
  }

  // Return the freshly-read state so the client reflects ground truth, not the
  // value it optimistically sent.
  try {
    return NextResponse.json(await buildState());
  } catch {
    return NextResponse.json({ enabled: body.enabled });
  }
}
