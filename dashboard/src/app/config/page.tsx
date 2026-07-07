import { redirect } from "next/navigation";

// Legacy non-grouped page — predates the /settings split. Modern equivalents:
//   /settings/general        — identity, payout address
//   /settings/capabilities   — archive_mode, ghost_pay, public_mining, reaper
//   /settings/filtering      — tier policy + reaper detectors
//   /settings/privacy        — ghost_mode + read-only privacy status
// Redirecting to /settings (which redirects on to /settings/general).
export default function Page() {
  redirect("/settings");
}
