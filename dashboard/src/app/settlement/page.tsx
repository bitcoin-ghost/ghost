import { redirect } from "next/navigation";

// Legacy free-standing page (no dashboard chrome, manual polling, no React
// Query). Settlement state is now surfaced inside the Ghost Pay Network page
// (Settlement to L1 section, uses useSettlement).
export default function Page() {
  redirect("/ghost-pay");
}
