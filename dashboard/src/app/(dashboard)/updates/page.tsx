import { redirect } from "next/navigation";

// Legacy duplicate of /system's Updates section. Nothing in the dashboard links
// here any more; this server-side redirect is kept only so old external
// bookmarks to /updates still land on the canonical /system page.
export default function Page() {
  redirect("/system");
}
