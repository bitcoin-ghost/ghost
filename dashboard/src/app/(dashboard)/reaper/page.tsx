import { redirect } from "next/navigation";

// Reaper controls now live under Filtering › Advanced. Keep this route working
// for old links/bookmarks by redirecting there.
export default function ReaperRedirectPage() {
  redirect("/filtering/advanced");
}
