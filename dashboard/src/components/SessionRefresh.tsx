"use client";

import { useEffect } from "react";

/**
 * Slides the session cookie while the operator is actively using the dashboard.
 *
 * The server issues tokens with a fixed TTL (DASHBOARD_TOKEN_TTL_SECS, default
 * 1 hour). Without refresh, an operator gets redirected to /login on the first
 * action after expiry — and because the Home (overview) and Sync screens run an
 * always-on socket, they surface that expiry *immediately* as a bounce to
 * /login, while plain REST pages only throw. So a lapsed session looks like
 * "overview and sync force a re-login."
 *
 * A bare 20-minute `setInterval` is not enough on its own: browsers throttle or
 * pause timers in a backgrounded tab, so the interval can silently lapse past
 * the 1-hour TTL while the tab is hidden. We therefore also renew immediately on
 * mount and whenever the tab returns to the foreground (visibility / focus), so
 * a session that was merely idle (not yet expired) is slid the moment the
 * operator comes back, before any socket reconnects and probes it.
 *
 * If the refresh returns 401 the token has already been invalidated — we let
 * the next route navigation trigger the middleware-driven redirect rather than
 * forcing a reload here.
 */
const REFRESH_INTERVAL_MS = 20 * 60 * 1000; // 20 minutes

export function SessionRefresh() {
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (window.location.pathname.startsWith("/login")) return;

    let cancelled = false;
    const refresh = async () => {
      try {
        await fetch("/api/auth/refresh", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
        });
      } catch {
        // Ignore — network blip. Next cycle, focus, or navigation recovers it.
      }
    };

    // Slide once on mount so a session that sat idle in a backgrounded tab is
    // renewed the moment the operator returns to the dashboard.
    void refresh();

    const handle = window.setInterval(() => {
      if (!cancelled) void refresh();
    }, REFRESH_INTERVAL_MS);

    // Timers are throttled/paused in hidden tabs, so renew on return-to-front.
    const onForeground = () => {
      if (cancelled) return;
      if (document.visibilityState === "visible") void refresh();
    };
    document.addEventListener("visibilitychange", onForeground);
    window.addEventListener("focus", onForeground);

    return () => {
      cancelled = true;
      window.clearInterval(handle);
      document.removeEventListener("visibilitychange", onForeground);
      window.removeEventListener("focus", onForeground);
    };
  }, []);

  return null;
}
