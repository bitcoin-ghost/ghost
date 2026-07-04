"use client";

import Link from "next/link";
import { Ghost } from "lucide-react";

interface GhostBrandProps {
  /** Visual scale. `sm` = sidebar header, `md` = top header. */
  size?: "sm" | "md";
  /** Override the wordmark text. Default "ghost node". */
  label?: string;
  /** Where the brand links to. Default `/`. Pass `null` to render unlinked. */
  href?: string | null;
  className?: string;
}

/**
 * Ghost brand — orange Lucide ghost icon plus a tracked-out lowercase wordmark.
 * One source of truth for the logo across nav, sidebar, login screen, error
 * pages, etc. Sized via `size`; colors are `var(--accent)` for the icon and
 * `var(--fg)` for the text so it inverts cleanly with the theme toggle.
 */
export function GhostBrand({
  size = "md",
  label = "ghost node",
  href = "/",
  className = "",
}: GhostBrandProps) {
  const iconSize = size === "sm" ? 20 : 22;
  const fontSize = size === "sm" ? "13px" : "16px";

  const inner = (
    <span
      className={`inline-flex items-center gap-2.5 ${className}`}
      style={{ color: "var(--fg)" }}
    >
      <Ghost size={iconSize} strokeWidth={1.75} style={{ color: "var(--accent)" }} aria-hidden="true" />
      <span
        style={{
          fontFamily: "var(--font-sans)",
          fontWeight: 400,
          fontSize,
          letterSpacing: "0.3em",
          textTransform: "lowercase",
        }}
      >
        {label}
      </span>
    </span>
  );

  if (href === null) return inner;
  return (
    <Link href={href} className="bare" style={{ textDecoration: "none" }}>
      {inner}
    </Link>
  );
}
