"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode } from "react";

interface SidebarItemProps {
  href: string;
  icon: ReactNode;
  label: string;
  collapsed?: boolean;
  /** When provided, the parent (Sidebar) has computed the single active item
   *  via longest-prefix match, so nested routes highlight only their deepest
   *  match (e.g. /filtering/advanced does NOT also light up /filtering). */
  isActive?: boolean;
}

/**
 * Active state: 2px orange left-border + foreground color, no fill.
 * Hover:       foreground color, no fill.
 * Idle:        dim color.
 *
 * Borders carry the meaning — matches the website's "no card chrome,
 * borders only where they signal something" rule.
 */
export function SidebarItem({ href, icon, label, collapsed = false, isActive: isActiveProp }: SidebarItemProps) {
  const pathname = usePathname();
  const isActive = isActiveProp ?? (pathname === href || (href !== "/" && pathname.startsWith(href)));

  return (
    <Link
      href={href}
      title={collapsed ? label : undefined}
      className="bare flex items-center gap-3 transition-colors"
      style={{
        color: isActive ? "var(--fg)" : "var(--dim)",
        padding: collapsed ? "8px" : "8px 12px",
        paddingLeft: collapsed ? "8px" : isActive ? "10px" : "12px",
        borderLeft: isActive ? "2px solid var(--accent)" : "2px solid transparent",
        textDecoration: "none",
        fontSize: "14px",
        fontWeight: isActive ? 500 : 400,
        justifyContent: collapsed ? "center" : "flex-start",
      }}
      onMouseEnter={(e) => {
        if (!isActive) e.currentTarget.style.color = "var(--fg)";
      }}
      onMouseLeave={(e) => {
        if (!isActive) e.currentTarget.style.color = "var(--dim)";
      }}
    >
      <span
        className="flex-shrink-0"
        style={{ width: "16px", height: "16px", display: "inline-flex", alignItems: "center", justifyContent: "center" }}
      >
        {icon}
      </span>
      {!collapsed && <span style={{ fontFamily: "var(--font-sans)" }}>{label}</span>}
    </Link>
  );
}
