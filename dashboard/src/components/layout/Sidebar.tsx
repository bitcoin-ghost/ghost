"use client";

import {
  LayoutDashboard,
  Pickaxe,
  Activity,
  RefreshCw,
  ShieldCheck,
  Gauge,
  Network as NetworkIcon,
  Coins,
  Crown,
  Lock,
  Shield,
  Eye,
  Cloud,
  Filter,
  Layers,
  SlidersHorizontal,
  Globe,
  MapPin,
  HeartPulse,
  ScrollText,
  Users,
  CreditCard,
  Banknote,
  HardDrive,
  Cpu,
  Settings,
  ChevronLeft,
  X,
  Menu,
} from "lucide-react";

import { useUIStore, useConfigStore } from "@/stores";
import { useNodeStore } from "@/stores";
import { SidebarItem } from "./SidebarItem";
import { GhostBrand } from "@/components/ui/GhostBrand";
import { StatusDot } from "@/components/ui/StatusDot";
import { ThemeToggle } from "@/components/ui/ThemeToggle";

interface NavItem {
  href: string;
  label: string;
  icon: React.ReactNode;
}
interface NavGroup {
  label: string;
  items: NavItem[];
}

const ICON = { size: 16, strokeWidth: 1.75 } as const;

/**
 * Single source of nav truth — sidebar is the only navigation.
 * 7 groups, ~25 items, no nested dropdowns. Each group is rendered with
 * the website's `.section-label` rhythm: 11px IBM Plex Mono uppercase
 * tracked-out in `var(--accent)` orange.
 */
const GROUPS: NavGroup[] = [
  {
    label: "overview",
    items: [
      { href: "/", label: "Overview", icon: <LayoutDashboard {...ICON} /> },
      { href: "/mempool", label: "Mempool", icon: <Activity {...ICON} /> },
      { href: "/sync", label: "Sync", icon: <RefreshCw {...ICON} /> },
      { href: "/capabilities", label: "Capabilities", icon: <ShieldCheck {...ICON} /> },
      { href: "/geo", label: "Geo", icon: <MapPin {...ICON} /> },
    ],
  },
  {
    label: "filtering",
    items: [
      { href: "/filtering", label: "Overview", icon: <Filter {...ICON} /> },
      { href: "/filtering/basic", label: "Basic", icon: <Layers {...ICON} /> },
      { href: "/filtering/advanced", label: "Advanced", icon: <SlidersHorizontal {...ICON} /> },
    ],
  },
  {
    label: "ghost pool",
    items: [
      { href: "/mining", label: "Mining", icon: <Pickaxe {...ICON} /> },
      { href: "/capacity", label: "Capacity", icon: <Gauge {...ICON} /> },
    ],
  },
  {
    label: "operate",
    items: [
      { href: "/swarm", label: "Swarm", icon: <NetworkIcon {...ICON} /> },
      { href: "/rewards", label: "Rewards", icon: <Coins {...ICON} /> },
    ],
  },
  {
    label: "ghost pay",
    items: [
      { href: "/ghost-pay", label: "Overview", icon: <Crown {...ICON} /> },
      { href: "/locks", label: "Locks", icon: <Lock {...ICON} /> },
      { href: "/wraith", label: "Wraith", icon: <Shield {...ICON} /> },
    ],
  },
  {
    label: "privacy",
    items: [
      { href: "/network", label: "Network", icon: <Globe {...ICON} /> },
      { href: "/shroud", label: "Shroud", icon: <Eye {...ICON} /> },
      { href: "/haze", label: "Haze", icon: <Cloud {...ICON} /> },
    ],
  },
  {
    label: "identity",
    items: [
      { href: "/elders", label: "Elders & MPC", icon: <Users {...ICON} /> },
    ],
  },
  {
    label: "treasury",
    items: [
      { href: "/payouts", label: "Payouts", icon: <Banknote {...ICON} /> },
      { href: "/treasury", label: "Treasury", icon: <CreditCard {...ICON} /> },
    ],
  },
  {
    label: "system",
    items: [
      { href: "/system", label: "System", icon: <Cpu {...ICON} /> },
      { href: "/peers", label: "Peers", icon: <NetworkIcon {...ICON} /> },
      { href: "/storage", label: "Storage", icon: <HardDrive {...ICON} /> },
      { href: "/watchdog", label: "Watchdog", icon: <HeartPulse {...ICON} /> },
      { href: "/logs", label: "Logs", icon: <ScrollText {...ICON} /> },
      { href: "/settings", label: "Settings", icon: <Settings {...ICON} /> },
    ],
  },
];

function GroupLabel({ children, collapsed }: { children: string; collapsed: boolean }) {
  if (collapsed) return null;
  return (
    <div
      style={{
        padding: "16px 14px 6px",
        fontFamily: "var(--font-mono)",
        fontSize: "11px",
        fontWeight: 500,
        textTransform: "uppercase",
        letterSpacing: "0.18em",
        color: "var(--accent)",
      }}
    >
      {children}
    </div>
  );
}

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const mobileOpen = useUIStore((s) => s.sidebarMobileOpen);
  const toggle = useUIStore((s) => s.toggleSidebar);
  const setMobileOpen = useUIStore((s) => s.setSidebarMobileOpen);
  const nickname = useConfigStore((s) => s.nickname);
  const isConnected = useNodeStore((s) => s.isConnected);

  return (
    <>
      {/* Mobile hamburger button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="fixed top-3 left-3 z-40 md:hidden"
        aria-label="Open menu"
        style={{
          padding: "8px",
          border: "1px solid var(--rule)",
          background: "var(--bg)",
          color: "var(--dim)",
          borderRadius: "4px",
        }}
      >
        <Menu size={18} strokeWidth={1.75} />
      </button>

      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 md:hidden"
          onClick={() => setMobileOpen(false)}
          style={{ background: "rgba(0, 0, 0, 0.6)" }}
        />
      )}

      <aside
        className={`flex flex-col fixed md:relative inset-y-0 left-0 z-50 transition-all duration-200 ease-in-out ${
          mobileOpen ? "translate-x-0 w-64" : "-translate-x-full md:translate-x-0"
        } ${collapsed ? "md:w-16" : "md:w-60"}`}
        style={{
          borderRight: "1px solid var(--rule)",
          background: "var(--bg)",
        }}
      >
        {/* Brand + collapse toggle */}
        <div
          className="flex items-center justify-between px-4"
          style={{ height: "60px", borderBottom: "1px solid var(--rule)" }}
        >
          {!collapsed ? (
            <div className="flex flex-col min-w-0">
              <GhostBrand size="sm" />
              {nickname && (
                <span
                  style={{
                    color: "var(--fainter)",
                    fontSize: "11px",
                    fontFamily: "var(--font-mono)",
                    marginTop: "2px",
                  }}
                  className="truncate"
                >
                  {nickname}
                </span>
              )}
            </div>
          ) : (
            <button
              onClick={() => toggle()}
              title="Expand sidebar"
              aria-label="Expand sidebar"
              className="w-full flex justify-center"
              style={{
                padding: "4px",
                background: "transparent",
                border: "none",
                cursor: "pointer",
              }}
            >
              <GhostBrand size="sm" label="" />
            </button>
          )}
          {!collapsed && (
            <button
              onClick={() => {
                if (mobileOpen) setMobileOpen(false);
                else toggle();
              }}
              title={mobileOpen ? "Close menu" : "Collapse sidebar"}
              style={{
                padding: "4px",
                color: "var(--dim)",
                background: "transparent",
                border: "none",
                cursor: "pointer",
              }}
            >
              {mobileOpen ? <X size={16} strokeWidth={1.75} /> : <ChevronLeft size={16} strokeWidth={1.75} />}
            </button>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto" style={{ paddingBottom: "12px" }}>
          {GROUPS.map((group, idx) => (
            <div key={group.label}>
              {idx > 0 && !collapsed && (
                <div style={{ borderTop: "1px solid var(--rule)", margin: "6px 14px 0" }} />
              )}
              <GroupLabel collapsed={collapsed}>{group.label}</GroupLabel>
              <div>
                {group.items.map((item) => (
                  <SidebarItem
                    key={item.href}
                    href={item.href}
                    icon={item.icon}
                    label={item.label}
                    collapsed={collapsed}
                  />
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer: connection status + theme toggle */}
        <div
          className="flex items-center"
          style={{
            padding: "10px 14px",
            borderTop: "1px solid var(--rule)",
            justifyContent: collapsed ? "center" : "space-between",
          }}
        >
          {collapsed ? (
            <StatusDot status={isConnected ? "online" : "offline"} pulse={isConnected} size="sm" />
          ) : (
            <>
              <StatusDot
                status={isConnected ? "online" : "offline"}
                pulse={isConnected}
                label={isConnected ? "Connected" : "Disconnected"}
                size="sm"
              />
              <ThemeToggle />
            </>
          )}
        </div>
      </aside>
    </>
  );
}
