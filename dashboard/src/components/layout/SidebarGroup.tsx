'use client';

import { useState, ReactNode } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';

interface SidebarGroupItem {
  href: string;
  label: string;
}

interface SidebarGroupProps {
  icon: ReactNode;
  label: string;
  items: SidebarGroupItem[];
  collapsed?: boolean;
}

// Check if a path is active - exact match only for submenu items
function isPathActive(pathname: string, href: string): boolean {
  return pathname === href;
}

export function SidebarGroup({ icon, label, items, collapsed = false }: SidebarGroupProps) {
  const pathname = usePathname();
  const isAnyActive = items.some(item => isPathActive(pathname, item.href));
  const [isOpen, setIsOpen] = useState(isAnyActive);

  if (collapsed) {
    // When collapsed, show just the icon with a dropdown on hover
    return (
      <div className="relative group">
        <button
          className={`
            flex items-center justify-center w-full px-3 py-2 rounded-lg transition-colors
            ${isAnyActive
              ? 'bg-[var(--accent)]/20 text-[color:var(--accent)]'
              : 'text-[color:var(--dim)] hover:text-[color:var(--fg)] hover:bg-[var(--surface)]/50'
            }
          `}
        >
          <span className="w-5 h-5">{icon}</span>
        </button>

        {/* Flyout menu on hover */}
        <div className="absolute left-full top-0 ml-2 hidden group-hover:block z-50">
          <div className="bg-[var(--surface)] border border-[color:var(--rule-strong)] rounded-lg shadow-xl py-1 min-w-40">
            <div className="px-3 py-2 text-xs font-semibold text-[color:var(--fainter)] uppercase">
              {label}
            </div>
            {items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`
                  block px-3 py-2 text-sm transition-colors
                  ${isPathActive(pathname, item.href)
                    ? 'text-[color:var(--accent)] bg-[var(--accent)]/10'
                    : 'text-[color:var(--dim)] hover:text-[color:var(--fg)] hover:bg-[var(--surface)]'
                  }
                `}
              >
                {item.label}
              </Link>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`
          flex items-center justify-between w-full px-3 py-2 rounded-lg transition-colors
          ${isAnyActive
            ? 'bg-[var(--accent)]/20 text-[color:var(--accent)]'
            : 'text-[color:var(--dim)] hover:text-[color:var(--fg)] hover:bg-[var(--surface)]/50'
          }
        `}
      >
        <div className="flex items-center gap-3">
          <span className="w-5 h-5">{icon}</span>
          <span className="text-sm font-medium">{label}</span>
        </div>
        <svg
          className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isOpen && (
        <div className="mt-1 ml-4 pl-4 border-l border-[color:var(--rule)] space-y-1">
          {items.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`
                block px-3 py-2 text-sm rounded-lg transition-colors
                ${isPathActive(pathname, item.href)
                  ? 'text-[color:var(--accent)] bg-[var(--accent)]/10'
                  : 'text-[color:var(--dim)] hover:text-[color:var(--fg)] hover:bg-[var(--surface)]/50'
                }
              `}
            >
              {item.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
