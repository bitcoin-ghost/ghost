'use client';

import { ReactNode, useState, Children } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
}

export function Card({ children, className = '', collapsible, defaultCollapsed = false }: CardProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  if (!collapsible) {
    return (
      <div
        className={`p-6 ${className}`}
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--rule)',
          borderRadius: '4px',
        }}
      >
        {children}
      </div>
    );
  }

  // Split children: first child is the header (always visible), rest is body (toggled)
  const childArray = Children.toArray(children);
  const header = childArray[0];
  const body = childArray.slice(1);

  return (
    <div className={`bg-[var(--surface)] border border-[color:var(--rule)] rounded-lg p-6 ${className}`}>
      <div
        className="cursor-pointer select-none"
        onClick={() => setCollapsed(!collapsed)}
      >
        <div className="flex items-center justify-between">
          <div className="flex-1">{header}</div>
          <svg
            className={`w-5 h-5 text-[color:var(--dim)] transition-transform flex-shrink-0 ml-2 ${collapsed ? '' : 'rotate-180'}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>
      {!collapsed && <div className="mt-4">{body}</div>}
    </div>
  );
}

interface CardHeaderProps {
  title: ReactNode;
  subtitle?: string;
  action?: ReactNode;
}

export function CardHeader({ title, subtitle, action }: CardHeaderProps) {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <h3
          className="font-medium"
          style={{ color: 'var(--fg)', fontSize: '16px' }}
        >
          {title}
        </h3>
        {subtitle && (
          <p style={{ color: 'var(--dim)', fontSize: '13px', marginTop: '2px' }}>
            {subtitle}
          </p>
        )}
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}
