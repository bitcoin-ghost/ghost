'use client';

import { ReactNode } from 'react';
import { Skeleton } from './Skeleton';
import { Tooltip } from './Tooltip';

interface StatCardProps {
  label: string;
  value: string | number;
  tooltip?: string;
  icon?: ReactNode;
  sublabel?: string;
  loading?: boolean;
  className?: string;
}

export function StatCard({ label, value, tooltip, icon, sublabel, loading, className = '' }: StatCardProps) {
  if (loading) {
    return (
      <div className={`bg-[var(--surface)] border border-[color:var(--rule)] rounded-lg p-4 h-[104px] ${className}`}>
        <Skeleton className="h-4 w-20 mb-3" />
        <Skeleton className="h-7 w-24 mb-1" />
        <Skeleton className="h-3 w-16" />
      </div>
    );
  }

  const content = (
    <div className={`bg-[var(--surface)] border border-[color:var(--rule)] rounded-lg p-4 h-[104px] flex flex-col justify-between ${className}`}>
      <div className="flex items-center gap-1.5 text-sm text-[color:var(--dim)]">
        {tooltip && (
          <svg className="w-3 h-3 text-[color:var(--fainter)] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <circle cx="12" cy="12" r="10" />
            <path d="M12 16v-4M12 8h.01" />
          </svg>
        )}
        {icon && <span className="w-4 h-4 flex-shrink-0">{icon}</span>}
        <span className="truncate">{label}</span>
      </div>
      <div>
        <div className="text-2xl font-bold text-[color:var(--fg)] truncate">{value}</div>
        {sublabel && <div className="text-xs text-[color:var(--fainter)] truncate">{sublabel}</div>}
      </div>
    </div>
  );

  if (tooltip) {
    return <Tooltip content={tooltip}>{content}</Tooltip>;
  }

  return content;
}
