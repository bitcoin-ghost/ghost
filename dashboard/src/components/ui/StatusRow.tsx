import { ReactNode } from 'react';
import { Tooltip } from './Tooltip';

interface StatusRowProps {
  label: string;
  tooltip?: string;
  children: ReactNode;
}

export function StatusRow({ label, tooltip, children }: StatusRowProps) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[color:var(--rule)] last:border-b-0">
      <div className="flex items-center gap-2">
        {tooltip ? (
          <Tooltip content={tooltip}>
            <span className="text-[color:var(--dim)] text-sm cursor-help">{label}</span>
          </Tooltip>
        ) : (
          <span className="text-[color:var(--dim)] text-sm">{label}</span>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}
