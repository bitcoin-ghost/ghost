import { ReactNode } from 'react';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ icon, title, description, action, className = '' }: EmptyStateProps) {
  return (
    <div className={`flex flex-col items-center justify-center py-12 px-4 text-center ${className}`}>
      {icon && (
        <div className="w-12 h-12 text-[color:var(--fainter)] mb-4">
          {icon}
        </div>
      )}
      <h3 className="text-sm font-medium text-[color:var(--dim)] mb-1">{title}</h3>
      {description && (
        <p className="text-sm text-[color:var(--fainter)] max-w-sm">{description}</p>
      )}
      {action && (
        <div className="mt-4">{action}</div>
      )}
    </div>
  );
}
