interface StatusDotProps {
  status: 'online' | 'warning' | 'offline' | 'unknown';
  pulse?: boolean;
  size?: 'sm' | 'md' | 'lg';
  label?: string;
  className?: string;
}

const colorClasses = {
  online: 'bg-[var(--green)]',
  warning: 'bg-[var(--accent)]',
  offline: 'bg-[var(--red)]',
  unknown: 'bg-[var(--fainter)]',
};

const sizeClasses = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-3 h-3',
};

export function StatusDot({ status, pulse, size = 'md', label, className = '' }: StatusDotProps) {
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <span className="relative flex-shrink-0">
        <span className={`block rounded-full ${colorClasses[status]} ${sizeClasses[size]}`} />
        {pulse && (
          <span className={`absolute inset-0 rounded-full ${colorClasses[status]} animate-ping opacity-75`} />
        )}
      </span>
      {label && <span className="text-sm text-[color:var(--dim)]">{label}</span>}
    </span>
  );
}
