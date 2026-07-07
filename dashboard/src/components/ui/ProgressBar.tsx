interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  sublabel?: string;
  color?: 'orange' | 'green' | 'blue' | 'red' | 'yellow' | 'gray';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const colorClasses = {
  orange: 'bg-[var(--accent)]',
  green: 'bg-[var(--green)]',
  blue: 'bg-[var(--blue)]',
  red: 'bg-[var(--red)]',
  yellow: 'bg-[var(--accent)]',
  gray: 'bg-[var(--fainter)]',
};

const sizeClasses = {
  sm: 'h-1.5',
  md: 'h-2.5',
  lg: 'h-4',
};

export function ProgressBar({
  value,
  max = 100,
  label,
  sublabel,
  color = 'orange',
  size = 'md',
  className = '',
}: ProgressBarProps) {
  const percent = max > 0 ? Math.min((value / max) * 100, 100) : 0;

  return (
    <div className={className}>
      {(label || sublabel) && (
        <div className="flex justify-between items-center mb-1.5">
          {label && <span className="text-sm text-[color:var(--dim)]">{label}</span>}
          {sublabel && <span className="text-sm text-[color:var(--dim)] font-mono">{sublabel}</span>}
        </div>
      )}
      <div className={`bg-[var(--surface)] rounded-full overflow-hidden ${sizeClasses[size]}`}>
        <div
          className={`${colorClasses[color]} rounded-full transition-all duration-500 h-full`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
