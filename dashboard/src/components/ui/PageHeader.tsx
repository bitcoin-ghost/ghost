import { ReactNode } from 'react';

interface PageHeaderProps {
  /** Short uppercase mono label rendered above the title (website's .section-label).
   *  Optional — pages can omit if the title alone reads cleanly. */
  eyebrow?: string;
  title: string;
  subtitle?: string;
  /** Let the subtitle span the full container width instead of the 60ch reading measure. */
  subtitleFullWidth?: boolean;
  actions?: ReactNode;
  className?: string;
}

/**
 * Page header matching the public website's `.section-label` + `.section-title`
 * rhythm: an orange uppercase mono "eyebrow" line above a large light-weight
 * title. Subtitle stays as supporting prose.
 */
export function PageHeader({ eyebrow, title, subtitle, subtitleFullWidth = false, actions, className = '' }: PageHeaderProps) {
  return (
    <div className={`flex items-start justify-between gap-4 mb-8 ${className}`}>
      <div className="flex-1 min-w-0">
        {eyebrow && (
          <div
            className="font-mono uppercase mb-2"
            style={{
              color: 'var(--accent)',
              fontSize: '11px',
              letterSpacing: '0.18em',
            }}
          >
            {eyebrow}
          </div>
        )}
        <h1
          className="font-normal"
          style={{
            color: 'var(--fg)',
            fontSize: '32px',
            lineHeight: '1.15',
            letterSpacing: '-0.01em',
          }}
        >
          {title}
        </h1>
        {subtitle && (
          <p
            className="mt-2"
            style={{ color: 'var(--dim)', fontSize: '15px', maxWidth: subtitleFullWidth ? 'none' : '60ch' }}
          >
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </div>
  );
}
