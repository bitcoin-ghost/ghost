import { ReactNode } from 'react';

interface PageHeaderProps {
  /** Short uppercase mono label rendered above the title (website's .section-label).
   *  Optional — pages can omit if the title alone reads cleanly. */
  eyebrow?: string;
  title: string;
  subtitle?: string;
  /** Subtitles span the full container width by default. Pass `false` for the
   *  narrow 60ch reading measure on the rare page that wants it. */
  subtitleFullWidth?: boolean;
  actions?: ReactNode;
  className?: string;
}

/**
 * Page header matching the public website's `.section-label` + `.section-title`
 * rhythm: an orange uppercase mono "eyebrow" line above a large light-weight
 * title. Subtitle stays as supporting prose.
 */
export function PageHeader({ eyebrow, title, subtitle, subtitleFullWidth = true, actions, className = '' }: PageHeaderProps) {
  return (
    <div className={`flex items-start justify-between gap-4 mb-8 ${className}`}>
      <div className="flex-1 min-w-0">
        {eyebrow && (
          <div className="t-eyebrow mb-2" style={{ color: 'var(--accent)' }}>
            {eyebrow}
          </div>
        )}
        <h1 className="t-display" style={{ color: 'var(--fg)' }}>
          {title}
        </h1>
        {subtitle && (
          <p
            className="t-lead mt-2"
            style={{ color: 'var(--dim)', maxWidth: subtitleFullWidth ? 'none' : '60ch' }}
          >
            {subtitle}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
    </div>
  );
}
