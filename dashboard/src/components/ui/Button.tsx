'use client';

import { forwardRef, ButtonHTMLAttributes } from 'react';

type ButtonVariant = 'default' | 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'success' | 'warning';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

const variantClasses: Record<ButtonVariant, string> = {
  default: 'bg-[var(--rule-strong)] text-[color:var(--fg)] hover:bg-[var(--rule-strong)] border-[color:var(--rule-strong)]',
  primary: 'bg-[var(--accent)] text-[color:var(--fg)] hover:bg-[var(--accent)] border-[color:var(--accent)]',
  secondary: 'bg-[var(--accent)] text-[color:var(--fg)] hover:bg-[var(--accent)] border-[color:var(--accent)]',
  outline: 'bg-transparent text-[color:var(--dim)] hover:bg-[var(--surface)] border-[color:var(--rule-strong)]',
  ghost: 'bg-transparent text-[color:var(--dim)] hover:bg-[var(--surface)] border-transparent',
  danger: 'bg-[var(--red)] text-[color:var(--fg)] hover:bg-[var(--red)] border-[color:var(--red)]',
  success: 'bg-[var(--green)] text-[color:var(--fg)] hover:bg-[var(--green)] border-[color:var(--green)]',
  warning: 'bg-[var(--accent)] text-[color:var(--fg)] hover:bg-[var(--accent)] border-[color:var(--accent)]',
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'px-2 py-1 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'default', size = 'md', loading = false, disabled, className = '', children, ...props }, ref) => {
    const isDisabled = disabled || loading;

    return (
      <button
        ref={ref}
        disabled={isDisabled}
        className={`
          inline-flex items-center justify-center font-medium rounded-lg border transition-colors
          focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[color:var(--surface)] focus:ring-orange-500
          disabled:opacity-50 disabled:cursor-not-allowed
          ${variantClasses[variant]}
          ${sizeClasses[size]}
          ${className}
        `.trim()}
        {...props}
      >
        {loading && (
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        {children}
      </button>
    );
  }
);

Button.displayName = 'Button';
