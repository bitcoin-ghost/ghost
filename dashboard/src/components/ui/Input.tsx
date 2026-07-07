'use client';

import { forwardRef, InputHTMLAttributes, TextareaHTMLAttributes } from 'react';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, helperText, className = '', ...props }, ref) => {
    return (
      <div className="space-y-1">
        {label && (
          <label className="block text-sm font-medium text-[color:var(--dim)]">
            {label}
          </label>
        )}
        <input
          ref={ref}
          className={`
            w-full px-3 py-2 text-sm
            bg-[var(--surface)] border rounded-lg
            text-[color:var(--fg)] placeholder-[color:var(--fainter)]
            focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent
            disabled:opacity-50 disabled:cursor-not-allowed
            ${error ? 'border-[color:var(--red)]' : 'border-[color:var(--rule-strong)]'}
            ${className}
          `.trim()}
          {...props}
        />
        {error && (
          <p className="text-xs text-[color:var(--red)]">{error}</p>
        )}
        {helperText && !error && (
          <p className="text-xs text-[color:var(--fainter)]">{helperText}</p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  helperText?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, error, helperText, className = '', ...props }, ref) => {
    return (
      <div className="space-y-1">
        {label && (
          <label className="block text-sm font-medium text-[color:var(--dim)]">
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          className={`
            w-full px-3 py-2 text-sm
            bg-[var(--surface)] border rounded-lg
            text-[color:var(--fg)] placeholder-[color:var(--fainter)]
            focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent
            disabled:opacity-50 disabled:cursor-not-allowed
            resize-none
            ${error ? 'border-[color:var(--red)]' : 'border-[color:var(--rule-strong)]'}
            ${className}
          `.trim()}
          {...props}
        />
        {error && (
          <p className="text-xs text-[color:var(--red)]">{error}</p>
        )}
        {helperText && !error && (
          <p className="text-xs text-[color:var(--fainter)]">{helperText}</p>
        )}
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';

interface SelectProps extends InputHTMLAttributes<HTMLSelectElement> {
  label?: string;
  error?: string;
  helperText?: string;
  options: Array<{ value: string; label: string }>;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, error, helperText, options, className = '', ...props }, ref) => {
    return (
      <div className="space-y-1">
        {label && (
          <label className="block text-sm font-medium text-[color:var(--dim)]">
            {label}
          </label>
        )}
        <select
          ref={ref}
          className={`
            w-full px-3 py-2 text-sm
            bg-[var(--surface)] border rounded-lg
            text-[color:var(--fg)]
            focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent
            disabled:opacity-50 disabled:cursor-not-allowed
            ${error ? 'border-[color:var(--red)]' : 'border-[color:var(--rule-strong)]'}
            ${className}
          `.trim()}
          {...(props as React.SelectHTMLAttributes<HTMLSelectElement>)}
        >
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        {error && (
          <p className="text-xs text-[color:var(--red)]">{error}</p>
        )}
        {helperText && !error && (
          <p className="text-xs text-[color:var(--fainter)]">{helperText}</p>
        )}
      </div>
    );
  }
);

Select.displayName = 'Select';
