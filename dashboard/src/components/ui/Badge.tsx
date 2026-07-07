import { ReactNode } from "react";

type BadgeVariant = "success" | "warning" | "error" | "info" | "default";

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const variants: Record<BadgeVariant, string> = {
  success: "bg-[color-mix(in_srgb,var(--green)_16%,transparent)] text-[color:var(--green)] border-[color-mix(in_srgb,var(--green)_40%,transparent)]",
  warning: "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] text-[color:var(--accent)] border-[color-mix(in_srgb,var(--accent)_40%,transparent)]",
  error: "bg-[color-mix(in_srgb,var(--red)_16%,transparent)] text-[color:var(--red)] border-[color-mix(in_srgb,var(--red)_40%,transparent)]",
  info: "bg-[color-mix(in_srgb,var(--blue)_16%,transparent)] text-[color:var(--blue)] border-[color-mix(in_srgb,var(--blue)_40%,transparent)]",
  default: "bg-[var(--surface)] text-[color:var(--dim)] border-[color:var(--rule-strong)]",
};

export function Badge({ children, variant = "default", className = "" }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${variants[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
