'use client';

import React from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { UseWizardReturn } from '@/hooks/useWizard';

interface StepIndicatorProps {
  steps: { id: string; title: string }[];
  currentStep: number;
}

export function StepIndicator({ steps, currentStep }: StepIndicatorProps) {
  return (
    <div className="flex items-start justify-between w-full px-2">
      {steps.map((step, index) => {
        const isCompleted = index < currentStep;
        const isActive = index === currentStep;
        const isPending = index > currentStep;

        return (
          <React.Fragment key={step.id}>
            <div className="flex flex-col items-center min-w-0">
              {/* Dot */}
              <div className="relative flex items-center justify-center">
                {isActive && (
                  <span className="absolute inline-flex h-8 w-8 rounded-full bg-[var(--accent)]/20 animate-ping" />
                )}
                <div
                  className={`
                    relative z-10 flex items-center justify-center w-8 h-8 rounded-full text-sm font-semibold
                    transition-colors duration-200
                    ${isCompleted ? 'bg-[var(--accent)] text-white' : ''}
                    ${isActive ? 'border-2 border-[color:var(--accent)] text-[color:var(--accent)] bg-[var(--surface)]' : ''}
                    ${isPending ? 'bg-[var(--rule-strong)] text-[color:var(--dim)]' : ''}
                  `}
                >
                  {isCompleted ? (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    index + 1
                  )}
                </div>
              </div>
              {/* Title (hidden on small screens) */}
              <span
                className={`
                  hidden md:block mt-2 text-xs text-center truncate max-w-[80px]
                  ${isCompleted ? 'text-[color:var(--accent)]' : ''}
                  ${isActive ? 'text-[color:var(--accent)] font-medium' : ''}
                  ${isPending ? 'text-[color:var(--fainter)]' : ''}
                `}
              >
                {step.title}
              </span>
            </div>

            {/* Connector line */}
            {index < steps.length - 1 && (
              <div className="flex-1 flex items-center pt-4">
                <div
                  className={`
                    h-0.5 w-full transition-colors duration-200
                    ${index < currentStep ? 'bg-[var(--accent)]' : 'bg-[var(--rule-strong)]'}
                  `}
                />
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

interface WizardDialogProps<TData> {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  wizard: UseWizardReturn<TData>;
  children: (data: TData, setData: (patch: Partial<TData>) => void) => React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

export function WizardDialog<TData>({
  isOpen,
  onClose,
  title,
  wizard,
  children,
  size = 'lg',
}: WizardDialogProps<TData>) {
  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      description={wizard.step.description}
      size={size}
      footer={
        <>
          <Button
            variant="ghost"
            onClick={wizard.back}
            disabled={wizard.isFirst || wizard.isSubmitting}
          >
            Back
          </Button>
          <Button
            variant="primary"
            onClick={wizard.next}
            loading={wizard.isSubmitting}
          >
            {wizard.isLast ? 'Finish' : 'Next'}
          </Button>
        </>
      }
    >
      {/* Step Indicator */}
      <div className="mb-6 -mt-1">
        <StepIndicator
          steps={wizard.steps}
          currentStep={wizard.currentStep}
        />
      </div>

      {/* Error Banner */}
      {wizard.error && (
        <div className="mb-4 px-4 py-3 rounded-lg bg-[color-mix(in_srgb,var(--red)_20%,var(--surface))] border border-[color-mix(in_srgb,var(--red)_40%,transparent)] text-[color:var(--red)] text-sm">
          {wizard.error}
        </div>
      )}

      {/* Step Content */}
      <div className="min-h-[200px]">
        {children(wizard.data, wizard.setData)}
      </div>
    </Dialog>
  );
}
