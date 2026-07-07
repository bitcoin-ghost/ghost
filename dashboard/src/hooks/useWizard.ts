'use client';

import { useState, useCallback } from 'react';

export interface WizardStep<TData> {
  id: string;
  title: string;
  description?: string;
  validate?: (data: TData) => string | null;
  onSubmit?: (data: TData) => Promise<void>;
}

export interface UseWizardConfig<TData> {
  steps: WizardStep<TData>[];
  initialData: TData;
  onComplete?: (data: TData) => void;
}

export interface UseWizardReturn<TData> {
  currentStep: number;
  step: WizardStep<TData>;
  steps: WizardStep<TData>[];
  totalSteps: number;
  data: TData;
  setData: (patch: Partial<TData>) => void;
  error: string | null;
  isSubmitting: boolean;
  next: () => Promise<void>;
  back: () => void;
  reset: (overrideData?: TData) => void;
  isFirst: boolean;
  isLast: boolean;
  isComplete: boolean;
}

export function useWizard<TData>(config: UseWizardConfig<TData>): UseWizardReturn<TData> {
  const { steps, initialData, onComplete } = config;

  const [currentStep, setCurrentStep] = useState(0);
  const [data, setDataState] = useState<TData>(initialData);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isComplete, setIsComplete] = useState(false);

  const step = steps[currentStep];
  const totalSteps = steps.length;
  const isFirst = currentStep === 0;
  const isLast = currentStep === totalSteps - 1;

  const setData = useCallback((patch: Partial<TData>) => {
    setDataState((prev) => ({ ...prev, ...patch }));
    setError(null);
  }, []);

  const next = useCallback(async () => {
    const currentStepDef = steps[currentStep];

    // Validate current step
    if (currentStepDef.validate) {
      const validationError = currentStepDef.validate(data);
      if (validationError) {
        setError(validationError);
        return;
      }
    }

    // Run onSubmit if present
    if (currentStepDef.onSubmit) {
      setIsSubmitting(true);
      setError(null);
      try {
        await currentStepDef.onSubmit(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        setIsSubmitting(false);
        return;
      }
      setIsSubmitting(false);
    }

    // Advance or complete
    if (currentStep < totalSteps - 1) {
      setCurrentStep((prev) => prev + 1);
      setError(null);
    } else {
      setIsComplete(true);
      onComplete?.(data);
    }
  }, [currentStep, data, steps, totalSteps, onComplete]);

  const back = useCallback(() => {
    setCurrentStep((prev) => Math.max(0, prev - 1));
    setError(null);
  }, []);

  // Reset the wizard to its first step. Pass `overrideData` to seed it with a
  // freshly-resolved value (e.g. once an async config query lands) instead of
  // the `initialData` captured at mount — this is what lets a re-opened wizard
  // reflect live node state rather than a stale default.
  const reset = useCallback((overrideData?: TData) => {
    setCurrentStep(0);
    setDataState(overrideData ?? initialData);
    setError(null);
    setIsSubmitting(false);
    setIsComplete(false);
  }, [initialData]);

  return {
    currentStep,
    step,
    steps,
    totalSteps,
    data,
    setData,
    error,
    isSubmitting,
    next,
    back,
    reset,
    isFirst,
    isLast,
    isComplete,
  };
}
