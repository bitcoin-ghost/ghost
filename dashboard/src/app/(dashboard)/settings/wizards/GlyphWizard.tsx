'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { GLYPH_PALETTE, computeBitmapHash, checkGlyphAvailability } from '@/lib/api/glyph';
import { useClaimGlyph, useGhostId } from '@/hooks/queries';

const GRID_SIZE = 16;
const CELL_SIZE = 20;
const PREVIEW_SIZE = 128;
const PREVIEW_CELL = PREVIEW_SIZE / GRID_SIZE; // 8

function paletteToHex(r: number, g: number, b: number): string {
  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
}

interface GlyphData {
  ghost_id: string;
}

interface GlyphWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function GlyphWizard({ isOpen, onClose }: GlyphWizardProps) {
  const toast = useToast();
  const claimMutation = useClaimGlyph();
  const ghostIdQuery = useGhostId({ enabled: isOpen });

  // Canvas / palette state lives in the wizard (not in wizard data) because
  // the 256-entry pixel array is large and only the claim step needs it.
  const [pixels, setPixels] = useState<number[]>(() => new Array(256).fill(0));
  const [selectedColor, setSelectedColor] = useState(1);
  const [painting, setPainting] = useState(false);
  const [availability, setAvailability] = useState<{ checked: boolean; available: boolean; hash: string } | null>(null);
  const [checking, setChecking] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Reset transient editor state whenever the wizard is (re)opened.
  useEffect(() => {
    if (isOpen) {
      setPixels(new Array(256).fill(0));
      setSelectedColor(1);
      setAvailability(null);
      setChecking(false);
    }
  }, [isOpen]);

  // Painting an empty design conveys nothing; the check/claim steps require
  // at least one non-background pixel.
  const isBlank = pixels.every((p) => p === 0);

  const renderPreview = useCallback((px: number[]) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    ctx.clearRect(0, 0, PREVIEW_SIZE, PREVIEW_SIZE);
    for (let i = 0; i < 256; i++) {
      const colorIdx = px[i] ?? 0;
      const color = GLYPH_PALETTE[colorIdx] ?? GLYPH_PALETTE[0];
      ctx.fillStyle = paletteToHex(color.r, color.g, color.b);
      const x = (i % GRID_SIZE) * PREVIEW_CELL;
      const y = Math.floor(i / GRID_SIZE) * PREVIEW_CELL;
      ctx.fillRect(x, y, PREVIEW_CELL, PREVIEW_CELL);
    }
  }, []);

  useEffect(() => {
    renderPreview(pixels);
  }, [pixels, renderPreview]);

  const paintCell = useCallback((index: number) => {
    setPixels((prev) => {
      if (prev[index] === selectedColor) return prev;
      const next = [...prev];
      next[index] = selectedColor;
      return next;
    });
    // Any edit invalidates a prior availability check.
    setAvailability(null);
  }, [selectedColor]);

  const handleMouseDown = useCallback((index: number) => {
    setPainting(true);
    paintCell(index);
  }, [paintCell]);

  const handleMouseEnter = useCallback((index: number) => {
    if (painting) paintCell(index);
  }, [painting, paintCell]);

  const handleMouseUp = useCallback(() => {
    setPainting(false);
  }, []);

  const handleClear = useCallback(() => {
    setPixels(new Array(256).fill(0));
    setAvailability(null);
  }, []);

  const runAvailabilityCheck = useCallback(async () => {
    setChecking(true);
    try {
      const hash = await computeBitmapHash(pixels);
      const result = await checkGlyphAvailability(hash);
      setAvailability({ checked: true, available: result.available, hash });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Availability check failed';
      toast.error('Check Failed', message);
      setAvailability(null);
    } finally {
      setChecking(false);
    }
  }, [pixels, toast]);

  const steps: WizardStep<GlyphData>[] = [
    {
      id: 'intro',
      title: 'About',
      description: 'What is a Ghost Glyph?',
    },
    {
      id: 'design',
      title: 'Design',
      description: 'Draw your 16x16 glyph',
      validate: () => {
        if (isBlank) {
          return 'Paint at least one pixel before continuing';
        }
        return null;
      },
    },
    {
      id: 'availability',
      title: 'Availability',
      description: 'Confirm the design is unclaimed',
      validate: () => {
        if (!availability?.checked) {
          return 'Check availability before continuing';
        }
        if (!availability.available) {
          return 'This design is already claimed — edit it and re-check';
        }
        return null;
      },
    },
    {
      id: 'claim',
      title: 'Claim',
      description: 'Bind this glyph to your Ghost ID',
      validate: (data) => {
        if (!data.ghost_id.trim()) {
          return 'A Ghost ID is required to claim';
        }
        return null;
      },
      onSubmit: async (data) => {
        try {
          const result = await claimMutation.mutateAsync({
            ghostId: data.ghost_id.trim(),
            pixels,
          });
          toast.success(
            'Glyph Claimed',
            `Bound to ${data.ghost_id.trim().slice(0, 14)}... — commitment ${result.commitment.slice(0, 16)}...`
          );
          onClose();
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to claim glyph';
          toast.error('Claim Failed', message);
          throw err;
        }
      },
    },
  ];

  const wizard = useWizard<GlyphData>({
    steps,
    initialData: {
      ghost_id: '',
    },
  });

  // The canvas is remounted whenever the active step changes, so redraw it
  // after each step transition (the pixels-driven effect won't fire because
  // the pixel array is unchanged across the navigation).
  useEffect(() => {
    renderPreview(pixels);
  }, [wizard.currentStep, pixels, renderPreview]);

  // Prefill the Ghost ID from the node once it loads (only if untouched).
  useEffect(() => {
    if (isOpen && ghostIdQuery.data?.ghost_id && !wizard.data.ghost_id) {
      wizard.setData({ ghost_id: ghostIdQuery.data.ghost_id });
    }
  }, [isOpen, ghostIdQuery.data, wizard]);

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Claim a Ghost Glyph"
      wizard={wizard}
      size="xl"
    >
      {(data, setData) => (
        <div className="space-y-6" onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}>
          {/* Step 1: Intro */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50 space-y-3">
                <p className="text-sm text-gray-300">
                  A Ghost Glyph is a small 16x16 pixel image that becomes the visual
                  identity for your Ghost ID. Once claimed it is bound permanently to
                  your identity and cannot be transferred.
                </p>
                <ul className="text-sm text-gray-400 list-disc list-inside space-y-1">
                  <li>Design a unique bitmap from the Ghost palette.</li>
                  <li>Each design hashes to a unique fingerprint — duplicates are rejected.</li>
                  <li>Claiming binds the bitmap hash to your Ghost ID.</li>
                </ul>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Claiming a glyph is permanent. Take your time on the design step.
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Design */}
          {wizard.currentStep === 1 && (
            <div className="flex flex-col lg:flex-row gap-6">
              {/* Grid */}
              <div className="flex flex-col gap-3">
                <div
                  className="inline-grid border border-gray-700 select-none"
                  style={{
                    gridTemplateColumns: `repeat(${GRID_SIZE}, ${CELL_SIZE}px)`,
                    gridTemplateRows: `repeat(${GRID_SIZE}, ${CELL_SIZE}px)`,
                  }}
                >
                  {pixels.map((colorIdx, i) => {
                    const color = GLYPH_PALETTE[colorIdx] ?? GLYPH_PALETTE[0];
                    return (
                      <div
                        key={i}
                        className="border border-gray-800/50 cursor-crosshair hover:opacity-80"
                        style={{
                          backgroundColor: paletteToHex(color.r, color.g, color.b),
                          width: CELL_SIZE,
                          height: CELL_SIZE,
                        }}
                        onMouseDown={() => handleMouseDown(i)}
                        onMouseEnter={() => handleMouseEnter(i)}
                      />
                    );
                  })}
                </div>
                <button
                  type="button"
                  onClick={handleClear}
                  className="self-start px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition-colors"
                >
                  Clear
                </button>
              </div>

              {/* Palette + preview */}
              <div className="flex flex-col gap-4 flex-1">
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-2">Palette</h4>
                  <div className="flex flex-wrap gap-1">
                    {GLYPH_PALETTE.map((color) => (
                      <button
                        key={color.index}
                        type="button"
                        title={color.name}
                        className={`w-6 h-6 rounded-sm border-2 transition-all ${
                          selectedColor === color.index
                            ? 'border-white scale-110'
                            : 'border-gray-700 hover:border-gray-500'
                        }`}
                        style={{ backgroundColor: paletteToHex(color.r, color.g, color.b) }}
                        onClick={() => setSelectedColor(color.index)}
                      />
                    ))}
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Selected: {GLYPH_PALETTE[selectedColor]?.name ?? 'Unknown'}
                  </p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-gray-400 mb-2">Preview</h4>
                  <canvas
                    ref={canvasRef}
                    width={PREVIEW_SIZE}
                    height={PREVIEW_SIZE}
                    className="border border-gray-700 rounded bg-black"
                    style={{ imageRendering: 'pixelated' }}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Availability */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-start gap-6">
                  <canvas
                    ref={canvasRef}
                    width={PREVIEW_SIZE}
                    height={PREVIEW_SIZE}
                    className="border border-gray-700 rounded bg-black shrink-0"
                    style={{ imageRendering: 'pixelated' }}
                  />
                  <div className="space-y-3 flex-1">
                    <p className="text-sm text-gray-300">
                      Each glyph design must be unique. Check whether this bitmap has
                      already been claimed before proceeding.
                    </p>
                    <button
                      type="button"
                      onClick={runAvailabilityCheck}
                      disabled={checking}
                      className="px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded transition-colors disabled:opacity-50"
                    >
                      {checking ? 'Checking…' : 'Check Availability'}
                    </button>
                    {availability?.checked && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          {availability.available ? (
                            <Badge variant="success">Available</Badge>
                          ) : (
                            <Badge variant="error">Already claimed</Badge>
                          )}
                        </div>
                        <p className="text-xs text-gray-500 font-mono break-all">
                          {availability.hash.slice(0, 32)}…
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Claim */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-start gap-6">
                  <canvas
                    ref={canvasRef}
                    width={PREVIEW_SIZE}
                    height={PREVIEW_SIZE}
                    className="border border-gray-700 rounded bg-black shrink-0"
                    style={{ imageRendering: 'pixelated' }}
                  />
                  <div className="flex-1">
                    <Input
                      label="Ghost ID"
                      type="text"
                      value={data.ghost_id}
                      onChange={(e) => setData({ ghost_id: e.target.value })}
                      placeholder="ghost1..."
                    />
                    <p className="text-sm text-gray-400 mt-2">
                      The Ghost identity this glyph will be bound to. Prefilled from this
                      node when available.
                    </p>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to claim this glyph. The binding is permanent and cannot
                  be undone.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
