'use client';

import { ReactNode, useCallback, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useUIStore } from '@/stores';

interface TooltipProps {
  content: string;
  children: ReactNode;
  position?: 'top' | 'bottom' | 'left' | 'right';
}

type Side = 'top' | 'bottom' | 'left' | 'right';

// Gap kept between the tooltip box and the viewport edge.
const MARGIN = 8;
// Gap between the trigger and the tooltip box (leaves room for the arrow).
const GAP = 8;
// Half-width of the 4px CSS-border arrow, used to keep it clear of the corners.
const ARROW = 4;

const arrowClasses: Record<Side, string> = {
  top: 'border-t-gray-700 border-x-transparent border-b-transparent',
  bottom: 'border-b-gray-700 border-x-transparent border-t-transparent',
  left: 'border-l-gray-700 border-y-transparent border-r-transparent',
  right: 'border-r-gray-700 border-y-transparent border-l-transparent',
};

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(v, hi));
}

// The tooltip box is rendered through a portal to document.body with fixed
// positioning. This is deliberate: the dashboard's <main> wrapper is
// `overflow-auto`, so an absolutely-positioned tooltip inside a card gets
// clipped at main's left edge (which abuts the sidebar) whenever the card sits
// near that edge. Portalling out of the scroll container and positioning against
// the viewport means the tooltip is never clipped and always paints above the
// sidebar. Placement is applied imperatively (DOM refs) in a layout effect so it
// is measured-then-positioned before paint, with no intermediate flash.
export function Tooltip({ content, children, position = 'top' }: TooltipProps) {
  const tooltipsEnabled = useUIStore((s) => s.tooltipsEnabled);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const arrowRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  // Measure the trigger and the tooltip, pick the side (flipping if the
  // preferred side has no room), clamp the box to the viewport, and offset the
  // arrow so it keeps pointing at the trigger centre.
  const reposition = useCallback(() => {
    const wrapper = wrapperRef.current;
    const tip = tipRef.current;
    const arrow = arrowRef.current;
    if (!wrapper || !tip || !arrow) return;

    const w = wrapper.getBoundingClientRect();
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const off = GAP + ARROW;

    let side: Side = position;
    if (position === 'top' || position === 'bottom') {
      if (position === 'top' && w.top - th - off < MARGIN && w.bottom + th + off + MARGIN <= vh) side = 'bottom';
      else if (position === 'bottom' && w.bottom + th + off + MARGIN > vh && w.top - th - off >= MARGIN) side = 'top';
    } else {
      if (position === 'left' && w.left - tw - off < MARGIN && w.right + tw + off + MARGIN <= vw) side = 'right';
      else if (position === 'right' && w.right + tw + off + MARGIN > vw && w.left - tw - off >= MARGIN) side = 'left';
    }

    const centerX = w.left + w.width / 2;
    const centerY = w.top + w.height / 2;
    let left: number;
    let top: number;
    let arrowOffset: number;

    if (side === 'top' || side === 'bottom') {
      left = clamp(centerX - tw / 2, MARGIN, vw - tw - MARGIN);
      top = side === 'top' ? w.top - th - off : w.bottom + off;
      arrowOffset = clamp(centerX - left, ARROW + 4, tw - ARROW - 4);
    } else {
      top = clamp(centerY - th / 2, MARGIN, vh - th - MARGIN);
      left = side === 'left' ? w.left - tw - off : w.right + off;
      arrowOffset = clamp(centerY - top, ARROW + 4, th - ARROW - 4);
    }

    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
    tip.style.opacity = '1';

    arrow.className = `absolute w-0 h-0 border-4 ${arrowClasses[side]}`;
    arrow.style.left = '';
    arrow.style.right = '';
    arrow.style.top = '';
    arrow.style.bottom = '';
    if (side === 'top' || side === 'bottom') {
      arrow.style.left = `${arrowOffset}px`;
      arrow.style.transform = 'translateX(-50%)';
      arrow.style[side === 'top' ? 'top' : 'bottom'] = '100%';
    } else {
      arrow.style.top = `${arrowOffset}px`;
      arrow.style.transform = 'translateY(-50%)';
      arrow.style[side === 'left' ? 'left' : 'right'] = '100%';
    }
  }, [position]);

  // Position on open, and keep it anchored while the page scrolls or resizes.
  useLayoutEffect(() => {
    if (!open) return;
    reposition();
    window.addEventListener('scroll', reposition, true);
    window.addEventListener('resize', reposition);
    return () => {
      window.removeEventListener('scroll', reposition, true);
      window.removeEventListener('resize', reposition);
    };
  }, [open, reposition]);

  if (!tooltipsEnabled) {
    return <>{children}</>;
  }

  return (
    <div
      ref={wrapperRef}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocusCapture={() => setOpen(true)}
      onBlurCapture={() => setOpen(false)}
    >
      {children}
      {open && typeof document !== 'undefined' &&
        createPortal(
          <div
            ref={tipRef}
            style={{ left: 0, top: 0, opacity: 0 }}
            className="fixed z-[9999] pointer-events-none transition-opacity duration-150"
          >
            <div className="relative bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded-lg px-3 py-2 w-72 max-w-[calc(100vw-1rem)] shadow-lg whitespace-normal">
              {content}
              <div ref={arrowRef} className={`absolute w-0 h-0 border-4 ${arrowClasses[position]}`} />
            </div>
          </div>,
          document.body,
        )}
    </div>
  );
}
