'use client';

import { CSSProperties, ReactNode, useCallback, useRef, useState } from 'react';
import { useUIStore } from '@/stores';

interface TooltipProps {
  content: string;
  children: ReactNode;
  position?: 'top' | 'bottom' | 'left' | 'right';
}

const positionClasses = {
  top: 'bottom-full left-1/2 mb-2',
  bottom: 'top-full left-1/2 mt-2',
  left: 'right-full top-1/2 mr-2',
  right: 'left-full top-1/2 ml-2',
};

const arrowClasses = {
  top: 'top-full left-1/2 border-t-gray-700 border-x-transparent border-b-transparent',
  bottom: 'bottom-full left-1/2 border-b-gray-700 border-x-transparent border-t-transparent',
  left: 'left-full top-1/2 border-l-gray-700 border-y-transparent border-r-transparent',
  right: 'right-full top-1/2 border-r-gray-700 border-y-transparent border-l-transparent',
};

// Gap kept between the tooltip box and the viewport edge.
const MARGIN = 8;

export function Tooltip({ content, children, position = 'top' }: TooltipProps) {
  const tooltipsEnabled = useUIStore((s) => s.tooltipsEnabled);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const [effective, setEffective] = useState(position);
  const [shift, setShift] = useState(0);

  // Measure on show and nudge the tooltip so it never leaves the viewport:
  // top/bottom clamp horizontally (and flip vertically if there is no room),
  // left/right clamp vertically (and flip horizontally). The arrow is
  // counter-shifted so it keeps pointing at the trigger.
  const reposition = useCallback(() => {
    const wrapper = wrapperRef.current;
    const tip = tipRef.current;
    if (!wrapper || !tip) return;

    const w = wrapper.getBoundingClientRect();
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    let pos = position;

    if (position === 'top' || position === 'bottom') {
      // Flip vertically if the preferred side has no room.
      if (position === 'top' && w.top - th - MARGIN < 0 && w.bottom + th + MARGIN <= vh) {
        pos = 'bottom';
      } else if (position === 'bottom' && w.bottom + th + MARGIN > vh && w.top - th - MARGIN >= 0) {
        pos = 'top';
      }
      // Horizontal clamp: tooltip is centred on the trigger.
      const centerX = w.left + w.width / 2;
      const left = centerX - tw / 2;
      const right = centerX + tw / 2;
      let s = 0;
      if (left < MARGIN) s = MARGIN - left;
      else if (right > vw - MARGIN) s = vw - MARGIN - right;
      setShift(s);
    } else {
      // Flip horizontally if the preferred side has no room.
      if (position === 'left' && w.left - tw - MARGIN < 0 && w.right + tw + MARGIN <= vw) {
        pos = 'right';
      } else if (position === 'right' && w.right + tw + MARGIN > vw && w.left - tw - MARGIN >= 0) {
        pos = 'left';
      }
      // Vertical clamp: tooltip is centred on the trigger.
      const centerY = w.top + w.height / 2;
      const top = centerY - th / 2;
      const bottom = centerY + th / 2;
      let s = 0;
      if (top < MARGIN) s = MARGIN - top;
      else if (bottom > vh - MARGIN) s = vh - MARGIN - bottom;
      setShift(s);
    }

    setEffective(pos);
  }, [position]);

  if (!tooltipsEnabled) {
    return <>{children}</>;
  }

  const horizontal = effective === 'top' || effective === 'bottom';
  const boxStyle: CSSProperties = horizontal
    ? { transform: `translateX(calc(-50% + ${shift}px))` }
    : { transform: `translateY(calc(-50% + ${shift}px))` };
  const arrowStyle: CSSProperties = horizontal
    ? { transform: `translateX(calc(-50% - ${shift}px))` }
    : { transform: `translateY(calc(-50% - ${shift}px))` };

  return (
    <div
      ref={wrapperRef}
      className="relative group/tooltip"
      onMouseEnter={reposition}
      onFocusCapture={reposition}
    >
      {children}
      <div
        ref={tipRef}
        style={boxStyle}
        className={`
          absolute z-50 pointer-events-none
          opacity-0 group-hover/tooltip:opacity-100
          transition-opacity duration-150
          ${positionClasses[effective]}
        `}
      >
        <div className="bg-gray-800 border border-gray-700 text-gray-200 text-xs rounded-lg px-3 py-2 w-72 max-w-[calc(100vw-1rem)] shadow-lg whitespace-normal">
          {content}
        </div>
        <div className={`absolute w-0 h-0 border-4 ${arrowClasses[effective]}`} style={arrowStyle} />
      </div>
    </div>
  );
}
