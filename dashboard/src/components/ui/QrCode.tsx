"use client";

import { useMemo } from "react";
import { encodeQr, qrToSvgPath, type Ecc } from "@/lib/qr";

interface QrCodeProps {
  /** The string to encode (URL, host:port, node id, …). */
  value: string;
  /** Rendered pixel size of the square. Defaults to 160. */
  size?: number;
  /** Error-correction level. MEDIUM balances density and scannability. */
  ecc?: Ecc;
  /** Quiet-zone width in modules (spec minimum is 4). */
  margin?: number;
  className?: string;
}

/**
 * Offline QR code, rendered as inline SVG. The dashboard runs under a strict
 * CSP that forbids external hosts, so the matrix is computed locally (see
 * `@/lib/qr`) and drawn as a single SVG path — no network, no canvas, no image.
 *
 * Codes are always drawn as dark modules on a solid white field with a white
 * quiet zone regardless of the dashboard theme: camera scanners need a
 * light background and high contrast, so a QR must not invert in dark mode.
 */
export function QrCode({ value, size = 160, ecc = "MEDIUM", margin = 4, className = "" }: QrCodeProps) {
  const { path, dim } = useMemo(() => {
    try {
      const matrix = encodeQr(value, ecc);
      return { path: qrToSvgPath(matrix), dim: matrix.size + margin * 2 };
    } catch {
      return { path: "", dim: 0 };
    }
  }, [value, ecc, margin]);

  if (!path) {
    return (
      <div
        className={`flex items-center justify-center text-xs text-[color:var(--fainter)] ${className}`}
        style={{ width: size, height: size, background: "#fff", borderRadius: 6 }}
      >
        —
      </div>
    );
  }

  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox={`0 0 ${dim} ${dim}`}
      role="img"
      aria-label={`QR code for ${value}`}
      shapeRendering="crispEdges"
      style={{ background: "#ffffff", borderRadius: 6, display: "block" }}
    >
      <path d={path} fill="#0a0a0a" transform={`translate(${margin}, ${margin})`} />
    </svg>
  );
}
