// Self-contained QR Code generator — zero dependencies, runs entirely in the
// browser. The node dashboard ships under a strict Content-Security-Policy that
// forbids any external host (no CDN scripts, no remote QR-image API), so pairing
// QR codes MUST be generated locally. This is a compact TypeScript port of
// Project Nayuki's public-domain QR Code generator, trimmed to byte mode (the
// only mode we need for URLs / host:port strings) with full automatic version
// and mask selection so the output scans reliably.
//
// Reference: https://www.nayuki.io/page/qr-code-generator-library (public domain)

export type Ecc = "LOW" | "MEDIUM" | "QUARTILE" | "HIGH";

// Format-info bit patterns and ECC-table column index for each level.
const ECC_META: Record<Ecc, { ordinal: number; formatBits: number }> = {
  LOW: { ordinal: 0, formatBits: 1 },
  MEDIUM: { ordinal: 1, formatBits: 0 },
  QUARTILE: { ordinal: 2, formatBits: 3 },
  HIGH: { ordinal: 3, formatBits: 2 },
};

const MIN_VERSION = 1;
const MAX_VERSION = 40;

// Number of error-correction codewords per block, indexed [eccOrdinal][version].
// Index 0 of each row is an unused placeholder so version maps directly.
const ECC_CODEWORDS_PER_BLOCK: number[][] = [
  // L
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  // M
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  // Q
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  // H
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];

// Number of error-correction blocks, indexed [eccOrdinal][version].
const NUM_ERROR_CORRECTION_BLOCKS: number[][] = [
  // L
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  // M
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  // Q
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  // H
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

function getNumRawDataModules(ver: number): number {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

function getNumDataCodewords(ver: number, eccOrdinal: number): number {
  return (
    Math.floor(getNumRawDataModules(ver) / 8) -
    ECC_CODEWORDS_PER_BLOCK[eccOrdinal][ver] * NUM_ERROR_CORRECTION_BLOCKS[eccOrdinal][ver]
  );
}

// Reed-Solomon over GF(256) with the QR primitive polynomial 0x11D.
function reedSolomonComputeDivisor(degree: number): number[] {
  const result: number[] = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = reedSolomonMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = reedSolomonMultiply(root, 0x02);
  }
  return result;
}

function reedSolomonComputeRemainder(data: number[], divisor: number[]): number[] {
  const result: number[] = new Array(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    for (let i = 0; i < divisor.length; i++) {
      result[i] ^= reedSolomonMultiply(divisor[i], factor);
    }
  }
  return result;
}

function reedSolomonMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

export interface QrMatrix {
  size: number;
  // Row-major boolean grid; true = dark module.
  modules: boolean[][];
}

// Encode a UTF-8 string as a QR Code and return the module matrix.
export function encodeQr(text: string, ecc: Ecc = "MEDIUM"): QrMatrix {
  const meta = ECC_META[ecc];
  const dataBytes = utf8Bytes(text);

  // Byte-mode segment: pick the smallest version that fits.
  let version = MIN_VERSION;
  let dataCapacityBits = 0;
  for (; ; version++) {
    if (version > MAX_VERSION) {
      throw new Error("Data too long for a QR Code");
    }
    dataCapacityBits = getNumDataCodewords(version, meta.ordinal) * 8;
    const charCountBits = version <= 9 ? 8 : 16;
    const segBits = 4 + charCountBits + dataBytes.length * 8;
    if (segBits <= dataCapacityBits) break;
  }

  // Build the bit stream.
  const bits: number[] = [];
  const appendBits = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  appendBits(0x4, 4); // byte mode indicator
  appendBits(dataBytes.length, version <= 9 ? 8 : 16);
  for (const b of dataBytes) appendBits(b, 8);

  // Terminator + pad to a byte boundary + alternating pad bytes.
  appendBits(0, Math.min(4, dataCapacityBits - bits.length));
  appendBits(0, (8 - (bits.length % 8)) % 8);
  for (let padByte = 0xec; bits.length < dataCapacityBits; padByte ^= 0xec ^ 0x11) {
    appendBits(padByte, 8);
  }

  // Pack bits into data codewords.
  const dataCodewords: number[] = new Array(bits.length / 8).fill(0);
  bits.forEach((bit, i) => {
    dataCodewords[i >>> 3] |= bit << (7 - (i & 7));
  });

  const allCodewords = addEccAndInterleave(dataCodewords, version, meta.ordinal);
  return buildMatrix(version, meta.formatBits, allCodewords);
}

function addEccAndInterleave(data: number[], version: number, eccOrdinal: number): number[] {
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[eccOrdinal][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[eccOrdinal][version];
  const rawCodewords = Math.floor(getNumRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const blocks: number[][] = [];
  const rsDiv = reedSolomonComputeDivisor(blockEccLen);
  let k = 0;
  for (let i = 0; i < numBlocks; i++) {
    const datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const dat = data.slice(k, k + datLen);
    k += datLen;
    const ecc = reedSolomonComputeRemainder(dat, rsDiv);
    if (i < numShortBlocks) dat.push(0); // pad so all blocks align for interleaving
    blocks.push(dat.concat(ecc));
  }

  // Interleave the blocks column by column.
  const result: number[] = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, j) => {
      // Skip the padding column of short data blocks.
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) {
        result.push(block[i]);
      }
    });
  }
  return result;
}

function buildMatrix(version: number, formatBits: number, codewords: number[]): QrMatrix {
  const size = version * 4 + 17;
  const modules: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const isFunction: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));

  const setFunction = (x: number, y: number, dark: boolean) => {
    modules[y][x] = dark;
    isFunction[y][x] = true;
  };

  // Timing patterns.
  for (let i = 0; i < size; i++) {
    setFunction(6, i, i % 2 === 0);
    setFunction(i, 6, i % 2 === 0);
  }

  // Finder patterns + separators (drawn as 9x9 regions).
  const drawFinder = (cx: number, cy: number) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < size && y >= 0 && y < size) {
          setFunction(x, y, dist !== 2 && dist !== 4);
        }
      }
    }
  };
  drawFinder(3, 3);
  drawFinder(size - 4, 3);
  drawFinder(3, size - 4);

  // Alignment patterns.
  const alignPositions = getAlignmentPositions(version);
  const numAlign = alignPositions.length;
  for (let i = 0; i < numAlign; i++) {
    for (let j = 0; j < numAlign; j++) {
      // Skip the three corners occupied by finder patterns.
      if (
        (i === 0 && j === 0) ||
        (i === 0 && j === numAlign - 1) ||
        (i === numAlign - 1 && j === 0)
      ) {
        continue;
      }
      const cx = alignPositions[i];
      const cy = alignPositions[j];
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          setFunction(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
  }

  // Reserve format-info areas (real bits drawn after masking).
  reserveFormatArea(size, setFunction);

  // Version info for version >= 7.
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const versionData = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((versionData >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFunction(a, b, bit);
      setFunction(b, a, bit);
    }
  }

  // Draw data codewords in the standard zig-zag order.
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // skip the vertical timing column
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFunction[y][x] && i < codewords.length * 8) {
          modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
    }
  }

  // Try all 8 masks, keep the one with the lowest penalty.
  let bestMask = 0;
  let minPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    applyMask(modules, isFunction, mask);
    drawFormatBits(formatBits, mask, size, modules);
    const penalty = computePenalty(modules, size);
    if (penalty < minPenalty) {
      minPenalty = penalty;
      bestMask = mask;
    }
    applyMask(modules, isFunction, mask); // XOR again to undo
  }
  applyMask(modules, isFunction, bestMask);
  drawFormatBits(formatBits, bestMask, size, modules);

  return { size, modules };
}

// Reserve the format-info modules as function cells (values filled later).
function reserveFormatArea(size: number, setFunction: (x: number, y: number, dark: boolean) => void) {
  for (let i = 0; i <= 5; i++) setFunction(8, i, false);
  setFunction(8, 7, false);
  setFunction(8, 8, false);
  setFunction(7, 8, false);
  for (let i = 9; i < 15; i++) setFunction(8, 14 - i, false);
  for (let i = 0; i < 8; i++) setFunction(size - 1 - i, 8, false);
  for (let i = 8; i < 15; i++) setFunction(8, size - 15 + i, false);
  setFunction(8, size - 8, true); // always-dark module
}

// Compute the 15-bit BCH format value and write it into both copies.
function drawFormatBits(formatBits: number, mask: number, size: number, modules: boolean[][]) {
  const data = (formatBits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bitsVal = ((data << 10) | rem) ^ 0x5412;

  const getBit = (i: number) => ((bitsVal >>> i) & 1) === 1;

  for (let i = 0; i <= 5; i++) modules[i][8] = getBit(i);
  modules[7][8] = getBit(6);
  modules[8][8] = getBit(7);
  modules[8][7] = getBit(8);
  for (let i = 9; i < 15; i++) modules[8][14 - i] = getBit(i);

  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = getBit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = getBit(i);
}

function applyMask(modules: boolean[][], isFunction: boolean[][], mask: number) {
  const size = modules.length;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (isFunction[y][x]) continue;
      let invert: boolean;
      switch (mask) {
        case 0: invert = (x + y) % 2 === 0; break;
        case 1: invert = y % 2 === 0; break;
        case 2: invert = x % 3 === 0; break;
        case 3: invert = (x + y) % 3 === 0; break;
        case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
        case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
        case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        default: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
      }
      if (invert) modules[y][x] = !modules[y][x];
    }
  }
}

function computePenalty(modules: boolean[][], size: number): number {
  let penalty = 0;

  // Rule 1: runs of 5+ same-colour modules in rows and columns.
  for (let y = 0; y < size; y++) {
    let runColor = modules[y][0];
    let runLen = 1;
    for (let x = 1; x < size; x++) {
      if (modules[y][x] === runColor) {
        runLen++;
        if (runLen === 5) penalty += 3;
        else if (runLen > 5) penalty++;
      } else {
        runColor = modules[y][x];
        runLen = 1;
      }
    }
  }
  for (let x = 0; x < size; x++) {
    let runColor = modules[0][x];
    let runLen = 1;
    for (let y = 1; y < size; y++) {
      if (modules[y][x] === runColor) {
        runLen++;
        if (runLen === 5) penalty += 3;
        else if (runLen > 5) penalty++;
      } else {
        runColor = modules[y][x];
        runLen = 1;
      }
    }
  }

  // Rule 2: 2x2 blocks of one colour.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = modules[y][x];
      if (c === modules[y][x + 1] && c === modules[y + 1][x] && c === modules[y + 1][x + 1]) {
        penalty += 3;
      }
    }
  }

  // Rule 3: finder-like 1:1:3:1:1 patterns, in rows and columns.
  for (let y = 0; y < size; y++) {
    for (let x = 0; x + 6 < size; x++) {
      if (hasFinderRunRow(modules[y], x)) penalty += 40;
    }
  }
  for (let x = 0; x < size; x++) {
    for (let y = 0; y + 6 < size; y++) {
      if (hasFinderRunCol(modules, x, y)) penalty += 40;
    }
  }

  // Rule 4: overall dark/light balance.
  let dark = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) if (modules[y][x]) dark++;
  }
  const total = size * size;
  const k = Math.floor((Math.abs(dark * 20 - total * 10) + total - 1) / total) - 1;
  penalty += k * 10;

  return penalty;
}

function hasFinderRunRow(row: boolean[], x: number): boolean {
  return (
    row[x] && !row[x + 1] && row[x + 2] && row[x + 3] && row[x + 4] && !row[x + 5] && row[x + 6]
  );
}

function hasFinderRunCol(modules: boolean[][], x: number, y: number): boolean {
  return (
    modules[y][x] &&
    !modules[y + 1][x] &&
    modules[y + 2][x] &&
    modules[y + 3][x] &&
    modules[y + 4][x] &&
    !modules[y + 5][x] &&
    modules[y + 6][x]
  );
}

function getAlignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step = Math.floor((version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2;
  const result = [6];
  for (let pos = version * 4 + 10; result.length < numAlign; pos -= step) {
    result.splice(1, 0, pos);
  }
  return result;
}

function utf8Bytes(str: string): number[] {
  const out: number[] = [];
  for (const ch of str) {
    const code = ch.codePointAt(0) as number;
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f),
      );
    }
  }
  return out;
}

// Render a matrix to an SVG path string ("M..h..v..z") covering the dark
// modules, in a coordinate space of `size` units (no quiet zone). The caller
// sets the viewBox and colours so the code inherits the dashboard theme.
export function qrToSvgPath(matrix: QrMatrix): string {
  const parts: string[] = [];
  for (let y = 0; y < matrix.size; y++) {
    for (let x = 0; x < matrix.size; x++) {
      if (matrix.modules[y][x]) {
        parts.push(`M${x},${y}h1v1h-1z`);
      }
    }
  }
  return parts.join("");
}
