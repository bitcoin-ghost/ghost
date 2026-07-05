/**
 * Bundled, dependency-free world map geometry.
 *
 * The offline CSP posture forbids external map tiles, CDN-hosted GeoJSON, and
 * mapping libraries pulled at runtime, and no mapping library is present in the
 * bundle. So the map is a small set of hand-simplified continent outlines,
 * expressed as [lon, lat] rings and rendered inline as SVG polygons under a
 * plain equirectangular projection. It is a stylised silhouette — recognisable
 * continents, not survey-grade coastlines — which is all a peer-region overview
 * needs, and it adds no dependency and only a few KB.
 *
 * Projection (equirectangular): the SVG viewBox is `0 0 360 180`, one unit per
 * degree, so a point projects to `x = lon + 180`, `y = 90 - lat`.
 */

export const MAP_WIDTH = 360;
export const MAP_HEIGHT = 180;

/** Project a [lon, lat] pair into viewBox coordinates. */
export function project(lon: number, lat: number): [number, number] {
  return [lon + 180, 90 - lat];
}

/** Build an SVG path `d` string for a closed ring of [lon, lat] points. */
export function ringToPath(ring: [number, number][]): string {
  return (
    ring
      .map(([lon, lat], i) => {
        const [x, y] = project(lon, lat);
        return `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(" ") + " Z"
  );
}

/**
 * Simplified continent outlines as closed [lon, lat] rings. Coarse by design.
 */
export const CONTINENTS: [number, number][][] = [
  // North America
  [
    [-168, 65], [-160, 71], [-140, 70], [-120, 72], [-95, 73], [-80, 73], [-62, 66],
    [-56, 60], [-64, 47], [-70, 44], [-70, 41], [-75, 35], [-81, 25], [-90, 29],
    [-97, 26], [-97, 22], [-105, 20], [-106, 23], [-114, 28], [-118, 33], [-122, 37],
    [-124, 42], [-124, 48], [-132, 52], [-140, 59], [-150, 59], [-165, 60], [-168, 65],
  ],
  // Greenland
  [
    [-45, 60], [-30, 61], [-20, 70], [-25, 78], [-40, 83], [-58, 80], [-55, 70],
    [-50, 64], [-45, 60],
  ],
  // South America
  [
    [-77, 8], [-72, 11], [-62, 10], [-52, 5], [-50, 0], [-42, -3], [-35, -6],
    [-38, -13], [-48, -25], [-58, -35], [-62, -40], [-65, -45], [-69, -52], [-74, -52],
    [-72, -45], [-73, -38], [-71, -30], [-71, -18], [-77, -12], [-81, -6], [-80, -2],
    [-78, 2], [-77, 8],
  ],
  // Africa
  [
    [-17, 15], [-16, 21], [-10, 27], [-5, 32], [10, 34], [11, 37], [20, 32], [25, 32],
    [32, 31], [34, 28], [43, 12], [51, 12], [43, 4], [41, -2], [40, -10], [35, -18],
    [32, -26], [27, -33], [20, -35], [18, -28], [13, -17], [9, -2], [9, 4], [3, 6],
    [-8, 4], [-13, 8], [-17, 15],
  ],
  // Europe (with a rough Scandinavia lobe)
  [
    [-10, 36], [-9, 43], [-2, 43], [-1, 49], [-5, 50], [2, 51], [4, 58], [8, 63],
    [12, 66], [18, 69], [24, 66], [28, 60], [30, 55], [26, 46], [20, 42], [15, 40],
    [18, 45], [12, 44], [8, 44], [3, 43], [-3, 36], [-10, 36],
  ],
  // Asia
  [
    [30, 55], [40, 62], [50, 68], [60, 70], [75, 73], [95, 76], [115, 74], [140, 73],
    [160, 70], [178, 66], [170, 60], [160, 60], [142, 50], [135, 45], [129, 42],
    [122, 40], [121, 31], [113, 22], [108, 21], [106, 16], [99, 8], [95, 16], [88, 22],
    [80, 13], [73, 8], [67, 25], [57, 25], [48, 40], [41, 42], [37, 45], [30, 47],
    [30, 55],
  ],
  // Australia
  [
    [114, -22], [122, -18], [130, -12], [137, -12], [143, -12], [147, -20], [153, -28],
    [150, -37], [143, -39], [135, -35], [129, -32], [123, -34], [115, -34], [113, -26],
    [114, -22],
  ],
];
