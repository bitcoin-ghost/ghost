// Optional white-label customization for the embedded mempool.space frontend.
//
// The upstream build loads this file before the app boots and reads
// `window.__env.customize` (always via optional chaining) for dashboard widget
// overrides and branding. This instance keeps the stock layout, so nothing is
// set here — the file exists so the `<script src="resources/customize.js">`
// reference resolves with a 200 instead of a 404.
window.__env = window.__env || {};
