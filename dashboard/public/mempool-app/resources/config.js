// Runtime configuration for the embedded mempool.space frontend.
//
// The Angular app reads `window.__env` and merges it over its compiled
// defaults (`this.env = Object.assign(defaults, window.__env)`), so every key
// set below overrides the build-time default.
//
// NOTE ON THE API BASE URL
// ------------------------
// The API/WebSocket base is NOT configurable from here. In the browser the
// app hard-codes its request base to `apiBaseUrl = ""` and builds every call
// as `apiBaseUrl + apiBasePath + "/api/v1/..."`, ignoring `window.__env`. To
// serve the app same-origin under the dashboard subpath `/mempool-app/`, the
// compiled bundles were patched to default `apiBaseUrl` to `/mempool-app` and
// to prefix the WebSocket path with `/mempool-app` (see main.*.js and the
// 601.*.js / 973.*.js chunks). All data therefore flows through
// `/mempool-app/api/...`, which the dashboard server proxies to the node-local
// mempool backend on 127.0.0.1:8999. Keep `ROOT_NETWORK` empty so the app's
// network path stays "" and requests hit `/mempool-app/api/v1/...` unprefixed.
window.__env = window.__env || {};

// This instance serves a single node's own mempool via the Core-only backend.
window.__env.BASE_MODULE = 'mempool';
window.__env.ROOT_NETWORK = '';

// Only the node's own network. Disable the other networks so the switcher and
// their routes don't offer endpoints this backend doesn't serve.
window.__env.MAINNET_ENABLED = true;
window.__env.TESTNET_ENABLED = false;
window.__env.TESTNET4_ENABLED = false;
window.__env.SIGNET_ENABLED = false;
window.__env.REGTEST_ENABLED = false;
window.__env.LIQUID_ENABLED = false;
window.__env.LIQUID_TESTNET_ENABLED = false;

// Disable the heavyweight / hosted-service features the Core-only backend has
// no data for, so the UI stays focused on the live mempool view.
window.__env.MINING_DASHBOARD = false;
window.__env.LIGHTNING = false;
window.__env.ACCELERATOR = false;
window.__env.ACCELERATOR_BUTTON = false;
window.__env.PUBLIC_ACCELERATIONS = false;
window.__env.HISTORICAL_PRICE = false;
window.__env.ADDITIONAL_CURRENCIES = false;
window.__env.OFFICIAL_MEMPOOL_SPACE = false;

window.__env.ITEMS_PER_PAGE = 10;
