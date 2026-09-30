# Forge Browser

`browser.fg` is the Forge DOM/events/navigation/HTTP/storage API. `src/bridge.js`
provides browser primitives and lossless JSON handles for `web.fg`. Forge's
`--emit-js` target generates application logic; this module does not embed
application routes, database policy or UI copy.

Bundle the bridge with esbuild and load it before the emitted JavaScript. JSON
handles are local to a synchronous callback; DOM handles persist until their
subtree is cleared. Never retain JSON handles across callbacks. Async HTTP
callbacks receive `{context,status,data,error}`. Applications reject stale
responses using their own route context. HTTP requests and authenticated uploads
are restricted to `/api/` on the current origin. Markdown is sanitized with
DOMPurify; HTML/event attributes and dangerous URL schemes are rejected.

Requires the Forge JavaScript backend, browser BigInt/TextEncoder support, and
Node for bundling. Native C builds cannot use this browser-only module. See
portfolio-platform/frontend-forge for a complete integration.
