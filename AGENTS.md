# p2p-filedrop

Static site, no build step and no dependencies beyond the pinned `vendor/trystero-nostr.mjs`.

- `app.js`: everything the user sees: files, chat, room setup.
- `security.js`: parsers and limits for all peer data, plus membership. All traffic goes through its room facade; never use the raw room in a feature.
- `test.mjs`: run after any change.

Rules: every peer message goes through a parser in `security.js`. Peer data reaches the DOM only as text. No inline script or style, since the CSP forbids them. Relays are listed in both `security.js` and the CSP, and a test checks they match. No telemetry, no persistence beyond `sessionStorage`. Trystero action names are at most 12 bytes. UI text, code and docs are English.
