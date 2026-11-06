# Ghostlink desktop UI

Reference: Outline Apps at ce518e8c058d4db9100ec27d15bc071a246a2274, its shared CSS and server-card/access-key-dialog source. Reference informs the flow and visual vocabulary. This is Ghostlink, with original UI markup and an original monoline app icon (a white ghost outline with a wavy hem and two eyes on the teal tile; `apps/desktop/ui/mark.svg`, rasterized by `scripts/generate-icon.ps1`); no Outline logo or affiliation is implied.

Role: a quiet daily utility, viewed at laptop distance. Content capacity: up to 32 server cards with search, a compact active-connection panel, and key import dialog.

Palette: teal #008a78 primary; white panels; #f3f5f5 background; #243432 text; #647571 muted; #dbe4e1 border; #b43b38 error. Dark theme uses #172321 and #21312e surfaces. Typography: Segoe UI Variable/Segoe UI, the native Windows utility typeface, with monospace for endpoint metadata. 8px spacing grid. 8px cards, 6px controls. Subtle one-level card elevation, dialogs one level higher. Transitions 150ms; honor reduced motion.

Flows: add ss:// or ssconf:// key; list/search saved servers; connect/disconnect/switch; rename, details, remove; choose default; autoconnect preference; actual session status and counters; service diagnostics. No credentials in localStorage. Empty state and service-unavailable state contain no invented servers or connection statistics.
