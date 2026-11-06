# Ghostlink web UI

React, TypeScript, Tailwind CSS and Lucide icons, built with Vite. `shared/` is the glass component library: surfaces, pill controls, the switch, sheets, toasts, charts, the glass-wave background and the mesh map. The server dashboard is in `dashboard/`, and the desktop app will follow on the same library.

```sh
cd ui
npm ci --ignore-scripts      # exact versions from package-lock.json
npm run build                # typecheck, then build the dashboard into the Go module
GHOSTLINK_DASHBOARD=http://127.0.0.1:8080 npm run dev:dashboard   # live reload against a real dashboard
```

**Output.** The dashboard is built into `core/outline-worker/internal/server/dashboard/`, where `ghostlink-server` embeds it.
- The build is committed, so the Go module builds without Node.
- The **Web UI** workflow rebuilds it and fails if the committed files differ.
- Don't edit the files there; change `ui/` and rebuild.

**Content-Security-Policy.** The dashboard's CSP allows only its own origin, with no inline scripts or style attributes. So:
- style with classes, not `style="…"`. React's `style` prop is applied through the CSSOM, which the CSP allows; use it only for computed positions.
- keep fonts and icons bundled. The fonts are Plus Jakarta Sans and JetBrains Mono (SIL OFL 1.1, Latin subsets), self-hosted from `@fontsource-variable`. Apple devices use San Francisco first.
- `assetsInlineLimit` is 0, so nothing becomes a `data:` URI.

`internal/server/dashboard_test.go` checks the embedded build: a single script and stylesheet, flat file names, and no inline code.

**Design rules.**
- Frosted surfaces (`.glass`, 28 px radius; inner panels 24 px) over three slow glass waves. The waves can be set to Subtle, Calm or Still, and are still when the system asks for reduced motion.
- Three finishes: Obsidian `#090A0D`, Titanium `#111318` and Daylight `#F2F4F8`. Each is a set of CSS variables on `<html data-finish>`.
- Sentence-case labels; no uppercase, letter-spaced micro-labels.
- Monospace (`.mono`) only for addresses, CIDRs, keys, ports and interface names.
- Tabular figures (`.num`) for every live number.
- A frosted element can't blur through a frosted parent. Render floating panels that must blur the page (such as the Island's) in a portal.
