// Print the Ghostlink release version after checking that every place declaring it agrees.
// Usage: node scripts/release-version.mjs [--tag vX.Y.Z]
// The root Cargo workspace version is authoritative; a mismatch or wrong tag exits nonzero.
import { readFileSync } from 'node:fs';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const capture = (path, pattern) => read(path).match(pattern)?.[1] ?? null;

const version = capture('Cargo.toml', /\[workspace\.package\][^[]*?^version\s*=\s*"([^"]+)"/ms);
if (!version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error('Cannot read a semantic version from [workspace.package] in Cargo.toml');
  process.exit(1);
}

const declared = {
  'apps/desktop/src-tauri/Cargo.toml': capture('apps/desktop/src-tauri/Cargo.toml', /^version\s*=\s*"([^"]+)"/m),
  'apps/desktop/src-tauri/tauri.conf.json': JSON.parse(read('apps/desktop/src-tauri/tauri.conf.json')).version,
  'apps/desktop/ui/index.html': capture('apps/desktop/ui/index.html', /PERSONAL VPN · ([^<\s]+)/),
  // The daemon only runs a worker whose version line matches exactly, so these must agree.
  'core/outline-worker/main.go': capture('core/outline-worker/main.go', /tunnel worker ([^;"]+);/),
  'core/vpn-engine/src/worker_session.rs': capture('core/vpn-engine/src/worker_session.rs', /tunnel worker ([^;"]+);/),
};
const mismatches = Object.entries(declared).filter(([, value]) => value !== version);
for (const [path, value] of mismatches) console.error(`${path} declares ${value ?? 'no version'}; Cargo.toml declares ${version}`);

const tagIndex = process.argv.indexOf('--tag');
if (tagIndex !== -1) {
  const tag = process.argv[tagIndex + 1] ?? '';
  if (tag !== `v${version}`) {
    console.error(`Tag ${tag || '(missing)'} does not match version v${version}`);
    process.exit(1);
  }
}
if (mismatches.length) process.exit(1);
console.log(version);
