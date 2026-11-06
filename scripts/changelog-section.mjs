// Print one version's section from CHANGELOG.md (without its heading) for the release notes.
// Usage: node scripts/changelog-section.mjs 0.2.0
import { readFileSync } from 'node:fs';

const version = process.argv[2];
if (!version) {
  console.error('Usage: node scripts/changelog-section.mjs <version>');
  process.exit(2);
}
const lines = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8').split(/\r?\n/);
const start = lines.findIndex(line => line.startsWith(`## [${version}]`));
if (start === -1) {
  console.error(`CHANGELOG.md has no section for ${version}`);
  process.exit(1);
}
const end = lines.findIndex((line, index) => index > start && line.startsWith('## ['));
const body = lines.slice(start + 1, end === -1 ? undefined : end);
// Drop the link-reference footer if this is the last section.
const footer = body.findIndex(line => /^\[[^\]]+\]: https?:\/\//.test(line));
console.log((footer === -1 ? body : body.slice(0, footer)).join('\n').trim());
