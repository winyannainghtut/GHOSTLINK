// PreToolUse hook (Bash). Before a `git commit`, scans what it could commit for secrets: the
// staged changes, the unstaged changes of tracked files (for `commit -a` or an `add` in the same
// command), and untracked files. This enforces agent.md's rule to scan before committing. Exit 2
// blocks the command and tells Claude why. Findings are redacted, so a secret never reaches the
// chat.
//
// It flags:
// - PEM private keys;
// - Ghostlink management keys (apiUrl with certSha256);
// - ss:// and vless:// keys whose host is a public IPv4 address.
// Test fixtures use documentation addresses (TEST-NET), loopback or private ranges, which pass.
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
let command = '';
try {
  command = JSON.parse(input).tool_input?.command ?? '';
} catch {
  process.exit(0);
}
if (!/\bgit\b[^\n;&|]*\bcommit\b/.test(command)) process.exit(0);

const git = args => {
  try {
    return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 256 << 20, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    return '';
  }
};

// [file, line] pairs to scan: added lines of both diffs, and every line of untracked files.
const lines = [];
for (const diff of [git(['diff', '--cached', '-U0', '--no-color', '--no-ext-diff']), git(['diff', '-U0', '--no-color', '--no-ext-diff'])]) {
  let file = '';
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ ')) file = line.slice(4).replace(/^b\//, '');
    else if (line.startsWith('+') && !line.startsWith('+++')) lines.push([file, line.slice(1)]);
  }
}
for (const file of git(['ls-files', '--others', '--exclude-standard']).split('\n').filter(Boolean)) {
  try {
    if (statSync(file).size > 2 << 20) continue;
    const text = readFileSync(file, 'utf8');
    if (text.includes('\0')) continue; // binary
    for (const line of text.split('\n')) lines.push([file, line]);
  } catch {
    /* unreadable: skip */
  }
}

// Documentation (TEST-NET), loopback, private, shared (CGNAT, the mesh) and unspecified addresses.
const harmless = ip => {
  const [a, b, c] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
};
const findings = [];
for (const [file, line] of lines) {
  if (/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(line)) findings.push([file, 'a PEM private key']);
  const api = line.match(/"apiUrl"\s*:\s*"https:\/\/(\d{1,3}(?:\.\d{1,3}){3})/);
  if (api && /"certSha256"\s*:\s*"[0-9A-Fa-f]{64}"/.test(line) && !harmless(api[1])) findings.push([file, 'a management key for a public address']);
  for (const key of line.matchAll(/\b(ss|vless):\/\/[^\s"'`<>@]{8,}@(\d{1,3}(?:\.\d{1,3}){3})[:/]/g)) {
    if (!harmless(key[2])) findings.push([file, `an ${key[1]}:// key for a public address`]);
  }
}
if (findings.length) {
  const unique = [...new Set(findings.map(([file, what]) => `  ${file}: ${what}`))];
  console.error(`Blocked: what this commit could include looks like it holds secrets (redacted):\n${unique.slice(0, 20).join('\n')}\n` +
    'Remove them. A test fixture should use a documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and a throwaway key.');
  process.exit(2);
}
