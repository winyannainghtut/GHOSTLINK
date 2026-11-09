// PostToolUse hook (Edit, Write, MultiEdit). After a Go or Rust file is changed, checks its format
// the way CI does (gofmt, rustfmt), so a misformatted file is fixed before it is committed. Exit 2
// shows Claude the message. The tool already ran, so nothing is undone.
import { spawnSync } from 'node:child_process';

let input = '';
for await (const chunk of process.stdin) input += chunk;
let file = '';
try {
  file = JSON.parse(input).tool_input?.file_path ?? '';
} catch {
  process.exit(0);
}
// Upstream sources and generated files are not ours to format.
if (!file || /[\\/](\.upstream|artifacts|target|node_modules|vendor)[\\/]/.test(file)) process.exit(0);

if (file.endsWith('.go')) {
  const result = spawnSync('gofmt', ['-l', file], { encoding: 'utf8' });
  if (result.status === 0 && result.stdout.trim()) {
    console.error(`gofmt would reformat ${file}. Run: gofmt -w "${file}"`);
    process.exit(2);
  }
} else if (file.endsWith('.rs')) {
  // 1 means "would reformat"; anything else (no rustfmt, a parse error mid-edit) stays quiet.
  const result = spawnSync('rustfmt', ['--check', '--edition', '2021', file], { encoding: 'utf8' });
  if (result.status === 1) {
    console.error(`rustfmt would reformat ${file}. Run: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/cargo.ps1 fmt --all`);
    process.exit(2);
  }
}
