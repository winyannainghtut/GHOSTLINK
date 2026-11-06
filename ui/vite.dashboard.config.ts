// Builds the Ghostlink server dashboard into the Go module, where ghostlink-server embeds it
// (core/outline-worker/internal/server/dashboard). The output is flat (the server serves only
// top-level names), content-hashed, and has no inline scripts, styles or data: URIs, so it runs
// under the dashboard's strict Content-Security-Policy.
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  root: here('./dashboard'),
  base: './',
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@shared': here('./shared'), '@admin': here('./admin') } },
  build: {
    outDir: here('../core/outline-worker/internal/server/dashboard'),
    emptyOutDir: true,
    assetsDir: '',
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    reportCompressedSize: false,
    rolldownOptions: {
      output: {
        entryFileNames: '[name]-[hash].js',
        chunkFileNames: '[name]-[hash].js',
        assetFileNames: '[name]-[hash][extname]',
      },
    },
  },
  server: {
    // npm run dev:dashboard proxies to a dashboard you opened with `ghostlink-server dashboard`
    // (or an SSH tunnel): GHOSTLINK_DASHBOARD=http://127.0.0.1:8080
    proxy: Object.fromEntries(['/api', '/login', '/logout'].map(path => [path, process.env.GHOSTLINK_DASHBOARD || 'http://127.0.0.1:8080'])),
  },
});
