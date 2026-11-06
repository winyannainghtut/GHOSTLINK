// Builds the Ghostlink desktop app's interface into apps/desktop/ui, which the Tauri shell
// bundles (frontendDist). Like the dashboard build it is flat, content-hashed and has no inline
// scripts, styles or data: URIs, so it runs under the app's strict Content-Security-Policy.
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  root: here('./desktop'),
  base: './',
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@shared': here('./shared'), '@admin': here('./admin') } },
  build: {
    outDir: here('../apps/desktop/ui'),
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
});
