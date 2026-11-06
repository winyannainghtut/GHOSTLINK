// Ambient declarations: CSS imports (handled by Vite) and the Node bits the Vite config uses.
declare module '*.css';
declare const process: { env: Record<string, string | undefined> };
declare module 'node:url' {
  export function fileURLToPath(url: URL | string): string;
}
