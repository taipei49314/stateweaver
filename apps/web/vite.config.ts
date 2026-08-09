import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 3000,
    strictPort: true,
    proxy: {
      '/healthz': { target: 'http://127.0.0.1:8000' },
      '/v1': { target: 'http://127.0.0.1:8000' },
    },
  },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true },
  test: {
    // happy-dom provides the browser APIs this contract suite exercises while keeping the
    // worker startup comfortably inside Vitest's fixed 60-second handshake on Windows.
    environment: 'happy-dom',
    setupFiles: ['./src/test-setup.ts'],
    // Fork workers can fail to come online on Windows and constrained CI hosts before
    // Vitest's startup deadline. A single worker thread keeps this small suite portable
    // and deterministic without changing test isolation.
    pool: 'threads',
    maxWorkers: 1,
    fileParallelism: false,
  },
});
