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
  test: { environment: 'jsdom', setupFiles: ['./src/test-setup.ts'] },
});
