import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    // Phase 1BU: Vite is not a public dev/staging server. Unpatched
    // picomatch remains in the dev-only lock; limiting exposure is NOT a patch.
    server: {
      host: '127.0.0.1',
      allowedHosts: ['localhost','127.0.0.1'],
      strictPort: true,
      cors: false,
      hmr: false,
      fs: {strict: true},
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
    preview: {
      host: '127.0.0.1',
      allowedHosts: ['localhost','127.0.0.1'],
      strictPort: true,
      cors: false,
    },
  };
});
