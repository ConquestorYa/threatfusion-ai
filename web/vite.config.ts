import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Development and preview servers listen on loopback only. The page calls
// /api on its own origin; Vite forwards those calls to the local FastAPI
// server (python -m threatfusion.api), which also binds 127.0.0.1 only.
const LOOPBACK = '127.0.0.1'
const API = `http://${LOOPBACK}:${process.env.THREATFUSION_API_PORT ?? '8600'}`

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  server: {
    host: LOOPBACK,
    port: 5173,
    strictPort: true,
    allowedHosts: [],
    proxy: { '/api': { target: API, changeOrigin: false } },
  },
  preview: {
    host: LOOPBACK,
    port: 4173,
    strictPort: true,
    allowedHosts: [],
    proxy: { '/api': { target: API, changeOrigin: false } },
  },
  build: { sourcemap: false },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
