import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      // voterClient.js only needs Poseidon. The circomlibjs barrel also pulls in
      // contract generators that depend on Node's buffer/assert/events, which
      // Vite stubs out in the browser; import the Poseidon module directly.
      {
        find: /^circomlibjs$/,
        replacement: fileURLToPath(new URL('./node_modules/circomlibjs/src/poseidon_wasm.js', import.meta.url)),
      },
    ],
  },
})
