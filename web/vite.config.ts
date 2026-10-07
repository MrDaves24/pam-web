import {reactRouter} from '@react-router/dev/vite'
import tailwindcss from '@tailwindcss/vite'
import {defineConfig} from 'vite'
import tsconfigPaths from 'vite-tsconfig-paths'

export default defineConfig({
  // Pre-bundled at startup : discovered on the first load, Vite re-bundles and reloads, and that page gets two Reacts
  optimizeDeps: {include: ['elysia', '@elysiajs/eden']},
  // React Router's plugin doesn't run under vitest
  plugins: [tailwindcss(), !process.env.VITEST && reactRouter(), tsconfigPaths()]
})
