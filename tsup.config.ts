import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', http: 'src/http.ts' },
  format: ['esm'],
  target: 'node20',
  outDir: 'dist',
  clean: true,
  dts: true,
  sourcemap: true,
  banner: { js: '#!/usr/bin/env node' },
});
