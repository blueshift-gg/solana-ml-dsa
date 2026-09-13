import { build } from 'esbuild';

await build({
  entryPoints: ['src/turboshake.ts'],
  outdir: 'dist',
  bundle: true,
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  banner: { js: '/*! Copyright (c) 2024 Paul Miller (https://paulmillr.com). MIT License. */' },
  alias: { '@noble/hashes/sha3.js': './src/sha3.ts' },
  external: ['@noble/hashes/*', '@noble/curves/*'],
});
