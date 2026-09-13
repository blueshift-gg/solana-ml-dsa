// Regenerate with `bun tests/fixtures/turbo.mjs`. This patches a test-only
// Noble copy: every SHAKE128/256 call becomes TurboSHAKE128/256, domain 0x1f.
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const dir = mkdtempSync(join(tmpdir(), 'ml-dsa-turbo-'));
try {
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    type: 'module',
    dependencies: { '@noble/post-quantum': '0.6.1' },
    overrides: { '@noble/curves': '2.2.0', '@noble/hashes': '2.2.0' },
  }));
  execFileSync('bun', ['install', '--ignore-scripts'], { cwd: dir, stdio: 'inherit' });
  const source = join(dir, 'node_modules/@noble/post-quantum');
  const patched = join(dir, 'patched');
  mkdirSync(patched);
  for (const file of ['ml-dsa.js', '_crystals.js', 'utils.js']) {
    cpSync(join(source, file), join(patched, file));
    const text = readFileSync(join(patched, file), 'utf8');
    writeFileSync(join(patched, file), text.replace(
      /import \{ (shake128, )?shake256 \} from '@noble\/hashes\/sha3.js';/,
      (_, shake128) => `import { ${shake128 ? 'turboshake128 as shake128, ' : ''}turboshake256 as shake256 } from '@noble/hashes/sha3-addons.js';`,
    ));
  }
  const { ml_dsa44: turbo } = await import(pathToFileURL(join(patched, 'ml-dsa.js')));
  const { ml_dsa44: standard } = await import(pathToFileURL(join(source, 'ml-dsa.js')));
  const { publicKey, secretKey } = turbo.keygen(new Uint8Array(32).fill(42));
  const message = new Uint8Array(32).fill(7);
  const context = new TextEncoder().encode('solana-ml-dsa');
  const signature = turbo.sign(message, secretKey, { context, extraEntropy: false });
  assert(turbo.verify(signature, message, publicKey, { context }));
  assert(!standard.verify(signature, message, publicKey, { context }));
  writeFileSync(new URL('turbo.pk', import.meta.url), publicKey);
  writeFileSync(new URL('turbo.sig', import.meta.url), signature);
  // svm-unit-test copies the source into a generated crate, so its constants
  // are embedded rather than loaded through relative include_bytes! paths.
  let block = '// turbo-fixture-begin\n';
  for (const [name, bytes] of [['TURBO_PUBLIC_KEY', publicKey], ['TURBO_SIGNATURE', signature]]) {
    block += `const ${name}: [u8; ${bytes.length}] = [\n`;
    for (let i = 0; i < bytes.length; i += 16)
      block += '    ' + Array.from(bytes.subarray(i, i + 16), b => `0x${b.toString(16).padStart(2, '0')},`).join(' ') + '\n';
    block += '];\n';
  }
  const sbpf = new URL('../sbpf.rs', import.meta.url);
  writeFileSync(sbpf, readFileSync(sbpf, 'utf8').replace(
    /\/\/ turbo-fixture-begin[\s\S]*?\/\/ turbo-fixture-end/,
    block + '// turbo-fixture-end',
  ));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
