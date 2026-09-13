import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { ml_dsa44 } from '@blueshift-gg/solana-ml-dsa/turboshake';
import { ml_dsa44 as standard } from '@noble/post-quantum/ml-dsa.js';

const seed = new Uint8Array(32).fill(42);
const message = new Uint8Array(32).fill(7);
const context = new TextEncoder().encode('solana-ml-dsa');

test('matches the TurboSHAKE fixtures verified by Rust and SBPF', () => {
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const signature = ml_dsa44.sign(message, secretKey, { context, extraEntropy: false });
  expect(publicKey).toEqual(new Uint8Array(readFileSync(new URL('../../../tests/fixtures/turbo.pk', import.meta.url))));
  expect(signature).toEqual(new Uint8Array(readFileSync(new URL('../../../tests/fixtures/turbo.sig', import.meta.url))));
  expect(ml_dsa44.getPublicKey(secretKey)).toEqual(publicKey);
  expect(ml_dsa44.verify(signature, message, publicKey, { context })).toBe(true);
  expect(standard.verify(signature, message, publicKey, { context })).toBe(false);
  expect(ml_dsa44.verify(signature, message, publicKey)).toBe(false);

  const original = standard.keygen(seed);
  const originalSignature = standard.sign(message, original.secretKey, { context, extraEntropy: false });
  expect(standard.verify(originalSignature, message, original.publicKey, { context })).toBe(true);
  expect(ml_dsa44.verify(originalSignature, message, original.publicKey, { context })).toBe(false);
});

test('Noble signing options and rejection behavior', () => {
  const { secretKey, publicKey } = ml_dsa44.keygen();
  for (const ctx of [new Uint8Array(), context, new Uint8Array(255).fill(1)]) {
    const sig = ml_dsa44.sign(message, secretKey, { context: ctx });
    expect(ml_dsa44.verify(sig, message, publicKey, { context: ctx })).toBe(true);
    expect(ml_dsa44.verify(sig, new Uint8Array(32), publicKey, { context: ctx })).toBe(false);
    sig[0]! ^= 1;
    expect(ml_dsa44.verify(sig, message, publicKey, { context: ctx })).toBe(false);
  }
  expect(() => ml_dsa44.sign(message, secretKey, { context: new Uint8Array(256) })).toThrow();
  expect(() => ml_dsa44.sign(message, new Uint8Array(32))).toThrow();
});
