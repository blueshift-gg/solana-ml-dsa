# Solana ML-DSA

Noble's ML-DSA-44 with TurboSHAKE128/256, domain `0x1f`. Matches
`solana_ml_dsa::ml_dsa_44::VerifyingKey::<true>` on-chain.

```sh
npm install @blueshift-gg/solana-ml-dsa
```

```ts
import { ml_dsa44 } from '@blueshift-gg/solana-ml-dsa/turboshake';

const { secretKey, publicKey } = ml_dsa44.keygen();
const message = new Uint8Array(32).fill(7);
const signature = ml_dsa44.sign(message, secretKey);
ml_dsa44.verify(signature, message, publicKey); // true
```

Same [Noble API](https://github.com/paulmillr/noble-post-quantum): byte arrays,
optional context, deterministic or randomized signing. Public keys are 1,312 bytes;
signatures are 2,420 bytes.

The build reuses Noble's implementation with its SHAKE imports redirected to
Noble's TurboSHAKE. This is a distinct construction, not FIPS 204. For standard
ML-DSA, use `@noble/post-quantum/ml-dsa.js` directly. Bind the variant when storing keys.

## License

[MIT](LICENSE). Includes Noble code by Paul Miller.
