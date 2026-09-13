//! Regenerates the SBPF measurement fixture: a fips204 key pair and a
//! signature over a 32-byte message digest under a short context, the shape
//! an on-chain verification has. Deterministic (a fixed xorshift seed drives
//! fips204's key generation and signing) so the CU numbers in the README
//! are reproducible. Rewrites the fixture block of `sbpf.rs` in place.
//!
//! ```sh
//! cargo test --release --test fixture -- --ignored
//! ```

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer};
use rand_core::{CryptoRng, RngCore};
use std::fmt::Write as _;

struct Xorshift(u64);

impl RngCore for Xorshift {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// Not a secure generator: it only has to be deterministic for the fixture.
impl CryptoRng for Xorshift {}

fn array(name: &str, bytes: &[u8]) -> String {
    let mut s = format!("const {name}: [u8; {}] = [\n", bytes.len());
    for row in bytes.chunks(16) {
        s.push_str("   ");
        for b in row {
            let _ = write!(s, " 0x{b:02x},");
        }
        s.push('\n');
    }
    s.push_str("];\n");
    s
}

#[test]
#[ignore]
fn regenerate_sbpf_fixture() {
    const SEED: u64 = 0x5eed_4d4c_4453_4144;
    let mut rng = Xorshift(SEED);
    let (pk, sk) = ml_dsa_44::try_keygen_with_rng(&mut rng).unwrap();
    let context = b"solana-ml-dsa";
    // A 32-byte digest, as a program would hash its authorised payload.
    let mut message = [0u8; 32];
    rng.fill_bytes(&mut message);
    let signature = sk.try_sign_with_rng(&mut rng, &message, context).unwrap();

    let mut block = format!(
        "// fips204 ML-DSA-44, deterministic seed 0x{SEED:x}; regenerate with\n\
         // `cargo test --release --test fixture -- --ignored`.\n"
    );
    block.push_str(&array("PUBLIC_KEY", &pk.clone().into_bytes()));
    block.push_str(&array("SIGNATURE", &signature));
    block.push_str(&array("CONTEXT", context));
    block.push_str(&array("MESSAGE", &message));

    std::fs::write("tests/fixtures/campaign.pk", pk.clone().into_bytes()).unwrap();
    let file = "tests/sbpf.rs";
    let src = std::fs::read_to_string(file).unwrap();
    let start = src.find("// fixture-begin\n").expect("marker") + "// fixture-begin\n".len();
    let end = src.find("// fixture-end\n").expect("marker");
    let out = format!("{}{}{}", &src[..start], block, &src[end..]);
    std::fs::write(file, out).unwrap();
}
