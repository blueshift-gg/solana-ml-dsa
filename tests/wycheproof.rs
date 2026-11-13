//! Project Wycheproof `mldsa_44_verify_test.json` (`C2SP/wycheproof` at
//! `20b256949e`, `testvectors_v1/`, Apache-2.0), reduced to each group's
//! `publicKey` and its tests. 180 cases in 27 groups: valid signatures with
//! and without a context, `ExpandA` sampling 0 and `q - 1`, zero public
//! keys, hint limits and encodings, decompose boundaries, `z` at or over the
//! infinity-norm bound, wrong key and signature lengths and 256-byte
//! contexts. Every case is checked on the compact key and the prepared key.

use serde_json::Value;
use solana_ml_dsa::ml_dsa_44::{Signature, VerifyingKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn groups() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/wycheproof_mldsa44_verify.json")).unwrap()
}

#[test]
fn verify_test_vectors() {
    let mut seen = [0usize; 2];
    let mut wrong_length = 0;
    for group in groups() {
        let key = VerifyingKey::<false>::from_slice(&unhex(group["publicKey"].as_str().unwrap()));
        let prepared = key.as_ref().ok().map(VerifyingKey::prepare);
        for case in group["tests"].as_array().unwrap() {
            let expected = match case["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {}: unexpected result {other}", case["tcId"]),
            };
            let msg = unhex(case["msg"].as_str().unwrap());
            let ctx = case
                .get("ctx")
                .map_or(Vec::new(), |c| unhex(c.as_str().unwrap()));
            let (Ok(key), Some(prepared), Ok(sig)) = (
                &key,
                &prepared,
                Signature::from_slice(&unhex(case["sig"].as_str().unwrap())),
            ) else {
                assert!(!expected, "tcId {}: {}", case["tcId"], case["comment"]);
                wrong_length += 1;
                seen[0] += 1;
                continue;
            };
            assert_eq!(
                prepared.verify_with_context(&msg, &ctx, &sig).is_ok(),
                expected,
                "tcId {}: {}",
                case["tcId"],
                case["comment"]
            );
            assert_eq!(
                key.verify_with_context(&msg, &ctx, &sig).is_ok(),
                expected,
                "raw key, tcId {}: {}",
                case["tcId"],
                case["comment"]
            );
            seen[expected as usize] += 1;
        }
    }
    assert_eq!(seen, [103, 77], "103 invalid and 77 valid cases");
    assert_eq!(
        wrong_length, 7,
        "keys and signatures of the wrong length, rejected by `from_slice`"
    );
}
