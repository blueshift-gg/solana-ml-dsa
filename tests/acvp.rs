//! NIST ACVP `ML-DSA-sigVer-FIPS204` vectors, ML-DSA-44 groups, taken
//! unchanged from `usnistgov/ACVP-Server` (`gen-val/json-files`,
//! `internalProjection.json`) and reduced to the fields the verifier reads.
//! Four groups of fifteen: the external interface (Algorithm 3) with
//! context strings, the external pre-hash interface (HashML-DSA, not
//! supported, skipped), the internal interface with the caller's `M′`
//! (Algorithm 8) and the internal interface with an external `μ`. Each
//! group holds three cases each of: valid, modified message, modified
//! commitment, modified `z`, modified hint.

use serde_json::Value;
use solana_ml_dsa::ml_dsa_44::{PreparedVerifyingKey, Signature, VerifyingKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn cases() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/acvp_mldsa44_sigver.json")).unwrap()
}

fn key_and_sig(case: &Value) -> (PreparedVerifyingKey, Signature) {
    let pk: [u8; 1312] = unhex(case["pk"].as_str().unwrap()).try_into().unwrap();
    let sig: [u8; 2420] = unhex(case["signature"].as_str().unwrap())
        .try_into()
        .unwrap();
    (
        VerifyingKey::<false>::from_bytes(&pk).prepare(),
        Signature::from_bytes(&sig),
    )
}

fn raw_key(case: &Value) -> VerifyingKey {
    VerifyingKey::<false>::from_bytes(&(unhex(case["pk"].as_str().unwrap()).try_into().unwrap()))
}

#[test]
fn external_pure_interface() {
    let mut seen = [0usize; 2];
    for case in cases()
        .iter()
        .filter(|c| c["interface"] == "external" && c["preHash"] == "pure")
    {
        let (key, sig) = key_and_sig(case);
        let ctx = unhex(case["context"].as_str().unwrap());
        let msg = unhex(case["message"].as_str().unwrap());
        let expected = case["testPassed"].as_bool().unwrap();
        assert_eq!(
            key.verify_with_context(&msg, &ctx, &sig).is_ok(),
            expected,
            "tcId {}: {}",
            case["tcId"],
            case["reason"]
        );
        assert_eq!(
            raw_key(case).verify_with_context(&msg, &ctx, &sig).is_ok(),
            expected,
            "raw key, tcId {}: {}",
            case["tcId"],
            case["reason"]
        );
        seen[expected as usize] += 1;
    }
    assert_eq!(seen, [12, 3], "3 valid and 12 modified cases");
}

#[test]
fn internal_interface_with_m_prime() {
    let mut seen = [0usize; 2];
    for case in cases()
        .iter()
        .filter(|c| c["interface"] == "internal" && c["externalMu"] == false)
    {
        let (key, sig) = key_and_sig(case);
        let m_prime = unhex(case["message"].as_str().unwrap());
        let expected = case["testPassed"].as_bool().unwrap();
        assert_eq!(
            key.verify_internal(&m_prime, &sig).is_ok(),
            expected,
            "tcId {}: {}",
            case["tcId"],
            case["reason"]
        );
        seen[expected as usize] += 1;
    }
    assert_eq!(seen, [12, 3]);
}

#[test]
fn internal_interface_with_external_mu() {
    let mut seen = [0usize; 2];
    for case in cases()
        .iter()
        .filter(|c| c["interface"] == "internal" && c["externalMu"] == true)
    {
        let (key, sig) = key_and_sig(case);
        let mu: [u8; 64] = unhex(case["mu"].as_str().unwrap()).try_into().unwrap();
        let expected = case["testPassed"].as_bool().unwrap();
        assert_eq!(
            key.verify_mu(&mu, &sig).is_ok(),
            expected,
            "tcId {}: {}",
            case["tcId"],
            case["reason"]
        );
        assert_eq!(
            raw_key(case).verify_mu(&mu, &sig).is_ok(),
            expected,
            "raw key, tcId {}: {}",
            case["tcId"],
            case["reason"]
        );
        seen[expected as usize] += 1;
    }
    assert_eq!(seen, [12, 3]);
}

#[test]
fn prehash_interface_is_not_supported() {
    let skipped = cases().iter().filter(|c| c["preHash"] == "preHash").count();
    assert_eq!(
        skipped, 15,
        "HashML-DSA cases present in the fixture, deliberately skipped"
    );
}
