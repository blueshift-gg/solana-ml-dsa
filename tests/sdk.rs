//! Public SDK contract and byte parity with the TypeScript package.
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use solana_ml_dsa::ml_dsa_44::{Error, PreparedVerifyingKey, Signature, VerifyingKey};

fn key() -> VerifyingKey {
    VerifyingKey::from_bytes(include_bytes!("fixtures/campaign.pk"))
}

#[test]
fn prepared_encoding_matches_shared_fixture() {
    let expected = std::fs::read("tests/fixtures/sdk-prepared.bin").unwrap();
    let prepared = key().prepare();
    assert_eq!(prepared.as_bytes().as_slice(), expected);
    let decoded = PreparedVerifyingKey::from_slice(&expected).unwrap();
    assert_eq!(decoded.as_bytes(), prepared.as_bytes());
    let invalid = [255; PreparedVerifyingKey::BYTE_LEN];
    assert!(matches!(
        PreparedVerifyingKey::from_bytes(&invalid),
        Err(Error::InvalidEncoding)
    ));

    for index in 0..4 {
        let mut row = [[0u32; 5]; 256];
        key().prepare_row_into(index, &mut row).unwrap();
        assert_eq!(Some(&row), prepared.row(index));
    }
    let mut row = [[7u32; 5]; 256];
    assert_eq!(key().prepare_row_into(4, &mut row), Err(Error::InvalidRow));
    assert_eq!(row, [[7; 5]; 256]);
}

#[test]
fn encoded_values_and_verification() {
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&[42; 32]);
    let key = VerifyingKey::from_bytes(&pk.into_bytes());
    let signature = Signature::from_bytes(&sk.try_sign_with_seed(&[0; 32], b"sdk", b"").unwrap());
    let encoded = key.to_bytes();
    assert_eq!(VerifyingKey::try_from(encoded.as_slice()).unwrap(), key);
    assert_eq!(VerifyingKey::ref_from_bytes(&encoded).unwrap(), &key);
    assert_eq!(
        Signature::from_slice(signature.as_bytes()).unwrap(),
        signature
    );
    assert_eq!(
        VerifyingKey::from_slice(&encoded[..1311]),
        Err(Error::InvalidLength)
    );
    assert_eq!(Signature::from_slice(&[]), Err(Error::InvalidLength));
    key.verify(b"sdk", &signature).unwrap();
    key.prepare().verify(b"sdk", &signature).unwrap();
    assert!(key.verify(b"changed", &signature).is_err());
}

#[test]
#[ignore = "regenerates the shared prepared-key fixture"]
fn regenerate_prepared_fixture() {
    std::fs::write(
        "tests/fixtures/sdk-prepared.bin",
        key().prepare().as_bytes(),
    )
    .unwrap();
}
