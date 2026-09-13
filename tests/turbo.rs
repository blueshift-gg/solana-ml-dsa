use sha3::digest::{ExtendableOutput, Update, XofReader};
use solana_ml_dsa::ml_dsa_44::{Error, PreparedVerifyingKey, Signature, VerifyingKey};

// Generated independently by the patched Noble signer in fixtures/turbo.mjs.
const PUBLIC_KEY: &[u8; 1312] = include_bytes!("fixtures/turbo.pk");
const SIGNATURE: &[u8; 2420] = include_bytes!("fixtures/turbo.sig");
const MESSAGE: &[u8; 32] = &[7; 32];
const CONTEXT: &[u8] = b"solana-ml-dsa";
static PREPARED: PreparedVerifyingKey<true> = {
    let mut key = PreparedVerifyingKey::<true>::ZERO;
    VerifyingKey::<true>::from_bytes(PUBLIC_KEY).prepare_into(&mut key);
    key
};

fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = sha3::TurboShake256::from_core(sha3::TurboShake256Core::new(0x1f));
    for part in parts {
        hash.update(part);
    }
    let mut output = [0; 64];
    hash.finalize_xof().read(&mut output);
    output
}

#[test]
fn noble_signature_verifies_through_every_key_path() {
    let key = VerifyingKey::<true>::from_bytes(PUBLIC_KEY);
    let signature = Signature::from_bytes(SIGNATURE);
    let prepared = key.prepare();
    assert_eq!(prepared.as_bytes(), PREPARED.as_bytes());
    assert_eq!(key.public_key_hash(), hash(&[PUBLIC_KEY]));
    let m_prime = [b"\x00\x0d", CONTEXT, MESSAGE].concat();
    let mu = hash(&[&key.public_key_hash(), &m_prime]);
    assert_eq!(
        key.verify_with_context(MESSAGE, CONTEXT, &signature),
        Ok(())
    );
    assert_eq!(key.verify_internal(&m_prime, &signature), Ok(()));
    assert_eq!(key.verify_mu(&mu, &signature), Ok(()));
    assert_eq!(
        prepared.verify_with_context(MESSAGE, CONTEXT, &signature),
        Ok(())
    );
    assert_eq!(prepared.verify_internal(&m_prime, &signature), Ok(()));
    assert_eq!(prepared.verify_mu(&mu, &signature), Ok(()));

    let decoded = PreparedVerifyingKey::<true>::from_bytes(prepared.as_bytes()).unwrap();
    let borrowed = PreparedVerifyingKey::<true>::ref_from_bytes(prepared.as_bytes()).unwrap();
    assert_eq!(decoded.as_bytes(), borrowed.as_bytes());
    assert_eq!(
        borrowed.verify_with_context(MESSAGE, CONTEXT, &signature),
        Ok(())
    );
    for i in 0..4 {
        let mut row = [[0; 5]; 256];
        key.prepare_row_into(i, &mut row).unwrap();
        assert_eq!(prepared.row(i), Some(&row));
    }
}

#[test]
fn rejects_the_wrong_mode_or_transcript() {
    use fips204::traits::{KeyGen, SerDes, Signer};

    let (public_key, secret_key) = fips204::ml_dsa_44::KG::keygen_from_seed(&[42; 32]);
    let key = VerifyingKey::<true>::from_bytes(&public_key.into_bytes());
    let signature = Signature::from_bytes(
        &secret_key
            .try_sign_with_seed(&[0; 32], MESSAGE, CONTEXT)
            .unwrap(),
    );
    assert_eq!(
        key.verify_with_context(MESSAGE, CONTEXT, &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        key.prepare()
            .verify_with_context(MESSAGE, CONTEXT, &signature),
        Err(Error::InvalidSignature)
    );

    let standard = VerifyingKey::<false>::from_bytes(PUBLIC_KEY);
    let signature = Signature::from_bytes(SIGNATURE);
    assert_eq!(
        standard.verify_with_context(MESSAGE, CONTEXT, &signature),
        Err(Error::InvalidSignature)
    );
    assert_eq!(
        standard
            .prepare()
            .verify_with_context(MESSAGE, CONTEXT, &signature),
        Err(Error::InvalidSignature)
    );
    let key = VerifyingKey::<true>::from_bytes(PUBLIC_KEY);
    for (message, context) in [
        (&[8; 32][..], CONTEXT),
        (&MESSAGE[..], b"wrong"),
        (&MESSAGE[..], b""),
    ] {
        assert_eq!(
            key.verify_with_context(message, context, &signature),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            PREPARED.verify_with_context(message, context, &signature),
            Err(Error::InvalidSignature)
        );
    }
    for index in [0, 32, 2419] {
        let mut bytes = *SIGNATURE;
        bytes[index] ^= 1;
        let signature = Signature::from_bytes(&bytes);
        assert_eq!(
            key.verify_with_context(MESSAGE, CONTEXT, &signature),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            PREPARED.verify_with_context(MESSAGE, CONTEXT, &signature),
            Err(Error::InvalidSignature)
        );
    }
}
