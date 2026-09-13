use fips204::{
    ml_dsa_44,
    traits::{KeyGen, SerDes, Signer},
};
use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::v1;
use solana_ml_dsa::ml_dsa_44::{PUBLIC_KEY_LEN, SIGNATURE_LEN, VerifyingKey};
use solana_ml_dsa_example::{CONTEXT, KEY_ACCOUNT_LEN};
use solana_program_error::ProgramError;
use solana_system_interface::{instruction::create_account, program::ID as SYSTEM_PROGRAM};

const CU_LIMIT: u64 = 1_400_000;

fn mollusk(program: &Address) -> Mollusk {
    // Build with `cargo build-sbf --arch v3 --manifest-path program/Cargo.toml`.
    let directory = std::env::var_os("SBF_OUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/deploy")
        });
    let elf = directory.join("solana_ml_dsa_example");
    let mut svm = Mollusk::new(program, elf.to_str().unwrap());
    svm.compute_budget.compute_unit_limit = CU_LIMIT;
    svm
}

fn transaction_size(payer: &Address, instructions: &[Instruction]) -> usize {
    let message = v1::Message::try_compile_with_config(
        payer,
        instructions,
        Default::default(),
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(CU_LIMIT as u32)
            .with_loaded_accounts_data_size_limit(1_048_576)
            .with_priority_fee(10_000),
    )
    .unwrap();
    // V1 appends exactly one 64-byte signature per required signer.
    let size = message.serialize().len() + usize::from(message.header.num_required_signatures) * 64;
    assert!(size <= 4096, "V1 transaction is {size} bytes");
    size
}

#[test]
fn register_in_one_transaction_then_verify_from_account() {
    let program = Address::new_from_array([1; 32]);
    let payer = Address::new_from_array([2; 32]);
    let key = Address::new_from_array([3; 32]);
    let svm = mollusk(&program);
    let accounts = vec![
        (payer, Account::new(1_000_000_000, 0, &SYSTEM_PROGRAM)),
        (key, Account::default()),
    ];
    // Fixed seeds are test fixtures only; never use these keys for funds.
    let (public_key, secret_key) = ml_dsa_44::KG::keygen_from_seed(&[42; 32]);
    let public_key = VerifyingKey::from_bytes(&(public_key.into_bytes()));
    let message = [7; 32];
    let signature = secret_key
        .try_sign_with_seed(&[0; 32], &message, CONTEXT)
        .unwrap();
    let mut data = vec![0];
    data.extend_from_slice(&public_key.to_bytes());
    let register = Instruction::new_with_bytes(program, &data, vec![AccountMeta::new(key, true)]);
    let instructions = [
        create_account(
            &payer,
            &key,
            svm.sysvars.rent.minimum_balance(KEY_ACCOUNT_LEN),
            KEY_ACCOUNT_LEN as u64,
            &program,
        ),
        register.clone(),
    ];
    let size = transaction_size(&payer, &instructions);
    // This API runs both instructions in ONE transaction context and CU budget.
    let result = svm.process_transaction_instructions(&instructions, &accounts, Some(&payer));
    assert_eq!(result.raw_result, Ok(()));
    assert!(result.compute_units_consumed < CU_LIMIT);
    let stored = &result
        .resulting_accounts
        .iter()
        .find(|(a, _)| a == &key)
        .unwrap()
        .1;
    assert_eq!(stored.owner, program);
    assert_eq!(stored.data.len(), KEY_ACCOUNT_LEN);
    assert_eq!(&stored.data[8..], public_key.prepare().as_bytes());
    println!(
        "registration: {} CUs, {size} V1 bytes",
        result.compute_units_consumed
    );

    // Registration is one-time; a failed replacement leaves the account intact.
    let repeated =
        svm.process_transaction_instructions(&[register], &result.resulting_accounts, Some(&payer));
    assert!(repeated.raw_result.is_err());
    assert_eq!(repeated.resulting_accounts, result.resulting_accounts);

    let mut data = vec![1];
    data.extend_from_slice(&signature);
    data.extend_from_slice(&message);
    let mut verify =
        Instruction::new_with_bytes(program, &data, vec![AccountMeta::new_readonly(key, false)]);
    let size = transaction_size(&payer, std::slice::from_ref(&verify));
    let verified = svm.process_transaction_instructions(
        std::slice::from_ref(&verify),
        &result.resulting_accounts,
        Some(&payer),
    );
    assert_eq!(verified.raw_result, Ok(()));
    assert!(verified.compute_units_consumed < 300_000);
    assert_eq!(verified.resulting_accounts, result.resulting_accounts);
    println!(
        "verification: {} CUs, {size} V1 bytes",
        verified.compute_units_consumed
    );

    *verify.data.last_mut().unwrap() ^= 1;
    let rejected =
        svm.process_transaction_instructions(&[verify], &result.resulting_accounts, Some(&payer));
    assert!(rejected.raw_result.is_err(), "tampered message accepted");
    assert_eq!(rejected.resulting_accounts, result.resulting_accounts);

    // A malformed registration rolls back the preceding System allocation.
    let mut malformed = instructions;
    malformed[1].data.pop();
    let failed = svm.process_transaction_instructions(&malformed, &accounts, Some(&payer));
    assert!(failed.raw_result.is_err());
    assert_eq!(failed.resulting_accounts, accounts);
}

#[test]
fn account_must_be_owned_initialized_and_authorized() {
    let program = Address::new_from_array([1; 32]);
    let key = Address::new_from_array([3; 32]);
    let svm = mollusk(&program);
    for (owner, len, signer, writable, expected) in [
        (
            SYSTEM_PROGRAM,
            KEY_ACCOUNT_LEN,
            true,
            true,
            ProgramError::IncorrectProgramId,
        ),
        (
            program,
            KEY_ACCOUNT_LEN - 1,
            true,
            true,
            ProgramError::InvalidAccountData,
        ),
        (
            program,
            KEY_ACCOUNT_LEN,
            false,
            true,
            ProgramError::MissingRequiredSignature,
        ),
        (
            program,
            KEY_ACCOUNT_LEN,
            true,
            false,
            ProgramError::InvalidAccountData,
        ),
    ] {
        let instruction = Instruction::new_with_bytes(
            program,
            &[0; 1 + PUBLIC_KEY_LEN],
            vec![AccountMeta {
                pubkey: key,
                is_signer: signer,
                is_writable: writable,
            }],
        );
        let account = Account::new(svm.sysvars.rent.minimum_balance(len), len, &owner);
        let result = svm.process_instruction(&instruction, &[(key, account)]);
        assert_eq!(result.program_result, ProgramResult::Failure(expected));
    }

    let mut data = vec![1];
    data.resize(1 + SIGNATURE_LEN, 0);
    let verify =
        Instruction::new_with_bytes(program, &data, vec![AccountMeta::new_readonly(key, false)]);
    let account = Account::new(
        svm.sysvars.rent.minimum_balance(KEY_ACCOUNT_LEN),
        KEY_ACCOUNT_LEN,
        &program,
    );
    let result = svm.process_instruction(&verify, &[(key, account)]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::UninitializedAccount)
    );
}
