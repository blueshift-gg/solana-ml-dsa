//! Example consumer: register a compact key, then borrow its prepared form.
//! Account allocation is a preceding top-level System Program instruction.

use solana_account_info::AccountInfo;
use solana_ml_dsa::ml_dsa_44::{PreparedVerifyingKey, SIGNATURE_LEN, Signature, VerifyingKey};
use solana_program_entrypoint::entrypoint;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;

entrypoint!(process_instruction);

const INITIALIZED: &[u8; 8] = b"MLDSA044";

/// Example account header followed by a 4-byte-aligned prepared key.
pub const KEY_ACCOUNT_LEN: usize = INITIALIZED.len() + PreparedVerifyingKey::BYTE_LEN;
/// Domain separator used by this example's signatures.
pub const CONTEXT: &[u8] = b"solana-ml-dsa";

fn process_instruction(id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if account.owner != id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if account.data_len() != KEY_ACCOUNT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let (&tag, data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => create(account, data),
        1 => verify(account, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// [0][public key: 1312 bytes]. The new key account signs registration.
fn create(account: &AccountInfo, data: &[u8]) -> ProgramResult {
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let public_key =
        VerifyingKey::ref_from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut bytes = account.try_borrow_mut_data()?;
    let (header, bytes) = bytes.split_at_mut(INITIALIZED.len());
    if header != [0; 8] {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    let prepared = PreparedVerifyingKey::mut_from_bytes(bytes)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    public_key.prepare_into(prepared);
    header.copy_from_slice(INITIALIZED);
    Ok(())
}

// [1][signature: 2420 bytes][message: remaining bytes]. Read-only account.
fn verify(account: &AccountInfo, data: &[u8]) -> ProgramResult {
    let (signature, message) = data
        .split_first_chunk::<SIGNATURE_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let bytes = account.try_borrow_data()?;
    let (header, bytes) = bytes.split_at(INITIALIZED.len());
    if header != INITIALIZED {
        return Err(ProgramError::UninitializedAccount);
    }
    let prepared = PreparedVerifyingKey::ref_from_bytes(bytes)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    prepared
        .verify_with_context(
            message,
            CONTEXT,
            Signature::ref_from_bytes(signature).unwrap(),
        )
        .map_err(|_| ProgramError::Custom(1))
}
