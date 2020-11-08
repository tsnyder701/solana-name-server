use byteorder::{ByteOrder, LittleEndian};
use num_derive::FromPrimitive;
use solana_sdk::{
    account_info::next_account_info,
    account_info::AccountInfo,
    decode_error::DecodeError,
    //entrypoint,
    //entrypoint::ProgramResult,
    entrypoint_deprecated,
    entrypoint_deprecated::ProgramResult,
    info,
    program_error::ProgramError,
    program_pack::{Pack, Sealed},
    pubkey::Pubkey,
    rent::Rent,
    sysvar::{self, Sysvar},
    hash::hash,
};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum VoteError {
    #[error("Unexpected Candidate")]
    UnexpectedCandidate,
    #[error("Incorrect Owner")]
    IncorrectOwner,
    #[error("Account Not Rent Exempt")]
    AccountNotRentExempt,
    #[error("Account Not Check Account")]
    AccountNotCheckAccount,
    #[error("Already Voted")]
    AlreadyVoted,
}
impl From<VoteError> for ProgramError {
    fn from(e: VoteError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
impl<T> DecodeError<T> for VoteError {
    fn type_of() -> &'static str {
        "Vote Error"
    }
}

// Instruction data

pub struct Metadata {
    pub acct_id: Pubkey
}

pub struct Vote {
    pub candidate: u8,
}

impl Sealed for Metadata {}

impl Pack for Metadata {
    const LEN: usize = 32;

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        Ok(Metadata {
            acct_id: Pubkey::new(src)
        })
    }

    fn pack_into_slice(&self, dst: &mut [u8]) {
        let key_bytes = self.acct_id.to_bytes();
        dst.clone_from_slice(&key_bytes)
    }
}

impl Sealed for Vote {}

impl Pack for Vote {
    const LEN: usize = 1;

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let candidate = src[0];

        if candidate != 1 && candidate != 2 {
            info!("Vote must be for candidate 1 or 2");
            return Err(VoteError::UnexpectedCandidate.into());
        }
        Ok(Vote { candidate })
    }

    fn pack_into_slice(&self, _dst: &mut [u8]) {}
}

// Vote Check structure, which is one 4 byte u32 number
// contains zero if they havn't voted, or the candidate number if they have

pub struct VoterCheck {
    pub voted_for: u32,
}

impl Sealed for VoterCheck {}

impl Pack for VoterCheck {
    const LEN: usize = 4;

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        Ok(VoterCheck {
            voted_for: LittleEndian::read_u32(&src[0..4]),
        })
    }

    fn pack_into_slice(&self, dst: &mut [u8]) {
        LittleEndian::write_u32(&mut dst[0..4], self.voted_for);
    }
}

// Vote Count structure, which is two 4 byte u32 numbers
// first number is candidate 1's vote count, second number is candidate 2's vote count

pub struct ServerData {
    pub name_count: u32,
}

impl Sealed for ServerData {}

impl Pack for ServerData {
    const LEN: usize = 4;

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        Ok(ServerData {
            name_count: LittleEndian::read_u32(&src[0..4]),
        })
    }

    fn pack_into_slice(&self, dst: &mut [u8]) {
        LittleEndian::write_u32(&mut dst[0..4], self.name_count);
    }
}

// Declare and export the program's entrypoint
entrypoint_deprecated!(process_instruction);

// Program entrypoint's implementation
fn process_instruction(
    program_id: &Pubkey,      // Public key of program account
    accounts: &[AccountInfo], // data accounts
    instruction_data: &[u8],  // string to use for indexed name
) -> ProgramResult {
    info!("Rust program entrypoint");

    // Compute the name hash from the input.
    let name_hash = hash(&instruction_data);

    // Iterating accounts is safer then indexing
    let accounts_iter = &mut accounts.iter();

    // Get the account that holds the count of names
    let server_account = next_account_info(accounts_iter)?;

    // The account must be owned by the program in order to modify its data
    if server_account.owner != program_id {
        info!("Server account not owned by program");
        return Err(VoteError::IncorrectOwner.into());
    }

    // Get the account that checks for existing mapping
    let metadata_account = next_account_info(accounts_iter)?;

    // The metadata account must be owned by the program in order to modify its data
    if metadata_account.owner != program_id {
        info!("Metadata account not owned by program");
        return Err(VoteError::IncorrectOwner.into());
    }

    // The account must be rent exempt, i.e. live forever
    let sysvar_account = next_account_info(accounts_iter)?;
    let rent = &Rent::from_account_info(sysvar_account)?;
    if !sysvar::rent::check_id(sysvar_account.key) {
        info!("Rent system account is not rent system account");
        return Err(ProgramError::InvalidAccountData);
    }
    if !rent.is_exempt(metadata_account.lamports(), metadata_account.data_len()) {
        info!("Check account is not rent exempt");
        return Err(VoteError::AccountNotRentExempt.into());
    }

    // the name target
    let target_account = next_account_info(accounts_iter)?;

    if !target_account.is_signer {
        info!("Target account is not signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let hash_pubkey = Pubkey::new(&name_hash.as_ref());
    let expected_metadata_account_pubkey =
        Pubkey::create_with_seed(&hash_pubkey, "metadata", program_id)?;

    if expected_metadata_account_pubkey != *metadata_account.key {
        info!("Naming violation! Not the correct metadata_account");
        return Err(VoteError::AccountNotCheckAccount.into());
    }

    let mut check_data = metadata_account.try_borrow_mut_data()?;

    // this unpack reads and deserialises the account data and also checks the data is the correct length

    let mut metadata_check =
        Metadata::unpack_unchecked(&check_data).expect("Failed to read VoterCheck");

    if metadata_check.acct_id.as_ref() != [0; 32] {
        info!("Voter fraud! You already voted");
        return Err(VoteError::AlreadyVoted.into());
    }

    // Increment count of names, and record the metadata

    let mut raw_server_data = server_account.try_borrow_mut_data()?;

    let mut server_data =
        ServerData::unpack_unchecked(&raw_server_data).expect("Failed to read ServerData");

    server_data.name_count += 1;

    ServerData::pack(server_data, &mut raw_server_data).expect("Failed to write ServerData");
    Metadata::pack(metadata_check, &mut check_data).expect("Failed to write Metadata");

    Ok(())
}

// Required to support info! in tests
#[cfg(not(target_arch = "bpf"))]
solana_sdk::program_stubs!();
