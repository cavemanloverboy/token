use {
    crate::processor::*,
    pinocchio::{
        account_info::AccountInfo,
        no_allocator, nostd_panic_handler, program_entrypoint,
        program_error::{ProgramError, ToStr},
        pubkey::Pubkey,
        ProgramResult,
    },
    pinocchio_token_interface::{error::TokenError, likely, unlikely_branch},
};

#[doc = r" Program entrypoint."]
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    const ACCOUNT1_HEADER: usize = 0x0008;
    const ACCOUNT1_DATA_LEN: usize = 0x0058;
    const ACCOUNT2_HEADER: usize = 0x2910;
    const ACCOUNT2_DATA_LEN: usize = 0x2960;
    const ACCOUNT3_HEADER: usize = 0x5218;
    const ACCOUNT3_DATA_LEN: usize = 0x5268;
    const INSTRUCTION_DATA_LEN: usize = 0x7a78;

    #[inline]
    fn round_to_next_8(input: u64) -> u64 {
        (input + 7) & (!7)
    }

    // fast path
    if likely(
        // there are 3 accounts (source, dest, auth)
        *input == 3
        // first two accounts have correct token account data length, and 2 and 3 are not dups
        && (*input.add(ACCOUNT1_DATA_LEN).cast::<u64>() == 165)
        && (*input.add(ACCOUNT2_HEADER) == 255)
        && (*input.add(ACCOUNT2_DATA_LEN).cast::<u64>() == 165)
        && (*input.add(ACCOUNT3_HEADER) == 255),
    ) {
        // get account 3 data len and round up to next value of 8
        let account_3_data_len_rounded_up =
            round_to_next_8(*input.add(ACCOUNT3_DATA_LEN).cast::<u64>()) as usize;
        let real_ix_data_len_offset = INSTRUCTION_DATA_LEN + account_3_data_len_rounded_up;

        // now check ix data len
        if likely(input.add(real_ix_data_len_offset).cast::<u64>().read() >= 9) {
            // check for transfer discriminator
            // and if correct read transfer amount
            let disc = input.add(real_ix_data_len_offset + 8).cast::<u8>().read();
            if likely(disc == 3) {
                let accounts = unsafe {
                    [
                        core::mem::transmute::<*mut u8, AccountInfo>(input.add(ACCOUNT1_HEADER)),
                        core::mem::transmute::<*mut u8, AccountInfo>(input.add(ACCOUNT2_HEADER)),
                        core::mem::transmute::<*mut u8, AccountInfo>(input.add(ACCOUNT3_HEADER)),
                    ]
                };
                // we are ok to truncate here. ix only checks that there are at least enough bytes for a u64
                let instruction_data = unsafe {
                    core::slice::from_raw_parts(input.add(real_ix_data_len_offset + 9), 8)
                };
                if let Err(e) = process_transfer(&accounts, instruction_data) {
                    unlikely_branch();
                    return e.into();
                }
                return 0;
            }
        }
    } else {
        // maybe batch transfer
    }

    const UNINIT: core::mem::MaybeUninit<pinocchio::account_info::AccountInfo> =
        core::mem::MaybeUninit::<pinocchio::account_info::AccountInfo>::uninit();
    let mut accounts = [UNINIT; { pinocchio::MAX_TX_ACCOUNTS }];
    let (program_id, count, instruction_data) =
        pinocchio::entrypoint::deserialize::<{ pinocchio::MAX_TX_ACCOUNTS }>(input, &mut accounts);
    match process_instruction(
        &program_id,
        core::slice::from_raw_parts(accounts.as_ptr() as _, count),
        &instruction_data,
    ) {
        Ok(()) => pinocchio::SUCCESS,
        Err(error) => error.into(),
    }
}
// Do not allocate memory.
no_allocator!();
// Use the no_std panic handler.
nostd_panic_handler!();

/// Log an error.
#[cold]
fn log_error(error: &ProgramError) {
    pinocchio::log::sol_log(error.to_str::<TokenError>());
}

/// Process an instruction.
///
/// In the first stage, the entrypoint checks the discriminator of the
/// instruction data to determine whether the instruction is a "batch"
/// instruction or a "regular" instruction. This avoids nesting of "batch"
/// instructions, since it is not sound to have a "batch" instruction inside
/// another "batch" instruction.
#[inline(always)]
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let [discriminator, remaining @ ..] = instruction_data else {
        return Err(TokenError::InvalidInstruction.into());
    };

    let result = if *discriminator == 255 {
        // 255 - Batch
        #[cfg(feature = "logging")]
        pinocchio::msg!("Instruction: Batch");

        process_batch(accounts, remaining)
    } else {
        inner_process_instruction(accounts, instruction_data)
    };

    result.inspect_err(log_error)
}

/// Process a "regular" instruction.
///
/// The processor of the token program is divided into two parts to reduce the
/// overhead of having a large `match` statement. The first part of the
/// processor handles the most common instructions, while the second part
/// handles the remaining instructions.
///
/// The rationale is to reduce the overhead of making multiple comparisons for
/// popular instructions.
///
/// Instructions on the first part of the inner processor:
///
/// - `0`: `InitializeMint`
/// - `1`: `InitializeAccount`
/// - `3`: `Transfer`
/// - `7`: `MintTo`
/// - `9`: `CloseAccount`
/// - `16`: `InitializeAccount2`
/// - `18`: `InitializeAccount3`
/// - `20`: `InitializeMint2`
#[inline(always)]
pub(crate) fn inner_process_instruction(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let [discriminator, instruction_data @ ..] = instruction_data else {
        return Err(TokenError::InvalidInstruction.into());
    };

    match *discriminator {
        // 0 - InitializeMint
        0 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeMint");

            process_initialize_mint(accounts, instruction_data)
        }
        // 1 - InitializeAccount
        1 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeAccount");

            process_initialize_account(accounts)
        }
        // 3 - Transfer
        3 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: Transfer");

            process_transfer(accounts, instruction_data)
        }
        // 7 - MintTo
        7 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: MintTo");

            process_mint_to(accounts, instruction_data)
        }
        // 8 - Burn
        8 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: Burn");

            process_burn(accounts, instruction_data)
        }
        // 9 - CloseAccount
        9 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: CloseAccount");

            process_close_account(accounts)
        }
        // 12 - TransferChecked
        12 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: TransferChecked");

            process_transfer_checked(accounts, instruction_data)
        }
        // 15 - BurnChecked
        15 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: BurnChecked");

            process_burn_checked(accounts, instruction_data)
        }
        // 16 - InitializeAccount2
        16 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeAccount2");

            process_initialize_account2(accounts, instruction_data)
        }
        // 18 - InitializeAccount3
        18 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeAccount3");

            process_initialize_account3(accounts, instruction_data)
        }
        // 20 - InitializeMint2
        20 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeMint2");

            process_initialize_mint2(accounts, instruction_data)
        }
        d => inner_process_remaining_instruction(accounts, instruction_data, d),
    }
}

/// Process a remaining "regular" instruction.
///
/// This function is called by the [`inner_process_instruction`] function if the
/// discriminator does not match any of the common instructions. This function
/// is used to reduce the overhead of having a large `match` statement in the
/// [`inner_process_instruction`] function.
fn inner_process_remaining_instruction(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
    discriminator: u8,
) -> ProgramResult {
    match discriminator {
        // 2 - InitializeMultisig
        2 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeMultisig");

            process_initialize_multisig(accounts, instruction_data)
        }
        // 4 - Approve
        4 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: Approve");

            process_approve(accounts, instruction_data)
        }
        // 5 - Revoke
        5 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: Revoke");

            process_revoke(accounts)
        }
        // 6 - SetAuthority
        6 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: SetAuthority");

            process_set_authority(accounts, instruction_data)
        }
        // 10 - FreezeAccount
        10 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: FreezeAccount");

            process_freeze_account(accounts)
        }
        // 11 - ThawAccount
        11 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: ThawAccount");

            process_thaw_account(accounts)
        }
        // 13 - ApproveChecked
        13 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: ApproveChecked");

            process_approve_checked(accounts, instruction_data)
        }
        // 14 - MintToChecked
        14 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: MintToChecked");

            process_mint_to_checked(accounts, instruction_data)
        }
        // 17 - SyncNative
        17 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: SyncNative");

            process_sync_native(accounts)
        }
        // 19 - InitializeMultisig2
        19 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeMultisig2");

            process_initialize_multisig2(accounts, instruction_data)
        }
        // 21 - GetAccountDataSize
        21 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: GetAccountDataSize");

            process_get_account_data_size(accounts)
        }
        // 22 - InitializeImmutableOwner
        22 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: InitializeImmutableOwner");

            process_initialize_immutable_owner(accounts)
        }
        // 23 - AmountToUiAmount
        23 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: AmountToUiAmount");

            process_amount_to_ui_amount(accounts, instruction_data)
        }
        // 24 - UiAmountToAmount
        24 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: UiAmountToAmount");

            process_ui_amount_to_amount(accounts, instruction_data)
        }
        // 38 - WithdrawExcessLamports
        38 => {
            #[cfg(feature = "logging")]
            pinocchio::msg!("Instruction: WithdrawExcessLamports");

            process_withdraw_excess_lamports(accounts)
        }
        _ => Err(TokenError::InvalidInstruction.into()),
    }
}
