// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Utreexo-based Bitcoin transaction mempool.
//!
//! This crate provides a transaction mempool implementation specifically designed for
//! [Utreexo](https://eprint.iacr.org/2019/611.pdf) nodes. Unlike traditional Bitcoin nodes
//! that maintain a complete UTXO set, Utreexo nodes use a compact cryptographic accumulator
//! to verify transaction validity, significantly reducing storage requirements.
//!
//! # Overview
//!
//! The mempool serves as a holding area for unconfirmed transactions, performing several
//! critical functions:
//!
//! - **Transaction validation**: Verifies Utreexo inclusion proofs for transaction inputs
//! - **Proof management**: Maintains a local accumulator to generate proofs for relay and mining
//! - **Block template construction**: Assembles candidate blocks for miners
//! - **Transaction relay**: Tracks which transactions to broadcast to peers

// cargo docs customization
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/249173822")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/getfloresta/floresta-media/master/logo_png/Icon-Green(main).png"
)]

pub mod mempool;

pub use mempool::Mempool;

use core::error::Error;
use core::fmt;
use core::fmt::Display;
use core::fmt::Formatter;

use floresta_chain::BlockchainError;

/// Errors that can occur when a transaction is submitted to the mempool.
///
/// Variants cover both the policy checks that are currently enforced and stubs
/// for checks that will be enforced in the future. Each variant maps to a
/// distinct rejection reason that can be surfaced to callers of
/// `sendrawtransaction` or any other code path that feeds into
/// [`Mempool::accept_to_mempool`].
#[derive(Debug)]
pub enum MempoolError {
    /// The transaction's fee rate is below the mempool's minimum.
    ///
    /// Currently a stub — returns `Ok(())` — but will enforce a configurable
    /// minimum fee rate once policy logic is implemented.
    FeeTooLow,

    /// The transaction's weight exceeds the maximum allowed per-transaction
    /// weight (`MAX_STANDARD_TX_WEIGHT` in Bitcoin Core).
    ///
    /// Currently a stub — returns `Ok(())`.
    ExceedsMaxWeight,

    /// The transaction does not meet standardness requirements (e.g. unknown
    /// script types, bare multisig, excessive output count, …).
    ///
    /// Currently a stub — returns `Ok(())`.
    NonStandard,

    /// One or more of the transaction's inputs contains a `scriptSig` that
    /// exceeds the maximum allowed size (`MAX_SCRIPT_SIG_SIZE`).
    ///
    /// Currently a stub — returns `Ok(())`.
    ExceedsScriptSigSize,

    /// The transaction is already present in the mempool.
    ///
    /// Previously this was silently swallowed with `Ok(())`; it is now
    /// surfaced as an explicit error so callers can distinguish between
    /// "successfully added" and "already known".
    AlreadyKnown,

    /// The mempool has reached its maximum memory budget.
    MemoryUsageTooHigh,

    /// The transaction conflicts with an existing mempool transaction (i.e.
    /// another mempool transaction already spends one of its inputs).
    ConflictingTransaction,

    /// The transaction spends the same input more than once within itself.
    DuplicatedInputs,

    /// The transaction failed context-free consensus validation.
    // TODO(davidson): we might want to make an error type specific for consensus,
    // instead of reusing BlockchainError.
    Consensus(BlockchainError),
}

impl Display for MempoolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            MempoolError::FeeTooLow => write!(f, "transaction fee rate is too low"),
            MempoolError::ExceedsMaxWeight => {
                write!(f, "transaction weight exceeds the maximum allowed")
            }
            MempoolError::NonStandard => {
                write!(f, "transaction does not meet standardness requirements")
            }
            MempoolError::ExceedsScriptSigSize => {
                write!(f, "transaction scriptSig exceeds the maximum allowed size")
            }
            MempoolError::AlreadyKnown => write!(f, "transaction is already in the mempool"),
            MempoolError::MemoryUsageTooHigh => write!(f, "we are running out of memory"),
            MempoolError::ConflictingTransaction => {
                write!(f, "we have another transaction that spends the same input")
            }
            MempoolError::DuplicatedInputs => {
                write!(f, "this transaction has duplicated inputs")
            }
            MempoolError::Consensus(e) => {
                write!(f, "the transaction failed consensus validation: {e}")
            }
        }
    }
}

impl Error for MempoolError {}
