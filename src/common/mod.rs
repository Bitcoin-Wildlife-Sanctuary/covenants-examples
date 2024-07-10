use crate::treepp::pushable::Pushable;
use crate::treepp::*;
use crate::SECP256K1_GENERATOR;
use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Sequence, TapSighashType, TxIn, Txid};
use covenants_gadgets::structures::tagged_hash::{HashTag, TaggedHashGadget};
use covenants_gadgets::utils::pseudo::{OP_CAT2, OP_CAT3, OP_CAT4, OP_HINT};
use covenants_gadgets::wizards::{tap_csv_preimage, tx};
use std::collections::BTreeMap;

/// Covenant header, which consists of a program counter and an application-specific state hash.
pub struct CovenantHeader {
    /// Program counter.
    pub pc: usize,
    /// State hash.
    pub state_hash: Vec<u8>,
}

/// Trait for covenants
pub trait CovenantProgram {
    type State: Pushable + Clone;

    fn new() -> Self::State;
    fn get_header(state: &Self::State) -> CovenantHeader;
    fn get_all_scripts() -> BTreeMap<usize, Script>;
    fn run(old_state: &Self::State) -> Result<Self::State>;
}

/// Information necessary to create the new transaction.
pub struct CovenantHints {
    /// The randomizer used in the previous caboose (for the Schnorr trick to work).
    pub prev_randomizer: u32,
    /// The balance of the previous program.
    pub prev_balance: u64,
    /// The txid of the previous program.
    pub prev_txid: Txid,

    /// The first input's outpoint of the transaction with txid.
    pub prev_tx_outpoint1: OutPoint,
    /// The second input's outpoint of the transaction with txid.
    /// Note: the second input is optional.
    pub prev_tx_outpoint2: Option<OutPoint>,

    /// The second input in the new transaction, used to deposit more money into the program.
    /// Note: The witness must be provided for this input.
    pub optional_deposit_input: Option<TxIn>,

    /// The balance of the new program, which needs to be smaller than the old balance plus the deposit,
    /// but does not need to equal (some sats will be used to cover the transaction fee).
    pub new_balance: u64,
}

/// stack output:
///     [..., csv_preimage]
pub fn step1() -> Script {
    script! {
        // For more information about the construction of the Tap CheckSigVerify Preimage, please
        // check out the `covenants-gadgets` repository.

        { tap_csv_preimage::Step1EpochGadget::default() }
        { tap_csv_preimage::Step2HashTypeGadget::from_constant(&TapSighashType::AllPlusAnyoneCanPay) }
        { tap_csv_preimage::Step3VersionGadget::from_constant(&Version::ONE) }
        { tap_csv_preimage::Step4LockTimeGadget::from_constant_absolute(&LockTime::ZERO) }
        OP_CAT4
    }
}

/// process new_balance and pubkey, consume new_balance
/// stack input:
///     [new_balance, pubkey,..., csv_preimage]
///
/// stack output:
///     [..., csv_preimage, pubkey, new_balance| 34 | pubkey | DUST_AMOUNT]
pub fn step2() -> Script {
    script! {
        // get a hint: new balance (8 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 8 OP_EQUALVERIFY

        // get a hint: this script's scriptpubkey (34 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 34 OP_EQUALVERIFY

        // save pubkey to the altstack
        OP_DUP OP_TOALTSTACK

        OP_PUSHBYTES_1 OP_PUSHBYTES_34
        OP_SWAP OP_CAT3

        OP_FROMALTSTACK OP_SWAP

        // CAT dust amount
        OP_PUSHBYTES_8 OP_PUSHBYTES_74 OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_PUSHBYTES_0
        OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
        OP_CAT
    }
}

pub fn covenant() -> Script {
    // Obtain the secp256k1 dummy generator, which would be point R in the signature, as well as
    // the public key.
    let secp256k1_generator = SECP256K1_GENERATOR.clone();
    script! {
        // csv_preimage
        step1
        // [..., csv_preimage]

        // new_balance| 34 | pubkey | DUST_AMOUNT
        step2
        // [..., csv_preimage, pubkey, new_balance| 34 | pubkey | DUST_AMOUNT]

        // script hash header
        OP_PUSHBYTES_2 OP_RETURN OP_PUSHBYTES_36
        // [..., csv_preimage, pubkey, new_balance| 34 | pubkey | DUST_AMOUNT, header]

        // get a hint: the new PC+state hash value
        OP_HINT
        OP_SIZE 32 OP_EQUALVERIFY
        // save the new PC+state hash to the altstack
        OP_DUP OP_TOALTSTACK

        // get a hint: the old PC+state hash value
        OP_HINT
        OP_SIZE 32 OP_EQUALVERIFY
        // save the previous PC+state into the altstack for later use
        OP_DUP OP_TOALTSTACK
        OP_TOALTSTACK

        // get a hint: the randomizer for this transaction (4 bytes)
        OP_HINT
        OP_SIZE 4 OP_EQUALVERIFY
        OP_CAT3

        OP_SHA256

        OP_PUSHBYTES_3 OP_PUSHBYTES_34 OP_PUSHBYTES_0 OP_PUSHBYTES_32
        OP_SWAP OP_CAT3

        OP_SHA256
        OP_ROT OP_SWAP OP_CAT2

        OP_FROMALTSTACK OP_SWAP

        { tap_csv_preimage::Step7SpendTypeGadget::from_constant(1, false) } OP_CAT2

        // current stack body: this scriptpubkey, previous counter, |1-7|

        // get a hint: previous tx's txid
        OP_HINT
        OP_SIZE 32 OP_EQUALVERIFY

        // save a copy to altstack
        OP_DUP OP_TOALTSTACK

        // require the output index be 0
        { tap_csv_preimage::step8_data_input_part_if_anyonecanpay::step1_outpoint::Step2IndexGadget::from_constant(0) }
        OP_CAT3

        // get a hint: previous tx's amount
        OP_HINT
        OP_SIZE 8 OP_EQUALVERIFY
        OP_DUP OP_TOALTSTACK
        OP_CAT2

        // add the script pub key
        2 OP_PICK
        OP_PUSHBYTES_1 OP_PUSHBYTES_34 OP_SWAP
        OP_CAT3

        // require the input sequence number be 0xffffffff
        { tap_csv_preimage::step8_data_input_part_if_anyonecanpay::Step4SequenceGadget::from_constant(&Sequence::default()) }
        OP_CAT2

        OP_FROMALTSTACK OP_SWAP
        OP_FROMALTSTACK OP_SWAP

        // current stack body: this scriptpubkey, previous counter, previous tx's amount, previous tx's txid, |1-11|

        // get a hint: tap leaf hash
        OP_HINT
        OP_SIZE 32 OP_EQUALVERIFY

        { tap_csv_preimage::step12_ext::Step2KeyVersionGadget::from_constant(0) }
        { tap_csv_preimage::step12_ext::Step3CodeSepPosGadget::no_code_sep_executed() }
        OP_CAT4

        // current stack body: this scriptpubkey, previous counter, previous tx's amount, previous tx's txid, this script's checksighash preimage
        { TaggedHashGadget::from_provided(&HashTag::TapSighash) }

        { secp256k1_generator.clone() }
        OP_DUP OP_TOALTSTACK
        OP_DUP OP_TOALTSTACK

        OP_DUP OP_ROT OP_CAT3

        { TaggedHashGadget::from_provided(&HashTag::BIP340Challenge) }

        // get a hint: the sha256 without the last byte
        OP_HINT
        OP_SIZE 31 OP_EQUALVERIFY

        OP_DUP { 1 } OP_CAT
        OP_ROT OP_EQUALVERIFY

        // current stack body:
        //   this scriptpubkey, previous counter, previous tx's amount, previous tx's txid,
        //   prefix

        OP_FROMALTSTACK OP_SWAP

        OP_PUSHBYTES_2 OP_PUSHBYTES_2 OP_RIGHT
        OP_CAT3

        OP_FROMALTSTACK
        OP_CHECKSIGVERIFY

        // current stack body:
        //   this scriptpubkey, previous counter, previous tx's amount, previous tx's txid

        { tx::Step1VersionGadget::from_constant(&Version::ONE) }

        // get a hint: first input's outpoint
        OP_HINT
        OP_SIZE 36 OP_EQUALVERIFY

        // get a hint: second input's outpoint
        OP_HINT
        OP_SIZE 0 OP_EQUAL OP_TOALTSTACK
        OP_SIZE 36 OP_EQUAL OP_FROMALTSTACK OP_BOOLOR OP_VERIFY

        OP_SIZE 0 OP_EQUAL
        OP_IF
            OP_DROP
            OP_PUSHBYTES_5 OP_PUSHBYTES_0 OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE
            OP_CAT
            { tx::Step2InCounterGadget::from_constant(1) }
            OP_SWAP OP_CAT
        OP_ELSE
            OP_TOALTSTACK
            OP_PUSHBYTES_5 OP_PUSHBYTES_0 OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE OP_INVALIDOPCODE
            OP_DUP
            OP_FROMALTSTACK OP_SWAP
            OP_CAT4
            { tx::Step2InCounterGadget::from_constant(2) }
            OP_SWAP OP_CAT
        OP_ENDIF
        OP_CAT2

        { tx::Step4OutCounterGadget::from_constant(2) }
        OP_CAT2

        // current stack body:
        //   this scriptpubkey, previous hash, previous tx's amount, previous tx's txid
        //   txid preimage (1-4)

        // get the previous amount
        2 OP_ROLL
        OP_CAT2

        // get the script pub key
        3 OP_ROLL
        OP_PUSHBYTES_1 OP_PUSHBYTES_34 OP_SWAP
        OP_CAT3

        { tx::step5_output::Step1AmountGadget::from_constant(&Amount::from_sat(DUST_AMOUNT)) }
        OP_CAT2

        // push the script hash header
        OP_PUSHBYTES_2 OP_RETURN OP_PUSHBYTES_36
        3 OP_ROLL

        // get a hint: the randomizer for previous transaction (4 bytes)
        OP_HINT
        OP_SIZE 4 OP_EQUALVERIFY
        OP_CAT3
        OP_SHA256

        OP_PUSHBYTES_3 OP_PUSHBYTES_34 OP_PUSHBYTES_0 OP_PUSHBYTES_32
        OP_SWAP OP_CAT3

        { tx::Step6LockTimeGadget::from_constant_absolute(&LockTime::ZERO) }
        OP_CAT2

        OP_SHA256
        OP_SHA256
        OP_EQUALVERIFY

        OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

pub const DUST_AMOUNT: u64 = 330;
