use crate::treepp::*;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Witness, WitnessProgram,
};
use covenants_gadgets::internal_structures::cpp_int_32::CppInt32Gadget;
use covenants_gadgets::utils::pseudo::{OP_CAT2, OP_CAT3, OP_CAT4};
use covenants_gadgets::wizards::{tap_csv_preimage, tx};

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

/// stack input:
///     [new_counter, prev_counter,..., pubkey, balance|34|pubkey|dust, header]
///
/// stack output:
//      [..., pubkey, prev_counter, balance|34|pubkey|dust, header | new_counter]
pub fn counter_ops() -> Script {
    script! {
        // check new_counter, and save to altstack
        OP_DEPTH OP_1SUB OP_ROLL
        OP_DUP 0 OP_GREATERTHAN OP_VERIFY
        OP_DUP OP_TOALTSTACK

        // check prev_counter, and save to altstack
        OP_DEPTH OP_1SUB OP_ROLL
        OP_DUP 0 OP_GREATERTHAN OP_VERIFY
        OP_DUP OP_TOALTSTACK OP_TOALTSTACK
        { CppInt32Gadget::from_positive_bitcoin_integer() }
        //  [..., pubkey, balance|34|pubkey|dust, header, new_counter] | [new_counter, prev_counter, prev_counter]

        OP_CAT2 OP_FROMALTSTACK OP_SWAP OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
        //  [..., pubkey, prev_counter, balance|34|pubkey|dust, header | new_counter]
    }
}

/// stack input:
///     [A, B]
///
/// stack output:
///     [A | 34_0_32 | B]
pub fn seperator1() -> Script {
    script! {
        OP_PUSHBYTES_3 OP_PUSHBYTES_34 OP_PUSHBYTES_0 OP_PUSHBYTES_32

        OP_SWAP OP_CAT3
    }
}

/// processing prev_txid and prev_balance, consume them all
pub fn step3() -> Script {
    script! {
        // get a hint: previous tx's txid
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 32 OP_EQUALVERIFY

        // save a copy to altstack
        OP_DUP OP_TOALTSTACK

        // require the output index be 0
        { tap_csv_preimage::step8_data_input_part_if_anyonecanpay::step1_outpoint::Step2IndexGadget::from_constant(0) }
        OP_CAT3

        // get a hint: previous tx's amount
        OP_DEPTH OP_1SUB OP_ROLL
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
    }
}

//// process tap leaf, consume it
///
pub fn step4() -> Script {
    script! {
        // get a hint: tap leaf hash
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 32 OP_EQUALVERIFY

        { tap_csv_preimage::step12_ext::Step2KeyVersionGadget::from_constant(0) }
        { tap_csv_preimage::step12_ext::Step3CodeSepPosGadget::no_code_sep_executed() }
        OP_CAT4
    }
}

/// process e[..31], and consume it
pub fn step5() -> Script {
    script! {
        // get a hint: the sha256 without the last byte
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 31 OP_EQUALVERIFY

        OP_DUP { 1 } OP_CAT
        OP_ROT OP_EQUALVERIFY

        OP_FROMALTSTACK OP_SWAP

        OP_PUSHBYTES_2 OP_PUSHBYTES_2 OP_RIGHT
        OP_CAT3

        OP_FROMALTSTACK
        OP_CHECKSIGVERIFY
    }
}

/// process first input's outpoints, consume them all
pub fn step6() -> Script {
    script! {
        { tx::Step1VersionGadget::from_constant(&Version::ONE) }

        // get a hint: first input's outpoint
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 36 OP_EQUALVERIFY

        // get a hint: second input's outpoint
        OP_DEPTH OP_1SUB OP_ROLL
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
    }
}

/// process prev_balance, prev_counter, pubkey
pub fn step7(dust: u64) -> Script {
    script! {
       // get the previous amount
       2 OP_ROLL
       OP_CAT2

       // get the script pub key
       3 OP_ROLL
       OP_PUSHBYTES_1 OP_PUSHBYTES_34 OP_SWAP
       OP_CAT3

       { tx::step5_output::Step1AmountGadget::from_constant(&Amount::from_sat(dust)) }
       OP_CAT2

       // push the script hash header
       OP_PUSHBYTES_2 OP_RETURN OP_PUSHBYTES_8

       3 OP_ROLL

       // extend the actual counter to 4 bytes
       { CppInt32Gadget::from_positive_bitcoin_integer() }
    }
}

///  process ranomizer, consume it
pub fn step8() -> Script {
    script! {
        // get a hint: the randomizer for previous transaction (4 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 4 OP_EQUALVERIFY
        OP_CAT3

        OP_SHA256
    }
}
