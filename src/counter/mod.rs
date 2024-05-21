use crate::SECP256K1_GENERATOR;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::{OP_PUSHBYTES_8, OP_RETURN};
use bitcoin::script::scriptint_vec;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Witness, WitnessProgram,
};
use bitcoin_scriptexec::TxTemplate;
use bitvm::treepp::*;
use covenants_gadgets::internal_structures::cpp_int_32::CppInt32Gadget;
use covenants_gadgets::structures::tagged_hash::{get_hashed_tag, HashTag, TaggedHashGadget};
use covenants_gadgets::utils::pseudo::{OP_CAT2, OP_CAT3, OP_CAT4};
use covenants_gadgets::wizards::{tap_csv_preimage, tx};
use sha2::Digest;
use std::str::FromStr;

const DUST_AMOUNT: u64 = 330;

/// Information necessary to create the new transaction.
pub struct CounterUpdateInfo {
    /// The counter value stored in the previous caboose.
    pub prev_counter: u32,
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

/// Compute the taproot of the script (which only has the script path, but not the key path).
pub fn get_script_pub_key_and_control_block() -> (ScriptBuf, Vec<u8>) {
    // Build the witness program.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let internal_key = UntweakedPublicKey::from(
        bitcoin::secp256k1::PublicKey::from_str(
            "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap(),
    );

    let script = get_script();

    let taproot_builder = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

    let witness_program =
        WitnessProgram::p2tr(&secp, internal_key, taproot_spend_info.merkle_root());

    // Derive the script pub key.
    let script_pub_key = ScriptBuf::new_witness_program(&witness_program);

    // Compute the control block.
    let mut control_block_bytes = Vec::new();
    taproot_spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap()
        .encode(&mut control_block_bytes)
        .unwrap();

    (script_pub_key, control_block_bytes)
}

/// Generate the new transaction and return the new transaction as well as the randomizer
pub fn get_tx(info: &CounterUpdateInfo) -> (TxTemplate, u32) {
    // Compute the script pub key, control block, and tap leaf hash.
    let (script_pub_key, control_block_bytes) = get_script_pub_key_and_control_block();
    let script = get_script();
    let tap_leaf_hash = TapLeafHash::from_script(
        &ScriptBuf::from_bytes(script.to_bytes()),
        LeafVersion::TapScript,
    );

    // Initialize a new transaction.
    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Push the previous program as the first input, with the witness left blank as a placeholder.
    tx.input.push(TxIn {
        previous_output: OutPoint::new(info.prev_txid.clone(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::default(),
        witness: Witness::new(), // placeholder
    });

    // If there is an optional deposit input, include it as well.
    if let Some(input) = &info.optional_deposit_input {
        tx.input.push(input.clone());
    }

    // Push the first output, which is the new program (and the only change is in the balance).
    tx.output.push(TxOut {
        value: Amount::from_sat(info.new_balance),
        script_pubkey: script_pub_key.clone(),
    });

    // Increment the counter by 1, which would give us the new counter.
    let new_counter = info.prev_counter + 1;

    // Start the search of a working randomizer from 0.
    let mut randomizer = 0u32;

    // Initialize a placeholder for e, which is the signature element "e" in Schnorr signature.
    // Finding e relies on trial-and-error. Specifically, e is a tagged hash of the signature preimage,
    // and the signature preimage is calculated by serializing the transaction in a specific way.
    let e;
    loop {
        // Generate the corresponding caboose with the new counter.
        let witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(vec![
            OP_RETURN.to_u8(),
            OP_PUSHBYTES_8.to_u8(),
            (new_counter & 0xff) as u8,
            ((new_counter >> 8) & 0xff) as u8,
            ((new_counter >> 16) & 0xff) as u8,
            ((new_counter >> 24) & 0xff) as u8,
            (randomizer & 0xff) as u8,
            ((randomizer >> 8) & 0xff) as u8,
            ((randomizer >> 16) & 0xff) as u8,
            ((randomizer >> 24) & 0xff) as u8,
        ]));

        // Temporarily insert this output.
        // If this output doesn't work, in a later step, we will revert the insertion and remove this
        // output from the transaction.
        tx.output.push(TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: ScriptBuf::new_witness_program(&witness_program),
        });

        // Initialize the SighashCache object for computing the signature preimage.
        let mut sighashcache = SighashCache::new(tx.clone());

        // Compute the taproot hash assuming AllPlusAnyoneCanPay.
        let hash = sighashcache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::One(
                    0,
                    &TxOut {
                        value: Amount::from_sat(info.prev_balance),
                        script_pubkey: script_pub_key.clone(),
                    },
                ),
                tap_leaf_hash,
                TapSighashType::AllPlusAnyoneCanPay,
            )
            .unwrap()
            .into_32();

        // Compute the tagged hash of the signature preimage.
        let bip340challenge_prefix = get_hashed_tag("BIP0340/challenge");
        let mut sha256 = sha2::Sha256::new();
        Digest::update(&mut sha256, &bip340challenge_prefix);
        Digest::update(&mut sha256, &bip340challenge_prefix);
        Digest::update(&mut sha256, SECP256K1_GENERATOR.as_slice());
        Digest::update(&mut sha256, SECP256K1_GENERATOR.as_slice());
        Digest::update(&mut sha256, hash);
        let e_expected = sha256.finalize().to_vec();

        // If the signature preimage ends with 0x01 (which is consistent to the Schnorr trick),
        // we will accept this randomizer.
        //
        // Note: this is in fact not a strict requirement that it needs to be ending at 0x01.
        // Nevertheless, requiring so makes sure that we can avoid the corner case (ending at 0xff),
        // and it is consistent with the Schnorr trick article.
        if e_expected[31] == 0x01 {
            e = Some(e_expected);
            break;
        } else {
            // Remove the nonfunctional output and retry.
            tx.output.pop().unwrap();
            randomizer += 1;
        }
    }

    // now start preparing the witness
    let mut script_execution_witness = Vec::<Vec<u8>>::new();

    // new balance (8 bytes)
    script_execution_witness.push(info.new_balance.to_le_bytes().to_vec());

    // this script's scriptpubkey (34 bytes)
    script_execution_witness.push(script_pub_key.to_bytes());

    // the actual number (as a Bitcoin integer)
    script_execution_witness.push(scriptint_vec(new_counter as i64));

    // the randomizer (4 bytes)
    script_execution_witness.push(randomizer.to_le_bytes().to_vec());

    // previous tx's txid (32 bytes)
    script_execution_witness.push(AsRef::<[u8]>::as_ref(&info.prev_txid).to_vec());

    // previous balance (8 bytes)
    script_execution_witness.push(info.prev_balance.to_le_bytes().to_vec());

    // tap leaf hash (32 bytes)
    script_execution_witness.push(AsRef::<[u8]>::as_ref(&tap_leaf_hash).to_vec());

    // the sha256 without the last byte (31 bytes)
    script_execution_witness.push(e.unwrap()[0..31].to_vec());

    // the first outpoint (32 + 4 = 36 bytes)
    {
        let mut bytes = vec![];
        info.prev_tx_outpoint1.consensus_encode(&mut bytes).unwrap();

        script_execution_witness.push(bytes);
    }

    // the second outpoint (0 or 36 bytes)
    {
        if info.prev_tx_outpoint2.is_some() {
            let mut bytes = vec![];
            info.prev_tx_outpoint2
                .unwrap()
                .consensus_encode(&mut bytes)
                .unwrap();

            script_execution_witness.push(bytes);
        } else {
            script_execution_witness.push(vec![]);
        }
    }

    // previous randomizer
    script_execution_witness.push(info.prev_randomizer.to_le_bytes().to_vec());

    // Construct the witness that will be included in the TxIn.
    let mut script_tx_witness = Witness::new();
    // all the initial stack elements
    for elem in script_execution_witness.iter() {
        script_tx_witness.push(elem);
    }
    // the full script
    script_tx_witness.push(script);
    // the control block bytes
    script_tx_witness.push(control_block_bytes);

    // Include the witness in the TxIn.
    tx.input[0].witness = script_tx_witness;

    // Prepare the TxTemplate.
    let tx_template = TxTemplate {
        tx,
        prevouts: vec![TxOut {
            value: Amount::from_sat(info.prev_balance),
            script_pubkey: script_pub_key.clone(),
        }],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((tap_leaf_hash.clone(), None)),
    };

    (tx_template, randomizer)
}

pub fn get_script() -> Script {
    // Obtain the secp256k1 dummy generator, which would be point R in the signature, as well as
    // the public key.
    let secp256k1_generator = SECP256K1_GENERATOR.clone();

    script! {
        // For more information about the construction of the Tap CheckSigVerify Preimage, please
        // check out the `covenants` repository.

        { tap_csv_preimage::Step1EpochGadget::default() }
        { tap_csv_preimage::Step2HashTypeGadget::from_constant(&TapSighashType::AllPlusAnyoneCanPay) }
        { tap_csv_preimage::Step3VersionGadget::from_constant(&Version::ONE) }
        { tap_csv_preimage::Step4LockTimeGadget::from_constant_absolute(&LockTime::ZERO) }
        OP_CAT4

        // current stack body: |1-4|

        // first output: the same script itself

        // get a hint: new balance (8 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 8 OP_EQUALVERIFY

        // get a hint: this script's scriptpubkey (34 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 34 OP_EQUALVERIFY

        // save a copy to the altstack
        OP_DUP OP_TOALTSTACK

        OP_PUSHBYTES_1 OP_PUSHBYTES_34
        OP_SWAP OP_CAT3

        OP_FROMALTSTACK OP_SWAP

        // current stack body: |1-4|, this scriptpubkey, |output1|

        // second output: the data carrier

        // the balance must be DUST_AMOUNT
        OP_PUSHBYTES_8 OP_PUSHBYTES_74 OP_PUSHBYTES_1 OP_PUSHBYTES_0 OP_PUSHBYTES_0
        OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
        OP_CAT

        // push the script hash header
        OP_PUSHBYTES_2 OP_RETURN OP_PUSHBYTES_8

        // get a hint: the actual counter value in Bitcoin integer format (<=4 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_1ADD OP_1SUB
        OP_DUP 0 OP_GREATERTHAN OP_VERIFY

        // save the previous number into the altstack for later use
        OP_DUP OP_1SUB OP_TOALTSTACK

        // extend the actual counter to 4 bytes
        { CppInt32Gadget::from_positive_bitcoin_integer() }

        // get a hint: the randomizer for this transaction (4 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
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

        // current stack body: this scriptpubkey, previous counter, previous tx's amount, previous tx's txid, |1-11|

        // get a hint: tap leaf hash
        OP_DEPTH OP_1SUB OP_ROLL
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
        OP_DEPTH OP_1SUB OP_ROLL
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

        // current stack body:
        //   this scriptpubkey, previous counter, previous tx's amount, previous tx's txid
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
        OP_PUSHBYTES_2 OP_RETURN OP_PUSHBYTES_8

        3 OP_ROLL

        // extend the actual counter to 4 bytes
        { CppInt32Gadget::from_positive_bitcoin_integer() }

        // get a hint: the randomizer for previous transaction (4 bytes)
        OP_DEPTH OP_1SUB OP_ROLL
        OP_SIZE 4 OP_EQUALVERIFY
        OP_CAT3

        OP_SHA256

        OP_PUSHBYTES_3 OP_PUSHBYTES_34 OP_PUSHBYTES_0 OP_PUSHBYTES_32
        OP_SWAP OP_CAT3

        { tx::Step6LockTimeGadget::from_constant_absolute(&LockTime::ZERO) }
        OP_CAT2

        OP_SHA256
        OP_SHA256

        OP_EQUAL
    }
}

#[cfg(test)]
mod test {
    use crate::counter::{get_script, get_script_pub_key_and_control_block, get_tx, CounterUpdateInfo, DUST_AMOUNT};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::{Hash, sha256d};
    use bitcoin::opcodes::all::{OP_PUSHBYTES_8, OP_RETURN};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WScriptHash,
        Witness, WitnessProgram,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options};
    use bitcoin_simulator::database::Database;
    use bitvm::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use std::cell::RefCell;
    use std::rc::Rc;
    use bitcoin::consensus::{Decodable, Encodable};

    #[test]
    fn test_script_execution() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // compute a random txid, counter, and randomizer for testing purposes only.
        let mut random_txid_preimage = [0u8; 20];
        prng.fill_bytes(&mut random_txid_preimage);
        let prev_counter = 123;
        let prev_randomizer = 45678;

        let prev_witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(vec![
            OP_RETURN.to_u8(),
            OP_PUSHBYTES_8.to_u8(),
            (prev_counter & 0xff) as u8,
            ((prev_counter >> 8) & 0xff) as u8,
            ((prev_counter >> 16) & 0xff) as u8,
            ((prev_counter >> 24) & 0xff) as u8,
            (prev_randomizer & 0xff) as u8,
            ((prev_randomizer >> 8) & 0xff) as u8,
            ((prev_randomizer >> 16) & 0xff) as u8,
            ((prev_randomizer >> 24) & 0xff) as u8,
        ]));

        // Perform the testing with a single input or with two inputs.
        for input_num in 1..=2 {
            let mut prev_tx = Transaction {
                version: Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::hash(&random_txid_preimage),
                        vout: 15,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::default(),
                    witness: Witness::new(),
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(123456),
                        script_pubkey: get_script_pub_key_and_control_block().0,
                    },
                    TxOut {
                        value: Amount::from_sat(DUST_AMOUNT),
                        script_pubkey: ScriptBuf::new_witness_program(&prev_witness_program),
                    },
                ],
            };

            if input_num == 2 {
                let mut random_txid_preimage = [0u8; 20];
                prng.fill_bytes(&mut random_txid_preimage);

                prev_tx.input.push(TxIn {
                    previous_output: OutPoint {
                        txid: Txid::hash(&random_txid_preimage),
                        vout: 423,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::default(),
                    witness: Witness::new(),
                })
            }

            let info = CounterUpdateInfo {
                prev_counter,
                prev_randomizer,
                prev_balance: prev_tx.output[0].value.to_sat(),
                prev_txid: prev_tx.compute_txid(),
                prev_tx_outpoint1: prev_tx.input[0].previous_output.clone(),
                prev_tx_outpoint2: prev_tx
                    .input
                    .get(1)
                    .and_then(|x| Some(x.previous_output.clone())),
                optional_deposit_input: None,
                new_balance: 78910,
            };

            // Construct the transaction.
            let (tx_template, _) = get_tx(&info);
            let witness = &tx_template.tx.input[0].witness;

            // Simulate the script execution by pre-appending all the initial witness elements.
            let mut script_buf = script! {
                for entry in witness.iter().take(witness.len() - 2) {
                    { entry.to_vec() }
                }
            }
            .to_bytes();
            let script_body = get_script();

            if input_num == 1 {
                println!("counter.len = {} bytes", script_body.len());
            }

            // Copy the full script.
            script_buf.extend_from_slice(script_body.as_bytes());

            // Run the script by emulating its execution environment.
            let script = Script::from_bytes(script_buf);
            let mut exec = Exec::new(
                ExecCtx::Tapscript,
                Options::default(),
                tx_template,
                script,
                vec![],
            )
            .expect("error creating exec");

            loop {
                if exec.exec_next().is_err() {
                    break;
                }
            }
            let res = exec.result().unwrap();
            assert!(res.success);
        }
    }

    #[test]
    fn test_simulation() {
        let prng = Rc::new(RefCell::new(ChaCha20Rng::seed_from_u64(0)));
        let get_rand_txid = || {
            let mut bytes = [0u8; 20];
            prng.borrow_mut().fill_bytes(&mut bytes);
            Txid::hash(&bytes)
        };

        let db = Database::connect_temporary_database().unwrap();

        let (script_pub_key, _) = get_script_pub_key_and_control_block();

        // initialize the counter and accept it unconditionally
        let init_tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: get_rand_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::default(),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1_000_000_000),
                    script_pubkey: script_pub_key.clone(),
                },
                TxOut {
                    value: Amount::from_sat(DUST_AMOUNT),
                    script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::hash(&[
                        OP_RETURN.to_u8(),
                        OP_PUSHBYTES_8.to_u8(),
                        0,
                        0,
                        0,
                        0,
                        12, // 12 is for testing purposes.
                        0,
                        0,
                        0,
                    ])),
                },
            ],
        };

        // Ignore whether the TxIn is valid, make the outputs available in the network.
        db.insert_transaction_unconditionally(&init_tx).unwrap();

        // Prepare the trivial script, which is used for testing purposes to deposit more money
        // into the program.
        let trivial_p2wsh_script = script! {
            OP_TRUE
        };

        let trivial_p2wsh_script_pubkey =
            ScriptBuf::new_p2wsh(&WScriptHash::hash(trivial_p2wsh_script.as_bytes()));

        let mut trivial_p2wsh_witness = Witness::new();
        trivial_p2wsh_witness.push([]);
        trivial_p2wsh_witness.push(trivial_p2wsh_script);

        // Initialize the state.
        let mut prev_counter = 0u32;
        let mut prev_randomizer = 12u32;
        let mut prev_balance = 1_000_000_000u64;
        let mut prev_txid = init_tx.compute_txid();

        let mut prev_tx_outpoint1 = init_tx.input[0].previous_output;
        let mut prev_tx_outpoint2 = None;

        for _ in 0..100 {
            let has_deposit_input = prng.borrow_mut().gen::<bool>();

            // If there is a deposit input
            let deposit_input = if has_deposit_input {
                let fee_tx = Transaction {
                    version: Version::ONE,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid: get_rand_txid(),
                            vout: 0xffffffffu32,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::default(),
                        witness: Witness::new(),
                    }], // a random input is needed to avoid TXID collision.
                    output: vec![TxOut {
                        value: Amount::from_sat(123_456_000),
                        script_pubkey: trivial_p2wsh_script_pubkey.clone(),
                    }],
                };

                db.insert_transaction_unconditionally(&fee_tx).unwrap();

                Some(TxIn {
                    previous_output: OutPoint {
                        txid: fee_tx.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::default(),
                    witness: trivial_p2wsh_witness.clone(),
                })
            } else {
                None
            };

            let mut new_balance = prev_balance;
            if deposit_input.is_some() {
                new_balance += 123_456_000;
            }
            new_balance -= 500; // as for transaction fee
            new_balance -= DUST_AMOUNT;

            let info = CounterUpdateInfo {
                prev_counter,
                prev_randomizer,
                prev_balance,
                prev_txid: prev_txid.clone(),
                prev_tx_outpoint1: prev_tx_outpoint1.clone(),
                prev_tx_outpoint2: prev_tx_outpoint2.clone(),
                optional_deposit_input: deposit_input,
                new_balance,
            };

            let (tx_template, randomizer) = get_tx(&info);

            // Check if the new transaction conforms to the requirement.
            // If so, insert this transaction unconditionally.
            assert!(db.verify_transaction(&tx_template.tx).is_ok());
            db.insert_transaction_unconditionally(&tx_template.tx)
                .unwrap();

            // Update the local state.
            prev_counter += 1;
            prev_randomizer = randomizer;
            prev_balance = new_balance;
            prev_txid = tx_template.tx.compute_txid();

            prev_tx_outpoint1 = tx_template.tx.input[0].previous_output;
            prev_tx_outpoint2 = tx_template
                .tx
                .input
                .get(1)
                .and_then(|x| Some(x.previous_output.clone()));
        }
    }

    #[test]
    fn test_consistency() {
        let tx1_data = "020000000001019acf43ed7f5a246ddd41594089c4a0f157b443512ea5844a243852257d05f5710000000000fdffffff028813000000000000160014f11c424c8130fa440d4a0302e6a06c0e6d741ab205d10e00000000001600147ec82fa13b7ba313b4cc4ea67812e9c11f4f960902473044022012fc1f00b48b14143fa8779e15859a88a4e67f25b4b1d960bee8fd2edade483802203c21c771793677fc1e4439857b1dd40cfea6870dba60c8c49a465b97e3ce6045012103cd33798d7aa483b259f3ba8996a65f62c04a39b15c4b3d0234674fe82dd240aeafff0200";
        let tx2_data = "01000000000101d4b0610c3363351b60993bc76d12fbb4afa68a132483c496444f1827053192750000000000ffffffff02941100000000000022512022d49e6696cb33db2d6b5d8c44b4dfd0c7e5c701bb8d4d23d9e81eca928310f14a010000000000002200202775ad76ba4cd805e2b41b9ef18c644904debd8fb19dbb50e7db061f85e2d5dd024730440220226e2b0c70c5c8895a29ced195c930631fcc3f8a398e2cdd860c5e43fdd71e7902202be9c113b6729eef19254906ea014fdbe9c522188afd3f87cb0cf8ec8196d7d801210385cabf57efd22267de723e80aac89c06136b058648ee5d4225746c695bc829d500000000";

        let tx1 = {
            let bytes = hex::decode(tx1_data).unwrap();
            Transaction::consensus_decode(&mut bytes.as_slice()).unwrap()
        };

        let tx2 = {
            let bytes = hex::decode(tx2_data).unwrap();
            Transaction::consensus_decode(&mut bytes.as_slice()).unwrap()
        };

        let db = Database::connect_temporary_database().unwrap();
        db.insert_transaction_unconditionally(&tx1).unwrap();

        assert!(db.verify_transaction(&tx2).is_ok());
        db.insert_transaction_unconditionally(&tx2).unwrap();

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hex::decode("68e2d729431eae48ff8deda8b2437b80dfba1973d834ef25a7c9e84dcb772231").unwrap());
        txid.reverse();

        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&hex::decode("7592310527184f4496c48324138aa6afb4fb126dc73b99601b3563330c61b0d4").unwrap());
        prev_txid.reverse();

        let prev_counter = 0;
        let prev_randomizer = 12;
        let prev_balance = 4500;
        let new_balance = 4500 - DUST_AMOUNT - 3000;

        let info = CounterUpdateInfo {
            prev_counter,
            prev_randomizer,
            prev_balance,
            prev_txid: Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&txid)),
            prev_tx_outpoint1: OutPoint {
                txid: Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&prev_txid)),
                vout: 0,
            },
            prev_tx_outpoint2: None,
            optional_deposit_input: None,
            new_balance,
        };

        let (tx_template, randomizer) = get_tx(&info);

        let tx = tx_template.tx;

        let mut bytes = vec![];
        tx.consensus_encode(&mut bytes).unwrap();

        println!("tx: {}", hex::encode(bytes.clone()));
        println!("randomizer: {}", randomizer);
        println!("tx length: {}", bytes.len());

        db.verify_transaction(&tx).unwrap();
        db.insert_transaction_unconditionally(&tx).unwrap();
    }
}
