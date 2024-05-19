use crate::SECP256K1_GENERATOR;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::OP_RETURN;
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

pub struct Information {
    pub prev_counter: u32,
    pub prev_randomizer: u32,
    pub prev_balance: u64,
    pub prev_txid: Txid,

    pub prev_tx_outpoint1: OutPoint,
    pub prev_tx_outpoint2: Option<OutPoint>,

    pub fee_paying_input: Option<TxIn>,

    pub new_balance: u64,
}

// structure:
//
// input:
//   this program
//   another paying input
//
// output:
//   this program (copy)
//   new state: OP_RETURN (4 bytes for the counter value) (4 bytes for randomness)

pub fn get_taproot() -> ScriptBuf {
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

    let script_pub_key = ScriptBuf::new_witness_program(&witness_program);
    script_pub_key
}

pub fn get_tx(information: &Information) -> (TxTemplate, u32) {
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

    let tap_leaf_hash = TapLeafHash::from_script(
        &ScriptBuf::from_bytes(script.to_bytes()),
        LeafVersion::TapScript,
    );

    let mut control_block_bytes = Vec::new();
    taproot_spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap()
        .encode(&mut control_block_bytes)
        .unwrap();

    let script_pub_key = ScriptBuf::new_witness_program(&witness_program);

    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    tx.input.push(TxIn {
        previous_output: OutPoint::new(information.prev_txid.clone(), 0),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::default(),
        witness: Witness::new(), // placeholder
    });

    if let Some(input) = &information.fee_paying_input {
        tx.input.push(input.clone());
    }

    tx.output.push(TxOut {
        value: Amount::from_sat(information.new_balance),
        script_pubkey: script_pub_key.clone(),
    });

    let new_counter = information.prev_counter + 1;

    let mut randomizer = 0u32;

    let e;
    loop {
        let witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(vec![
            OP_RETURN.to_u8(),
            (new_counter & 0xff) as u8,
            ((new_counter >> 8) & 0xff) as u8,
            ((new_counter >> 16) & 0xff) as u8,
            ((new_counter >> 24) & 0xff) as u8,
            (randomizer & 0xff) as u8,
            ((randomizer >> 8) & 0xff) as u8,
            ((randomizer >> 16) & 0xff) as u8,
            ((randomizer >> 24) & 0xff) as u8,
        ]));

        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_witness_program(&witness_program),
        });

        let mut sighashcache = SighashCache::new(tx.clone());

        let hash = sighashcache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::One(
                    0,
                    &TxOut {
                        value: Amount::from_sat(information.prev_balance),
                        script_pubkey: script_pub_key.clone(),
                    },
                ),
                tap_leaf_hash,
                TapSighashType::AllPlusAnyoneCanPay,
            )
            .unwrap()
            .into_32();

        let bip340challenge_prefix = get_hashed_tag("BIP0340/challenge");

        let mut sha256 = sha2::Sha256::new();
        Digest::update(&mut sha256, &bip340challenge_prefix);
        Digest::update(&mut sha256, &bip340challenge_prefix);
        Digest::update(&mut sha256, SECP256K1_GENERATOR.as_slice());
        Digest::update(&mut sha256, SECP256K1_GENERATOR.as_slice());
        Digest::update(&mut sha256, hash);
        let e_expected = sha256.finalize().to_vec();

        if e_expected[31] == 0x01 {
            e = Some(e_expected);

            let mut sighashcache = SighashCache::new(tx.clone());

            let mut bytes = vec![];
            sighashcache
                .taproot_encode_signing_data_to(
                    &mut bytes,
                    0,
                    &Prevouts::One(
                        0,
                        &TxOut {
                            value: Amount::from_sat(information.prev_balance),
                            script_pubkey: script_pub_key.clone(),
                        },
                    ),
                    None,
                    Some((tap_leaf_hash, 0xffffffffu32)),
                    TapSighashType::AllPlusAnyoneCanPay,
                )
                .unwrap();

            break;
        } else {
            tx.output.pop().unwrap();
            randomizer += 1;
        }
    }

    // now start preparing the witness

    let mut script_execution_witness = Vec::<Vec<u8>>::new();

    // new balance (8 bytes)
    script_execution_witness.push(information.new_balance.to_le_bytes().to_vec());

    // this script's scriptpubkey (34 bytes)
    script_execution_witness.push(script_pub_key.to_bytes());

    // the actual number (as a Bitcoin integer)
    script_execution_witness.push(scriptint_vec(new_counter as i64));

    // the randomizer (4 bytes)
    script_execution_witness.push(randomizer.to_le_bytes().to_vec());

    // previous tx's txid (32 bytes)
    script_execution_witness.push(AsRef::<[u8]>::as_ref(&information.prev_txid).to_vec());

    // previous balance (8 bytes)
    script_execution_witness.push(information.prev_balance.to_le_bytes().to_vec());

    // tap leaf hash (32 bytes)
    script_execution_witness.push(AsRef::<[u8]>::as_ref(&tap_leaf_hash).to_vec());

    // the sha256 without the last byte
    script_execution_witness.push(e.unwrap()[0..31].to_vec());

    // the first outpoint
    {
        let mut bytes = vec![];
        information
            .prev_tx_outpoint1
            .consensus_encode(&mut bytes)
            .unwrap();

        script_execution_witness.push(bytes);
    }

    // the second outpoint
    {
        if information.prev_tx_outpoint2.is_some() {
            let mut bytes = vec![];
            information
                .prev_tx_outpoint2
                .unwrap()
                .consensus_encode(&mut bytes)
                .unwrap();

            script_execution_witness.push(bytes);
        } else {
            script_execution_witness.push(vec![]);
        }
    }

    // previous randomness
    script_execution_witness.push(information.prev_randomizer.to_le_bytes().to_vec());

    let mut script_tx_witness = Witness::new();
    for elem in script_execution_witness.iter() {
        script_tx_witness.push(elem);
    }
    script_tx_witness.push(script);
    script_tx_witness.push(control_block_bytes);

    tx.input[0].witness = script_tx_witness;

    let tx_template = TxTemplate {
        tx,
        prevouts: vec![TxOut {
            value: Amount::from_sat(information.prev_balance),
            script_pubkey: script_pub_key.clone(),
        }],
        input_idx: 0,
        taproot_annex_scriptleaf: Some((tap_leaf_hash.clone(), None)),
    };

    (tx_template, randomizer)
}

pub fn get_script() -> Script {
    let secp256k1_generator = SECP256K1_GENERATOR.clone();

    script! {
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

        // the balance must be zero
        OP_PUSHBYTES_8 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
        OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0 OP_PUSHBYTES_0
        OP_CAT

        // push the script hash header
        OP_PUSHBYTES_1 OP_RETURN

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

        { tx::step5_output::Step1AmountGadget::from_constant(&Amount::ZERO) }
        OP_CAT2

        // push the script hash header
        OP_PUSHBYTES_1 OP_RETURN

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
    use std::cell::RefCell;
    use std::rc::Rc;
    use crate::counter::{get_script, get_taproot, get_tx, Information};
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, WitnessProgram, WScriptHash};
    use bitcoin_scriptexec::{Exec, ExecCtx, Options};
    use bitcoin_simulator::database::Database;
    use bitvm::treepp::*;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_script_execution() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let mut random_txid_preimage = [0u8; 20];
        prng.fill_bytes(&mut random_txid_preimage);

        let prev_counter = 123;
        let prev_randomness = 45678;

        let prev_witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(vec![
            OP_RETURN.to_u8(),
            (prev_counter & 0xff) as u8,
            ((prev_counter >> 8) & 0xff) as u8,
            ((prev_counter >> 16) & 0xff) as u8,
            ((prev_counter >> 24) & 0xff) as u8,
            (prev_randomness & 0xff) as u8,
            ((prev_randomness >> 8) & 0xff) as u8,
            ((prev_randomness >> 16) & 0xff) as u8,
            ((prev_randomness >> 24) & 0xff) as u8,
        ]));

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
                        script_pubkey: get_taproot(),
                    },
                    TxOut {
                        value: Amount::ZERO,
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

            let information = Information {
                prev_counter,
                prev_randomizer: prev_randomness,
                prev_balance: prev_tx.output[0].value.to_sat(),
                prev_txid: prev_tx.compute_txid(),
                prev_tx_outpoint1: prev_tx.input[0].previous_output.clone(),
                prev_tx_outpoint2: prev_tx
                    .input
                    .get(1)
                    .and_then(|x| Some(x.previous_output.clone())),
                fee_paying_input: None,
                new_balance: 78910,
            };

            let (tx_template, _) = get_tx(&information);
            let witness = &tx_template.tx.input[0].witness;

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
            script_buf.extend_from_slice(script_body.as_bytes());

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

        let script_pub_key = get_taproot();

        // create the first tx and accept it unconditionally
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
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000_000),
                script_pubkey: script_pub_key.clone()
            }, TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::hash(
                    &[OP_RETURN.to_u8(), 0, 0, 0, 0, 12, 0, 0, 0]
                ))
            }],
        };

        db.insert_transaction_unconditionally(&init_tx).unwrap();

        let trivial_p2wsh_script = script! {
            OP_TRUE
        };

        let trivial_p2wsh_script_pubkey = ScriptBuf::new_p2wsh(&WScriptHash::hash(trivial_p2wsh_script.as_bytes()));

        let mut trivial_p2wsh_witness = Witness::new();
        trivial_p2wsh_witness.push([]);
        trivial_p2wsh_witness.push(trivial_p2wsh_script);

        let mut prev_counter = 0u32;
        let mut prev_randomizer = 12u32;
        let mut prev_balance = 1_000_000_000u64;
        let mut prev_txid = init_tx.compute_txid();

        let mut prev_tx_outpoint1 = init_tx.input[0].previous_output;
        let mut prev_tx_outpoint2 = None;

        for _ in 0..100 {
            let has_fee_paying_input = prng.borrow_mut().gen::<bool>();

            let fee_paying_input = if has_fee_paying_input {
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
            if fee_paying_input.is_some() {
                new_balance += 123_456_000;
            }
            new_balance -= 1; // as for transaction fee

            let information = Information {
                prev_counter,
                prev_randomizer,
                prev_balance,
                prev_txid: prev_txid.clone(),
                prev_tx_outpoint1: prev_tx_outpoint1.clone(),
                prev_tx_outpoint2: prev_tx_outpoint2.clone(),
                fee_paying_input,
                new_balance,
            };

            let (tx_template, randomizer) = get_tx(&information);

            assert!(db.verify_transaction(&tx_template.tx).is_ok());
            db.insert_transaction_unconditionally(&tx_template.tx).unwrap();

            prev_counter += 1;
            prev_randomizer = randomizer;
            prev_balance = new_balance;
            prev_txid = tx_template.tx.compute_txid();

            prev_tx_outpoint1 = tx_template.tx.input[0].previous_output;
            prev_tx_outpoint2 = tx_template.tx.input.get(1).and_then(|x| Some(x.previous_output.clone()));
        }
    }
}
