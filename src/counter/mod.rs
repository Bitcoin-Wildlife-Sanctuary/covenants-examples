use crate::common::{covenant, CovenantHeader, CovenantHints, CovenantProgram, DUST_AMOUNT};
use crate::treepp::pushable::{Builder, Pushable};
use crate::treepp::*;
use crate::SECP256K1_GENERATOR;
use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Witness, WitnessProgram,
};
use bitcoin_scriptexec::utils::scriptint_vec;
use bitcoin_scriptexec::{convert_to_witness, TxTemplate};
use covenants_gadgets::structures::tagged_hash::get_hashed_tag;
use covenants_gadgets::utils::pseudo::OP_HINT;
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;

pub struct CounterProgram;

#[derive(Clone)]
pub struct CounterState {
    pub counter: usize,
}

impl Pushable for CounterState {
    fn bitcoin_script_push(&self, mut builder: Builder) -> Builder {
        builder = self.counter.bitcoin_script_push(builder);
        builder
    }
}

impl CovenantProgram for CounterProgram {
    type State = CounterState;

    fn new() -> Self::State {
        Self::State { counter: 0 }
    }

    fn get_header(state: &Self::State) -> CovenantHeader {
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, &scriptint_vec(state.counter as i64));
        let state_hash = sha256.finalize().to_vec();
        CovenantHeader {
            pc: 123456,
            state_hash,
        }
    }

    fn get_all_scripts() -> BTreeMap<usize, ScriptBuf> {
        let mut map = BTreeMap::new();
        map.insert(
            123456,
            script! {
                // stack:
                // - old state hash
                // - new state hash
                // - old PC
                // - new PC

                // require the new PC to be 123456
                123456 OP_EQUALVERIFY

                // require the old PC to be 123456
                123456 OP_EQUALVERIFY

                // get the old counter and the new counter
                OP_HINT OP_HINT
                // save a copy to the altstack
                // altstack: new counter, old counter
                OP_2DUP OP_TOALTSTACK OP_TOALTSTACK

                // stack:
                // - old state hash
                // - new state hash
                // - old counter
                // - new counter
                OP_SHA256 OP_ROT OP_EQUALVERIFY
                OP_SHA256 OP_EQUALVERIFY

                OP_FROMALTSTACK OP_FROMALTSTACK

                // stack:
                // - old counter
                // - new counter
                OP_1SUB OP_EQUAL
            },
        );
        map
    }

    fn run(old_state: &Self::State) -> Result<Self::State> {
        Ok(CounterState {
            counter: old_state.counter + 1,
        })
    }
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
pub fn get_tx<T: CovenantProgram>(
    info: &CovenantHints,
    old_state: &T::State,
    new_state: &T::State,
) -> (TxTemplate, u32) {
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

    let old_state_hash = T::get_header(old_state).state_hash;
    let new_state_hash = T::get_header(new_state).state_hash;

    // Start the search of a working randomizer from 0.
    let mut randomizer = 0u32;

    // Initialize a placeholder for e, which is the signature element "e" in Schnorr signature.
    // Finding e relies on trial-and-error. Specifically, e is a tagged hash of the signature preimage,
    // and the signature preimage is calculated by serializing the transaction in a specific way.
    let e;
    loop {
        let mut script_bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
        script_bytes.extend_from_slice(&new_state_hash);
        script_bytes.extend_from_slice(&randomizer.to_le_bytes());

        // Generate the corresponding caboose with the new counter.
        let witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(script_bytes));

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
        let hash = AsRef::<[u8]>::as_ref(
            &sighashcache
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
                .unwrap(),
        )
        .to_vec();

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

    // the new counter hash
    script_execution_witness.push(new_state_hash.clone());

    // the old counter hash
    script_execution_witness.push(old_state_hash.clone());

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

    // application-specific witnesses
    let application_witness = convert_to_witness(script! {
        { old_state.clone() }
        { new_state.clone() }
    })
    .unwrap();

    script_execution_witness.extend_from_slice(&application_witness);

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
    script! {
        covenant
        // hint:
        // - old counter
        // - new counter
        //
        // stack:
        // - old state hash
        // - new state hash

        OP_HINT OP_HINT
        OP_2DUP OP_TOALTSTACK OP_TOALTSTACK

        // stack:
        // - old state hash
        // - new state hash
        // - old counter
        // - new counter

        OP_SHA256 OP_ROT OP_EQUALVERIFY
        OP_SHA256 OP_EQUALVERIFY

        // stack:
        // - old counter
        // - new counter
        OP_FROMALTSTACK OP_FROMALTSTACK
        OP_1SUB OP_EQUAL
    }
}

#[cfg(test)]
mod test {
    use crate::common::{CovenantHints, DUST_AMOUNT};
    use crate::counter::{
        get_script, get_script_pub_key_and_control_block, get_tx, CounterProgram, CounterState,
    };
    use crate::treepp::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WScriptHash,
        Witness, WitnessProgram,
    };
    use bitcoin_scriptexec::execute_script_with_witness_and_tx_template;
    use bitcoin_scriptexec::utils::scriptint_vec;
    use bitcoin_simulator::database::Database;
    use bitcoin_simulator::policy::Policy;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use sha2::digest::Update;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn test_script_execution() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // compute a random txid, counter, and randomizer for testing purposes only.
        let mut random_txid_preimage = [0u8; 20];
        prng.fill_bytes(&mut random_txid_preimage);
        let prev_counter = 123;
        let prev_hash = {
            let mut sha256 = Sha256::new();
            Update::update(&mut sha256, &scriptint_vec(prev_counter as i64));
            sha256.finalize().to_vec()
        };
        let prev_randomizer = 45678u32;

        let mut script_bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
        script_bytes.extend_from_slice(&prev_hash);
        script_bytes.extend_from_slice(&prev_randomizer.to_le_bytes());

        let prev_witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(script_bytes));

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

            let info = CovenantHints {
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

            let old_state = CounterState {
                counter: prev_counter as usize,
            };
            let new_state = CounterState {
                counter: (prev_counter + 1) as usize,
            };

            let (tx_template, _) = get_tx::<CounterProgram>(&info, &old_state, &new_state);
            let mut witness = tx_template.tx.input[0].witness.to_vec();
            witness.pop();
            witness.pop();

            // Simulate the script execution.
            let script = get_script();

            if input_num == 1 {
                println!("counter.len = {} bytes", script.len());
            }

            let exec_result = execute_script_with_witness_and_tx_template(
                Script::from_bytes(script.to_bytes()),
                tx_template,
                witness,
            );
            assert!(exec_result.success);
        }
    }

    #[test]
    fn test_simulation() {
        let policy = Policy::default().set_fee(1).set_max_tx_weight(400000);

        let prng = Rc::new(RefCell::new(ChaCha20Rng::seed_from_u64(0)));
        let get_rand_txid = || {
            let mut bytes = [0u8; 20];
            prng.borrow_mut().fill_bytes(&mut bytes);
            Txid::hash(&bytes)
        };

        let db = Database::connect_temporary_database().unwrap();

        let (script_pub_key, _) = get_script_pub_key_and_control_block();

        let prev_counter = 0;
        let prev_hash = {
            let mut sha256 = Sha256::new();
            Update::update(&mut sha256, &scriptint_vec(prev_counter as i64));
            sha256.finalize().to_vec()
        };
        let prev_randomizer = 12u32;

        let mut script_bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
        script_bytes.extend_from_slice(&prev_hash);
        script_bytes.extend_from_slice(&prev_randomizer.to_le_bytes());

        let prev_witness_program = WitnessProgram::p2wsh(&ScriptBuf::from_bytes(script_bytes));

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
                    script_pubkey: ScriptBuf::new_witness_program(&prev_witness_program),
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

            let info = CovenantHints {
                prev_randomizer,
                prev_balance,
                prev_txid: prev_txid.clone(),
                prev_tx_outpoint1: prev_tx_outpoint1.clone(),
                prev_tx_outpoint2: prev_tx_outpoint2.clone(),
                optional_deposit_input: deposit_input,
                new_balance,
            };

            let old_state = CounterState {
                counter: prev_counter as usize,
            };
            let new_state = CounterState {
                counter: (prev_counter + 1) as usize,
            };

            let (tx_template, randomizer) = get_tx::<CounterProgram>(&info, &old_state, &new_state);

            // Check if the new transaction conforms to the requirement.
            // If so, insert this transaction unconditionally.
            db.verify_transaction(&tx_template.tx).unwrap();
            db.check_fees(&tx_template.tx, &policy).unwrap();
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
}
