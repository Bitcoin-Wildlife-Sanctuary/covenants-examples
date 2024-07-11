use crate::common::CovenantProgram;
use crate::treepp::pushable::{Builder, Pushable};
use crate::treepp::*;
use anyhow::Result;
use bitcoin_scriptexec::utils::scriptint_vec;
use covenants_gadgets::utils::pseudo::OP_HINT;
use sha2::digest::Update;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The covenant program of the counter example.
pub struct CounterProgram;

/// State of the counter example, which is a counter.
#[derive(Clone)]
pub struct CounterState {
    /// The counter.
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

    const CACHE_NAME: &'static str = "COUNTER";

    fn new() -> Self::State {
        Self::State { counter: 0 }
    }

    fn get_hash(state: &Self::State) -> Vec<u8> {
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, &scriptint_vec(state.counter as i64));
        sha256.finalize().to_vec()
    }

    fn get_all_scripts() -> BTreeMap<usize, Script> {
        let mut map = BTreeMap::new();
        map.insert(
            123456,
            script! {
                // stack:
                // - old state hash
                // - new state hash

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
        map.insert(
            123457,
            script! {
                // stack:
                // - old state hash
                // - new state hash

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
                OP_1SUB OP_1SUB OP_EQUAL
            },
        );
        map
    }

    fn run(id: usize, old_state: &Self::State) -> Result<Self::State> {
        if id == 123456 {
            Ok(CounterState {
                counter: old_state.counter + 1,
            })
        } else if id == 123457 {
            Ok(CounterState {
                counter: old_state.counter + 2,
            })
        } else {
            unimplemented!()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::common::{get_script_pub_key, get_tx, CovenantInput, CovenantProgram, DUST_AMOUNT};
    use crate::counter::CounterProgram;
    use crate::treepp::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WScriptHash,
        Witness, WitnessProgram,
    };
    use bitcoin_simulator::database::Database;
    use bitcoin_simulator::policy::Policy;
    use rand::prelude::SliceRandom;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::rand_core::CryptoRngCore;
    use rand_chacha::ChaCha20Rng;
    use std::cell::RefCell;
    use std::rc::Rc;

    type T = CounterProgram;

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

        let init_state = T::new();
        let init_state_hash = T::get_hash(&init_state);
        let script_pub_key = get_script_pub_key::<T>();

        let init_randomizer = 12u32;

        let mut script_bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
        script_bytes.extend_from_slice(&init_state_hash);
        script_bytes.extend_from_slice(&init_randomizer.to_le_bytes());

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
        let mut old_state = init_state;
        let mut old_randomizer = init_randomizer;
        let mut old_balance = 1_000_000_000u64;
        let mut old_txid = init_tx.compute_txid();

        let mut old_tx_outpoint1 = init_tx.input[0].previous_output;
        let mut old_tx_outpoint2 = None;

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

            let mut new_balance = old_balance;
            if deposit_input.is_some() {
                new_balance += 123_456_000;
            }
            new_balance -= 500; // as for transaction fee
            new_balance -= DUST_AMOUNT;

            let info = CovenantInput {
                old_randomizer,
                old_balance,
                old_txid: old_txid.clone(),
                input_outpoint1: old_tx_outpoint1.clone(),
                input_outpoint2: old_tx_outpoint2.clone(),
                optional_deposit_input: deposit_input,
                new_balance,
            };

            let which_program = *[123456usize, 123457]
                .choose(prng.borrow_mut().as_rngcore())
                .unwrap();

            let new_state = T::run(which_program, &old_state).unwrap();

            let (tx_template, randomizer) =
                get_tx::<CounterProgram>(&info, which_program, &old_state, &new_state);

            // Check if the new transaction conforms to the requirement.
            // If so, insert this transaction unconditionally.
            db.verify_transaction(&tx_template.tx).unwrap();
            db.check_fees(&tx_template.tx, &policy).unwrap();
            db.insert_transaction_unconditionally(&tx_template.tx)
                .unwrap();

            // Update the local state.
            old_state = new_state;
            old_randomizer = randomizer;
            old_balance = new_balance;
            old_txid = tx_template.tx.compute_txid();

            old_tx_outpoint1 = tx_template.tx.input[0].previous_output;
            old_tx_outpoint2 = tx_template
                .tx
                .input
                .get(1)
                .and_then(|x| Some(x.previous_output.clone()));
        }
    }
}
