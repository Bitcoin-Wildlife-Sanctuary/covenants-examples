use crate::treepp::*;
use crate::utils;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, TxIn, Txid};

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

impl CounterUpdateInfo {
    pub fn default() -> Self {
        let txid = Txid::hash(&[0_u8]);
        Self {
            prev_counter: 0_u32,
            prev_randomizer: 0_u32,
            prev_balance: 0_u64,
            prev_txid: txid,
            prev_tx_outpoint1: OutPoint::new(txid, 0_u32),
            prev_tx_outpoint2: None,
            optional_deposit_input: None,
            new_balance: 0_u64,
        }
    }
}

/// toy script of plus n on counter
pub fn get_script_counter_plus_n(n: u32) -> Script {
    script! {
        { utils::convenant(DUST_AMOUNT) }

        OP_FROMALTSTACK OP_FROMALTSTACK
        // [prev_counter, new_counter]
        { n } OP_SUB OP_EQUAL
    }
}

#[cfg(test)]
mod test {
    use super::super::{taptree, transaction};
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{ScriptBuf, Sequence, Witness};
    use bitcoin_scriptexec::{Exec, ExecCtx, Options};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_multi_script_execution() {
        let num_scripts = 1_usize;
        let tx_fee = 10;
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        // script tap tree and its pubkey
        let scripts = (0..num_scripts)
            .map(|i| get_script_counter_plus_n((i + 1) as u32))
            .collect::<Vec<_>>();
        let script_taptree = taptree::ScriptTapTree::new(&scripts);
        let pubkey = script_taptree.get_pub_key();

        // initial counter, randomizer, balance
        let init_counter = 123;
        let init_randomizer = 45678;
        let init_balance = 123456;

        // initial txid, txout (faucet transaction)
        let mut random_txid_preimage = [0u8; 20];
        prng.fill_bytes(&mut random_txid_preimage);
        let init_txid = Txid::hash(&random_txid_preimage);
        let init_txout = vec![TxIn {
            previous_output: OutPoint {
                txid: init_txid,
                vout: 15,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::default(),
            witness: Witness::new(),
        }];

        let prev_tx = transaction::CounterTransaction::get_transaction(
            &init_txout,
            init_counter,
            init_balance,
            init_randomizer,
            pubkey.clone(),
        );
        let prev_txid = prev_tx.compute_txid();

        // public input for new transaction
        let mut public_info = CounterUpdateInfo {
            prev_counter: init_counter,
            prev_randomizer: init_randomizer,
            prev_balance: init_balance,
            prev_txid: prev_txid,
            prev_tx_outpoint1: prev_tx.input[0].previous_output.clone(),
            prev_tx_outpoint2: prev_tx
                .input
                .get(1)
                .and_then(|x| Some(x.previous_output.clone())),
            optional_deposit_input: None,
            new_balance: init_balance - tx_fee,
        };

        // execute every transaction
        for i in 0..num_scripts {
            let script_control_block = script_taptree.get_control_block(&scripts[i]);
            let script_tap_leaf = taptree::ScriptTapTree::get_tap_leaf(&scripts[i]);

            // get transaction template, and update public info for the next transaction
            let tx_template = transaction::CounterTransaction::new(
                &pubkey,
                &scripts[i],
                script_control_block,
                script_tap_leaf,
                &mut public_info,
                i + 1,
                tx_fee,
            )
            .0;
            let witness = &tx_template.tx.input[0].witness;

            // Simulate the script execution by pre-appending all the initial witness elements.
            let mut script_buf = script! {
                for entry in witness.iter().take(witness.len() - 2) {
                    { entry.to_vec() }
                }
            }
            .to_bytes();
            let script_body = &scripts[i];
            println!("counter.len = {} bytes", script_body.len());
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
}
