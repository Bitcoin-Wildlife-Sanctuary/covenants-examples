use super::counter::CounterUpdateInfo;
use super::DUST_AMOUNT;
use crate::SECP256K1_GENERATOR;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::opcodes::all::*;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::{
    Amount, OutPoint, Sequence, TapLeafHash, TapSighashType, TxIn, TxOut, Witness, WitnessProgram,
};
use bitcoin_scriptexec::utils::scriptint_vec;
use bitcoin_scriptexec::TxTemplate;
use covenants_gadgets::structures::tagged_hash::get_hashed_tag;
use sha2::Digest;

pub struct CounterTransaction(pub TxTemplate);

impl CounterTransaction {
    pub fn get_default_transaction(
        prev_out: &Vec<TxIn>,
        balance: u64,
        pubkey: ScriptBuf,
    ) -> Transaction {
        // Initialize a new transaction.
        let mut tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // tx input
        for _in in prev_out.iter() {
            tx.input.push(_in.clone());
        }

        // tx output
        tx.output.push(TxOut {
            value: Amount::from_sat(balance),
            script_pubkey: pubkey,
        });
        tx
    }

    pub fn get_transaction(
        prev_out: &Vec<TxIn>,
        counter: u32,
        balance: u64,
        randomizer: u32,
        pubkey: ScriptBuf,
    ) -> Transaction {
        let mut tx = Self::get_default_transaction(prev_out, balance, pubkey);

        let witness_program = Self::get_witness_program(counter, randomizer);
        tx.output.push(TxOut {
            value: Amount::from_sat(DUST_AMOUNT),
            script_pubkey: ScriptBuf::new_witness_program(&witness_program),
        });
        tx
    }

    pub fn get_witness_program(counter: u32, randomizer: u32) -> WitnessProgram {
        WitnessProgram::p2wsh(&ScriptBuf::from_bytes(vec![
            OP_RETURN.to_u8(),
            OP_PUSHBYTES_8.to_u8(),
            (counter & 0xff) as u8,
            ((counter >> 8) & 0xff) as u8,
            ((counter >> 16) & 0xff) as u8,
            ((counter >> 24) & 0xff) as u8,
            (randomizer & 0xff) as u8,
            ((randomizer >> 8) & 0xff) as u8,
            ((randomizer >> 16) & 0xff) as u8,
            ((randomizer >> 24) & 0xff) as u8,
        ]))
    }

    pub fn get_tx_sig_preimage(
        tx: &mut Transaction,
        pubkey: ScriptBuf,
        leaf_hash: &TapLeafHash,
        prev_balance: u64,
        new_counter: u32,
    ) -> (Vec<u8>, u32) {
        let mut randomizer = 0_u32;
        // get signature preimage of tx
        let prevout = Prevouts::One(
            0,
            TxOut {
                value: Amount::from_sat(prev_balance),
                script_pubkey: pubkey.clone(),
            },
        );
        let e;
        loop {
            // Generate the corresponding caboose with the new counter.
            let witness_program = Self::get_witness_program(new_counter, randomizer);

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
                        &prevout,
                        leaf_hash.clone(),
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
        (e.unwrap(), randomizer)
    }

    pub fn new(
        pubkey: &ScriptBuf,
        script: &ScriptBuf,
        control_block: Vec<u8>,
        leaf_hash: TapLeafHash,
        public_info: &mut CounterUpdateInfo,
        step_size: usize,
        tx_fee: u64,
    ) -> Self {
        // prepare tx input
        let mut tx_input = vec![TxIn {
            previous_output: OutPoint::new(public_info.prev_txid.clone(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::default(),
            witness: Witness::new(), // placeholder
        }];
        // Push the previous program as the first input, with the witness left blank as a placeholder.
        // If there is an optional deposit input, include it as well.
        if let Some(input) = &public_info.optional_deposit_input {
            tx_input.push(input.clone());
        }
        // new a default tx
        let mut tx =
            Self::get_default_transaction(&tx_input, public_info.new_balance, pubkey.clone());

        // Increment the counter by 1, which would give us the new counter.
        let new_counter = public_info.prev_counter + step_size as u32;
        let (e, randomizer) = Self::get_tx_sig_preimage(
            &mut tx,
            pubkey.clone(),
            &leaf_hash,
            public_info.prev_balance,
            new_counter,
        );

        // now start preparing the witness
        let mut script_execution_witness = Vec::<Vec<u8>>::new();

        // new balance (8 bytes)
        script_execution_witness.push(public_info.new_balance.to_le_bytes().to_vec());

        // this script's scriptpubkey (34 bytes)
        script_execution_witness.push(pubkey.to_bytes());

        // the current counter (as a Bitcoin integer)
        script_execution_witness.push(scriptint_vec(new_counter as i64));

        // the prev_counter (as a Bitcoin integer)
        script_execution_witness.push(scriptint_vec(public_info.prev_counter as i64));

        // the randomizer (4 bytes)
        script_execution_witness.push(randomizer.to_le_bytes().to_vec());

        // previous tx's txid (32 bytes)
        script_execution_witness.push(AsRef::<[u8]>::as_ref(&public_info.prev_txid).to_vec());

        // previous balance (8 bytes)
        script_execution_witness.push(public_info.prev_balance.to_le_bytes().to_vec());

        // tap leaf hash (32 bytes)
        script_execution_witness.push(AsRef::<[u8]>::as_ref(&leaf_hash).to_vec());

        // the sha256 without the last byte (31 bytes)
        script_execution_witness.push(e[0..31].to_vec());

        // the first outpoint (32 + 4 = 36 bytes)
        {
            let mut bytes = vec![];
            public_info
                .prev_tx_outpoint1
                .consensus_encode(&mut bytes)
                .unwrap();

            script_execution_witness.push(bytes);
        }

        // the second outpoint (0 or 36 bytes)
        {
            if public_info.prev_tx_outpoint2.is_some() {
                let mut bytes = vec![];
                public_info
                    .prev_tx_outpoint2
                    .unwrap()
                    .consensus_encode(&mut bytes)
                    .unwrap();

                script_execution_witness.push(bytes);
            } else {
                script_execution_witness.push(vec![]);
            }
        }

        // previous randomizer
        script_execution_witness.push(public_info.prev_randomizer.to_le_bytes().to_vec());

        // Construct the witness that will be included in the TxIn.
        let mut script_tx_witness = Witness::new();
        // all the initial stack elements
        for elem in script_execution_witness.iter() {
            script_tx_witness.push(elem);
        }
        // the full script
        script_tx_witness.push(script);
        // the control block bytes
        script_tx_witness.push(control_block);

        // Include the witness in the TxIn.
        tx.input[0].witness = script_tx_witness;

        // Prepare the TxTemplate.
        let tx_template = TxTemplate {
            tx: tx.clone(),
            prevouts: vec![TxOut {
                value: Amount::from_sat(public_info.prev_balance),
                script_pubkey: pubkey.clone(),
            }],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((leaf_hash.clone(), None)),
        };

        // update public info
        public_info.prev_txid = tx.compute_txid();
        public_info.prev_balance = public_info.new_balance;
        public_info.new_balance -= tx_fee;
        public_info.prev_counter = new_counter;
        public_info.prev_randomizer = randomizer;
        public_info.prev_tx_outpoint1 = tx.input[0].previous_output.clone();
        public_info.prev_tx_outpoint2 = tx
            .input
            .get(1)
            .and_then(|x| Some(x.previous_output.clone()));
        public_info.optional_deposit_input = None;

        CounterTransaction(tx_template)
    }
}
