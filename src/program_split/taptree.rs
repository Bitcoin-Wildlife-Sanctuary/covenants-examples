/// Taptree gadget
use bitcoin::key::UntweakedPublicKey;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{ScriptBuf, TapLeafHash, WitnessProgram};
use std::str::FromStr;

#[derive(Clone)]
pub struct ScriptTapTree {
    spend_info: TaprootSpendInfo,
    pubkey: ScriptBuf,
}

impl ScriptTapTree {
    /// construct a taptree with any number of prepared scripts, and generate a pubkey
    pub fn new(scripts: &Vec<ScriptBuf>) -> Self {
        let num_scripts = scripts.len();
        let log2 = (num_scripts as u32).ilog2() as u8;
        let prev_power_of_2 = 2_usize.pow(log2 as u32);

        // Build the witness program.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let internal_key = UntweakedPublicKey::from(
            bitcoin::secp256k1::PublicKey::from_str(
                "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
            )
            .unwrap(),
        );

        // add the individual scripts into Taptree (as leaf node)
        let mut taproot_builder = TaprootBuilder::new();
        if prev_power_of_2 == 1 {
            taproot_builder = taproot_builder.add_leaf(0, scripts[0].clone()).unwrap();
        } else if prev_power_of_2 == num_scripts {
            for i in 0..prev_power_of_2 {
                taproot_builder = taproot_builder.add_leaf(log2, scripts[i].clone()).unwrap();
            }
        } else {
            // push the first prev_power_of_2 leaf nodes
            for i in 0..prev_power_of_2 {
                taproot_builder = taproot_builder
                    .add_leaf(log2 + 1, scripts[i].clone())
                    .unwrap();
            }
            // [None, N1]

            // push the remained leaf nodes except the last one
            for i in prev_power_of_2..(num_scripts - 1) {
                let depth = 2 + i - prev_power_of_2;
                taproot_builder = taproot_builder
                    .add_leaf(depth as u8, scripts[i].clone())
                    .unwrap();
            }
            // [None, N1, a_m, a_{m + 1}, a_{n - 2}]

            // push the last leaf node, make sure there's only one node at last which is also the taptree root
            taproot_builder = taproot_builder
                .add_leaf(
                    (num_scripts - prev_power_of_2) as u8,
                    scripts[num_scripts - 1].clone(),
                )
                .unwrap();
            // [N0]
        }

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();
        let witness_program =
            WitnessProgram::p2tr(&secp, internal_key, taproot_spend_info.merkle_root());

        let pub_key = ScriptBuf::new_witness_program(&witness_program);
        Self {
            spend_info: taproot_spend_info,
            pubkey: pub_key,
        }
    }

    /// obtain pubkey
    pub fn get_pub_key(&self) -> ScriptBuf {
        self.clone().pubkey
    }

    /// get taptree branch of specific leaf node (script)
    pub fn get_control_block(&self, script: &ScriptBuf) -> Vec<u8> {
        let mut control_block_bytes = Vec::new();
        self.clone()
            .spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap()
            .encode(&mut control_block_bytes)
            .unwrap();
        control_block_bytes
    }

    /// get hash of specific leaf node
    pub fn get_tap_leaf(script: &ScriptBuf) -> TapLeafHash {
        TapLeafHash::from_script(script, LeafVersion::TapScript)
    }
}
