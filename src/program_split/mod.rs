/// This is demo for spliting script
///
use crate::treepp::*;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use std::str::FromStr;

/// Demo script:
///     if there are num numbers in stack whose values are all exactly num,
///     then push num + 1 numbers whose values are all num + 1
pub fn demo_script(num: usize) -> Script {
    script! {
        OP_DEPTH { num } OP_EQUAL OP_IF
            for _ in 0..num {
                { num } OP_EQUALVERIFY
            }
            for _ in 0..(num + 1) {
                { num + 1 }
            }
        OP_ENDIF
    }
}

pub fn tap_tree_builder(num_scripts: usize) {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    // public key with x-coordinate
    let internal_key = UntweakedPublicKey::from(
        bitcoin::secp256k1::PublicKey::from_str(
            "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap(),
    );

    // construct specific number of individual scripts
    let scripts = (0..num_scripts).map(|i| demo_script(i)).collect::<Vec<_>>();

    // add the individual scripts into Taptree (as leaf node)
    let mut builder = TaprootBuilder::new();
    for i in 0..num_scripts {
        builder = builder.add_leaf(0, scripts[i].clone()).unwrap();
    }

    // build tree
    let tree_info = builder.finalize(&secp, internal_key).unwrap();
    println!(
        "Taproot of {} scripts: {}",
        num_scripts,
        tree_info.merkle_root().unwrap()
    );

    // given a specific script (leaf node) and its merkle branch (path), compute merkle root,
    // obtain its tweak scalar, and tweak the public key
    let output_key = tree_info.output_key();
    for i in 0..num_scripts {
        let ver_script = (scripts[i].clone(), LeafVersion::TapScript);
        // get the cooresponding merkle branch of specific leaf node
        let ctrl_block = tree_info.control_block(&ver_script).unwrap();
        // tweak and check, make sure the tweaked point is on the curve (a valid point)
        assert!(ctrl_block.verify_taproot_commitment(&secp, output_key.to_inner(), &ver_script.0))
    }
}
