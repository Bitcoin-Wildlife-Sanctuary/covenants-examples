use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{Address, Network, ScriptBuf, WScriptHash};
use bitcoin_scriptexec::utils::scriptint_vec;
use covenants_examples::common::get_script_pub_key;
use covenants_examples::counter::CounterProgram;
use sha2::digest::Update;
use sha2::{Digest, Sha256};

fn main() {
    let script_pub_key = get_script_pub_key::<CounterProgram>();

    let program_address =
        Address::from_script(script_pub_key.as_script(), Network::Signet).unwrap();

    let mut bytes = vec![OP_RETURN.to_u8(), OP_PUSHBYTES_36.to_u8()];
    let counter = 0;

    let hash = {
        let mut sha256 = Sha256::new();
        Update::update(&mut sha256, &scriptint_vec(counter as i64));
        sha256.finalize().to_vec()
    };
    bytes.extend_from_slice(&hash);
    bytes.extend_from_slice(&12u32.to_le_bytes());

    let caboose_address = Address::from_script(
        ScriptBuf::new_p2wsh(&WScriptHash::hash(&bytes)).as_script(),
        Network::Signet,
    )
    .unwrap();

    println!("{}", program_address);
    println!("{}", caboose_address);
}
