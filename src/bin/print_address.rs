use bitcoin::{Address, Network, ScriptBuf, WScriptHash};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_PUSHBYTES_8, OP_RETURN};
use covenants_examples::counter::get_script_pub_key_and_control_block;

fn main() {
    let (script_pub_key, _) = get_script_pub_key_and_control_block();

    let program_address = Address::from_script(script_pub_key.as_script(), Network::Signet).unwrap();
    let caboose_address = Address::from_script(ScriptBuf::new_p2wsh(&WScriptHash::hash(&[
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
    ])).as_script(), Network::Signet).unwrap();

    println!("{}", program_address);
    println!("{}", caboose_address);
}