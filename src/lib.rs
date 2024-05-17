use lazy_static::lazy_static;
lazy_static! {
    pub static ref SECP256K1_GENERATOR: Vec<u8> =
        hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
}

pub mod counter;
