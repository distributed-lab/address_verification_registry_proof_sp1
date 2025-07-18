// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use p2pkh_lib::{build_sig_msg, compute_p2pkh, verify_signature};

pub fn main() {
    let pk_bytes: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let arbitrary_bytes: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();
    let pq_addresses: Vec<String> = sp1_zkvm::io::read::<Vec<String>>();
    let bitcoin_version_byte: u8 = sp1_zkvm::io::read::<u8>();
    let sig_bytes: Vec<u8> = sp1_zkvm::io::read::<Vec<u8>>();

    let msg = build_sig_msg(&arbitrary_bytes, &pq_addresses);

    if !verify_signature(&msg, &sig_bytes, &pk_bytes) {
        panic!("Signature verification failed");
    }

    let p2pkh_address = compute_p2pkh(bitcoin_version_byte, &pk_bytes);

    sp1_zkvm::io::commit(&p2pkh_address);
    sp1_zkvm::io::commit(&arbitrary_bytes);
    sp1_zkvm::io::commit(&pq_addresses);
}
