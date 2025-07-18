use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const P2PKH_ELF: &[u8] = include_elf!("p2pkh-program");

fn main() {
    let prover = ProverClient::builder().cpu().build();
    let (_, vk) = prover.setup(P2PKH_ELF);
    println!("{}", vk.bytes32());
}