//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::fs;

use p2pkh_lib::GuessInputs;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const P2PKH_ELF: &[u8] = include_elf!("p2pkh-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::from_env();

    let params = fs::read_to_string("../p2pkh-inputs.json")
        .map_err(|e| eprintln!("Failed to read p2pkh-inputs.json: {}", e))
        .unwrap();
    let params_s: GuessInputs = serde_json::from_str(&params).unwrap();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&params_s.pk_bytes);
    stdin.write(&params_s.arbitrary_bytes);
    stdin.write(&params_s.pq_addresses);
    stdin.write(&params_s.bitcoin_version_byte);
    stdin.write(&params_s.sig_bytes);

    // println!("n: {}", args.n);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(P2PKH_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(P2PKH_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");
        let proof_s = serde_json::to_string(&proof).unwrap().len();

        println!("Proof: {proof_s}");

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
