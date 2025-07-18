use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuessInputs {
    pub pk_bytes: Vec<u8>,
    pub arbitrary_bytes: Vec<u8>,
    pub pq_addresses: Vec<String>,
    pub bitcoin_version_byte: u8,
    pub sig_bytes: Vec<u8>,
}

pub fn build_sig_msg(arbitrary_bytes: &[u8], pq_addresses: &[String]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&arbitrary_bytes);
    for address in pq_addresses {
        msg.extend_from_slice(address.as_bytes());
    }

    msg
}

pub fn verify_signature(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
    // Hash the message
    let msg_hash = Sha256::digest(msg);

    // Parse public key
    let verifying_key = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };

    // Parse signature
    let signature = match Signature::from_bytes(sig_bytes.into()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verifying_key.verify(&msg_hash, &signature).is_ok()
}

pub fn compute_p2pkh(version_byte: u8, pk_bytes: &[u8]) -> String {
    let sha256_hash = hash::<Sha256>(&pk_bytes);
    let ripemd160_hash = hash::<Ripemd160>(&sha256_hash);

    let mut address = vec![version_byte];
    address.extend(ripemd160_hash);

    let checksum = hash::<Sha256>(&hash::<Sha256>(&address));
    address.extend_from_slice(&checksum[..4]);

    return bs58::encode(address).into_string();
}

fn hash<H>(bytes: &[u8]) -> Vec<u8>
where
    H: Digest + Default,
{
    let mut hasher = H::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}
