use sha2::Digest;

pub fn double_sha256(data: &str) -> String {
    let hash = sha2::Sha256::digest(hex::decode(data).expect("Failed to decode"));

    let double_hash = sha2::Sha256::digest(hash);

    hex::encode(double_hash)
}
