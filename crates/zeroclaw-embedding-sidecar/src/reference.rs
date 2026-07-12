//! Canonical definition of the deterministic reference embedding space.

use sha2::{Digest, Sha256};

include!(concat!(env!("OUT_DIR"), "/reference_manifest.rs"));

pub fn feature_hash(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0_f32; DIMENSIONS];
    let mut saw_token = false;
    for token in text
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        saw_token = true;
        let mut hasher = Sha256::new();
        hasher.update(b"zeroclaw-reference-embedding-v1\0");
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        for lane in 0..4 {
            let offset = lane * 2;
            let raw = u16::from_be_bytes([digest[offset], digest[offset + 1]]);
            let index = usize::from(raw) % DIMENSIONS;
            let sign = if digest[16 + lane] & 1 == 0 {
                1.0
            } else {
                -1.0
            };
            vector[index] += sign;
        }
    }
    if !saw_token {
        vector[0] = 1.0;
        return vector;
    }
    let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
    if norm > 0.0 {
        for value in &mut vector {
            *value /= norm;
        }
    }
    vector
}
