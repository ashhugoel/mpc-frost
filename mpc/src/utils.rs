use frost_dalek::keygen::SecretShare;
use curve25519_dalek::scalar::Scalar;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;

/// Convert JSON array of peer shares into Vec<SecretShare>
pub fn parse_peer_shares(json_shares: &[Value]) -> Vec<SecretShare> {
    let mut shares_vec = Vec::new();

    for item in json_shares {
        if let (Some(node_id), Some(your_share_b64)) =
            (item.get("node_id").and_then(|v| v.as_u64()),
             item.get("your_share").and_then(|v| v.as_str()))
        {
            match STANDARD.decode(your_share_b64) {
                Ok(bytes) => {
                    let scalar = Scalar::from_bytes_mod_order(
                        bytes.try_into().expect("Expected 32 bytes for Scalar")
                    );
                    // Use the constructor instead of direct field access
                    let share = SecretShare::from_scalar(node_id as u32, scalar);

                            // ✅ Print the share bytes for debugging
        println!("🟣 Decoded share for node {}: {:?}", node_id, share.to_bytes());

                    shares_vec.push(share);
                }
                Err(e) => eprintln!("⚠️ Failed to decode share for node {}: {}", node_id, e),
            }
        } else {
            eprintln!("⚠️ Missing node_id or your_share field in JSON: {:?}", item);
        }
    }

    shares_vec
}





