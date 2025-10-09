use frost_dalek::{DistributedKeyGeneration, Participant, Parameters};
// add this:
use curve25519_dalek::ristretto::CompressedRistretto;
use base64::{engine::general_purpose, Engine as _};




fn main() { 
    // ---- 1. basic parameters ----
    let params = Parameters { t: 2, n: 3 };

    // ---- 2. each participant creates initial material ----
    let (alice, alice_coeffs) = Participant::new(&params, 1);
    let (bob, bob_coeffs) = Participant::new(&params, 2);
    let (carol, carol_coeffs) = Participant::new(&params, 3);

    // ---- 3. round 1 ----
    let mut others_for_alice = vec![bob.clone(), carol.clone()];
    let mut alice_state =
        DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coeffs, &mut others_for_alice)
            .expect("Alice DKG round 1");

    let alice_shares = alice_state.their_secret_shares().expect("Alice shares");

    let mut others_for_bob = vec![alice.clone(), carol.clone()];
    let mut bob_state =
        DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coeffs, &mut others_for_bob)
            .expect("Bob DKG round 1");

    let bob_shares = bob_state.their_secret_shares().expect("Bob shares");

    let mut others_for_carol = vec![alice.clone(), bob.clone()];
    let mut carol_state =
        DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coeffs, &mut others_for_carol)
            .expect("Carol DKG round 1");

    let carol_shares = carol_state.their_secret_shares().expect("Carol shares");

    // ---- 4. deliver shares to each participant ----
    let alice_received = vec![bob_shares[0].clone(), carol_shares[0].clone()];
    let bob_received   = vec![alice_shares[0].clone(), carol_shares[1].clone()];
    let carol_received = vec![alice_shares[1].clone(), bob_shares[1].clone()];

    // ---- 5. round 2 ----
    let alice_round2 = alice_state.to_round_two(alice_received).expect("Alice round 2");
    let bob_round2   = bob_state.to_round_two(bob_received).expect("Bob round 2");
    let carol_round2 = carol_state.to_round_two(carol_received).expect("Carol round 2");

    // ---- 6. finish → each gets (group key, secret share) ----
    let (alice_group, alice_secret) = alice_round2.finish(alice.public_key().unwrap()).unwrap();
    let (bob_group, bob_secret)     = bob_round2.finish(bob.public_key().unwrap()).unwrap();
    let (carol_group, carol_secret) = carol_round2.finish(carol.public_key().unwrap()).unwrap();

    // ---- 7. verify same group key ----
// ---- 7. verify same group key ----
    assert_eq!(alice_group, bob_group);
    assert_eq!(bob_group, carol_group);

    let group_pub_compressed: CompressedRistretto = alice.public_key().unwrap().compress();


    let compressed = alice_group.to_bytes(); // frost-dalek implements this for GroupKey
    let group_b64 = general_purpose::STANDARD.encode(&compressed);
    
    println!("✅ Shared group public key (Base64): {}", group_b64);


    let compressed = bob_group.to_bytes(); // frost-dalek implements this for GroupKey
    let group_b64 = general_purpose::STANDARD.encode(&compressed);
    
    println!("✅ Shared group public key (Base64): {}", group_b64);

    
    
    println!("---------------------------------------------------------------------------------------------------------");
    let alice_b64 = participant_pubkey_base64(&alice);
    let bob_b64   = participant_pubkey_base64(&bob);
    let carol_b64 = participant_pubkey_base64(&carol);
    
    println!("Alice public key (Base64): {}", alice_b64);
    println!("Bob public key (Base64):   {}", bob_b64);
    println!("Carol public key (Base64): {}", carol_b64);

    // println!("✅ DKG complete — all participants derived the same group key!");
    // println!("Alice secret share: {:?}", alice_secret);
    // println!("Bob secret share: {:?}", bob_secret);
    // println!("Carol secret share: {:?}", carol_secret);

}


pub fn participant_pubkey_base64(participant: &Participant) -> String {
    // 1️⃣ Extract public key (RistrettoPoint)
    let pk_point = participant
        .public_key()
        .expect("Participant must have a valid public key");

    // 2️⃣ Compress the point into 32 bytes
    let compressed: CompressedRistretto = pk_point.compress();

    // 3️⃣ Convert to bytes and encode as Base64 string
    general_purpose::STANDARD.encode(compressed.as_bytes())
}