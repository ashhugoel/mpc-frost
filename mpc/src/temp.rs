use base64::{Engine as _, engine::general_purpose};
use bincode::{config, encode_to_vec};
use ed25519_dalek::VerifyingKey as DalekPubkey;
use frost::keys::dkg;
use frost_ed25519::{self as frost, Ed25519Sha512, Identifier};
use rand::rngs::OsRng;
use solana_sdk::pubkey::Pubkey;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let threshold = 2;
    let mut rng = OsRng;

    let alice_id = Identifier::try_from(1u16)?;
    let bob_id = Identifier::try_from(2u16)?;
    let carol_id = Identifier::try_from(3u16)?;

    
// Print them out
println!("Alice ID: {:?}", alice_id);
println!("Bob ID: {:?}", bob_id);
println!("Carol ID: {:?}", carol_id);

    // ---- Round 1: Generate commitments for each participant ----
    let (alice_secret, alice_package) = dkg::part1(alice_id, 3, threshold, &mut rng)?;
    let (bob_secret, bob_package) = dkg::part1(bob_id, 3, threshold, &mut rng)?;
    let (carol_secret, carol_package) = dkg::part1(carol_id, 3, threshold, &mut rng)?;

    // ---- Prepare peer maps for Round 2 ----2
    // Each participant excludes their own Round 1 package
    let mut alice_peers = BTreeMap::new();
    alice_peers.insert(bob_id, bob_package.clone());
    alice_peers.insert(carol_id, carol_package.clone());

    let mut bob_peers = BTreeMap::new();
    bob_peers.insert(alice_id, alice_package.clone());
    bob_peers.insert(carol_id, carol_package.clone());

    let mut carol_peers = BTreeMap::new();
    carol_peers.insert(alice_id, alice_package.clone());
    carol_peers.insert(bob_id, bob_package.clone());

    println!("✅ Round 1 done");

    // ---- Round 2 ----
    let (alice_r2_secret, alice_r2_pkgs) = dkg::part2(alice_secret, &alice_peers)?;
    let (bob_r2_secret, bob_r2_pkgs) = dkg::part2(bob_secret, &bob_peers)?;
    let (carol_r2_secret, carol_r2_pkgs) = dkg::part2(carol_secret, &carol_peers)?;

    // Serialize
    let bytes = alice_r2_pkgs[&bob_id].serialize()?;


    println!("✅ Round 2 done  {:?}" , bytes);

    let pkg_back = dkg::round2::Package::deserialize(&bytes)?;

    println!("✅ pk before encoding{:?}" ,  alice_r2_pkgs[&bob_id].signing_share.to_scalar());


    println!("✅ pk after deconding{:?}" , pkg_back.signing_share.to_scalar());



    // ---- Build correct Round 2 package maps ----
    // Alice receives from Bob + Carol (NO self)
    let mut alice_r2_incoming = BTreeMap::new();
    alice_r2_incoming.insert(bob_id, bob_r2_pkgs[&alice_id].clone());
    alice_r2_incoming.insert(carol_id, carol_r2_pkgs[&alice_id].clone());

    // Bob receives from Alice + Carol (NO self)
    let mut bob_r2_incoming = BTreeMap::new();
    bob_r2_incoming.insert(alice_id, alice_r2_pkgs[&bob_id].clone());
    bob_r2_incoming.insert(carol_id, carol_r2_pkgs[&bob_id].clone());

    // Carol receives from Alice + Bob (NO self)
    let mut carol_r2_incoming = BTreeMap::new();
    carol_r2_incoming.insert(alice_id, alice_r2_pkgs[&carol_id].clone());
    carol_r2_incoming.insert(bob_id, bob_r2_pkgs[&carol_id].clone());

    // ---- Each participant now calls part3 ----


    // ---- Each participant's Round1 peer view ----
    let mut alice_round1_peers = BTreeMap::new();
    alice_round1_peers.insert(bob_id, bob_package.clone());
    alice_round1_peers.insert(carol_id, carol_package.clone());

    let mut bob_round1_peers = BTreeMap::new();
    bob_round1_peers.insert(alice_id, alice_package.clone());
    bob_round1_peers.insert(carol_id, carol_package.clone());

    let mut carol_round1_peers = BTreeMap::new();
    carol_round1_peers.insert(alice_id, alice_package.clone());
    carol_round1_peers.insert(bob_id, bob_package.clone());

    let (alice_key, alice_pub) =
        dkg::part3(&alice_r2_secret, &alice_round1_peers, &alice_r2_incoming)?;
    let (bob_key, bob_pub) = dkg::part3(&bob_r2_secret, &bob_round1_peers, &bob_r2_incoming)?;
    let (carol_key, carol_pub) =
        dkg::part3(&carol_r2_secret, &carol_round1_peers, &carol_r2_incoming)?;

    println!("✅ Round 3 done");
    println!("Alice pub: {:?}", alice_pub);
    println!("Bob   pub: {:?}", bob_pub);
    println!("Carol pub: {:?}", carol_pub);

    // ---- Verify that group keys match ----
    assert_eq!(alice_pub, bob_pub);
    assert_eq!(bob_pub, carol_pub);

    let vk_bytes = alice_pub.verifying_key().serialize()?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong key length"))?;
    let dalek = DalekPubkey::from_bytes(&vk_arr)?;
    let sol_pk = Pubkey::new_from_array(dalek.to_bytes());
    println!("Solana address: {}", sol_pk);


    let vk_bytes = bob_pub.verifying_key().serialize()?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong key length"))?;
    let dalek = DalekPubkey::from_bytes(&vk_arr)?;
    let sol_pk = Pubkey::new_from_array(dalek.to_bytes());
    println!("Solana address: {}", sol_pk);


    
    let message = b"ashu"; // message to sign 

    
    secret share for each node sign this message  ---> Signature from NODE 1 
    secret share for each node sign this message  ---> Signature from NODE 2
    secret share for each node sign this message  ---> Signature from NODE 3

    Send to one node SAY NODE 1 ADD EM ALL S1 + S2 + S3 ==> SIGNATURE , R 

    
    
    println!("{:?}", alice_key);



    Ok(())
}
