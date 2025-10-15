mod utils; // if in src/utils.rs
use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use base64::{
    Engine as _, 
    engine::general_purpose::{self, STANDARD},
};
use ed25519_dalek::VerifyingKey as DalekPubkey;
// use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use frost_dalek::{
    DistributedKeyGeneration, Parameters, Participant,
    keygen::{Coefficients, DkgState, RoundOne},
    nizk::NizkOfSecretKey,
};
use frost_ed25519::{
    Identifier,
    keys::{KeyPackage, PublicKeyPackage, dkg},
};
use rand_core::OsRng;
use reqwest;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::utils::parse_peer_shares;

#[derive(Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u32,
}

#[derive(Serialize, Deserialize)]
struct CommitmentsPayload {
    node_id: Vec<u8>,
    package: Vec<u8>, // serialized bytes of the Round1 package
}

#[derive(Clone)]
struct AppState {
    // Node identity / network
    pub node_id: Identifier, // this node’s Identifier (e.g., Identifier::try_from(1u16)?)
    pub n: u16,              // total participants
    pub t: u16,              // threshold
    pub peer_urls: Vec<String>, // HTTP endpoints for other nodes

    // ---- Round 1 state ----
    pub r1_secret: Arc<Mutex<Option<dkg::round1::SecretPackage>>>, // my Round1 secret (kept local)
    pub r1_package: Arc<Mutex<Option<dkg::round1::Package>>>,      // my Round1 package to broadcast
    pub r1_received: Arc<Mutex<BTreeMap<Identifier, dkg::round1::Package>>>, // peers’ Round1 packages

    // ---- Round 2 state ----
    pub r2_secret: Arc<Mutex<Option<dkg::round2::SecretPackage>>>, // my Round2 secret (kept local)
    pub r2_outgoing: Arc<Mutex<Option<BTreeMap<Identifier, dkg::round2::Package>>>>, // pkgs I produced (addressed to peers)
    pub r2_incoming: Arc<Mutex<BTreeMap<Identifier, dkg::round2::Package>>>, // pkgs I received (addressed to me)

    // ---- Final (after part3) ----
    pub key_package: Arc<Mutex<Option<KeyPackage>>>, // my private signing share package
    pub pubkey_package: Arc<Mutex<Option<PublicKeyPackage>>>, // shared group public key package
}

#[derive(Serialize, Deserialize)]
struct InitResponse {
    node_id: u32,
    commitments_count: usize,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct PeerCommitments {
    node_id: u32,
    commitments: Vec<[u8; 32]>, // the compressed Ristretto bytes
    proof_r: [u8; 32],
    proof_s: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerShare {
    node_id: u32,
    your_share: String, // base64 encoded
}
/// ---- Route: Initialize DKG ----
#[post("/dkg/init")]
pub async fn handle_dkg_init(data: web::Data<AppState>) -> impl Responder {
    // Acquire lock for Round 1 secret state
    let mut r1_secret_guard = data.r1_secret.lock().unwrap();
    // Prevent re-initialization
    if r1_secret_guard.is_some() {
        return HttpResponse::Ok().json(serde_json::json!({
            "node_id": format!("{:?}", data.node_id),
            "message": "Already initialized",
        }));
    }
    // ---- Step 1: parameters ----
    let threshold = data.t;
    let total = data.n;
    let mut rng = OsRng;

    // ---- Step 2: run part1 for this node ----
    let (secret_pkg, pkg) = match dkg::part1(data.node_id, total, threshold, &mut rng) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed in dkg::part1: {:?}", e)
            }));
        }
    };

    // ---- Step 3: store locally ----
    *r1_secret_guard = Some(secret_pkg);
    let mut r1_pkg_guard = data.r1_package.lock().unwrap();
    *r1_pkg_guard = Some(pkg.clone());

    // (optional) debug log
    println!(
        "✅ [Node {:?}] DKG init complete: generated Round1 commitments",
        data.node_id,
    );

    // ---- Step 4: respond ----
    HttpResponse::Ok().json(serde_json::json!({
        "node_id": format!("{:?}", data.node_id),
        "message": "DKG Round1 initialized successfully"
    }))
}

//RPC END POINT
#[post("/rpc")]
async fn rpc_handler(data: web::Data<AppState>, body: web::Json<RpcRequest>) -> impl Responder {
    match body.method.as_str() {
        "get_commitments" => match get_my_commitments(data).await {
            Ok(resp) => resp, // <-- don't wrap it in .json()
            Err(err) => err,
        },
        "get_my_share" => match get_my_share(&data, &body.params).await {
            Ok(resp) => resp, // <-- don't wrap it in .json()
            Err(err) => err,
        },
        _ => HttpResponse::BadRequest().body("unknown method"),
    }
}

// 👇 fetch commitments from peers
#[post("/dkg/fetch")]
pub async fn fetch_peer_commitments(data: web::Data<AppState>) -> impl Responder {
    let client = reqwest::Client::new();
    let mut all_bytes: Vec<Vec<u8>> = vec![];
    // ---- Step 1: fetch Round1 packages from all peers ----
    for peer in &data.peer_urls {
        let url = format!("{}/rpc", peer); // ✅ use the RPC route

        let rpc_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_commitments",
            "params": {},
            "id": 1
        });

        match client.post(&url).json(&rpc_body).send().await {
            Ok(resp) => match resp.bytes().await {
                Ok(bytes) => {
                    println!("📥 got commitments from {}", peer);
                    all_bytes.push(bytes.to_vec());
                }
                Err(e) => eprintln!("⚠️ failed to read bytes from {}: {}", peer, e),
            },
            Err(e) => eprintln!("❌ failed to reach {}: {}", peer, e),
        }
    }

    // ---- Step 2: decode peer payloads ----
    let mut peer_map = BTreeMap::new();

    for bytes in &all_bytes {
        match bincode::serde::decode_from_slice::<CommitmentsPayload, _>(
            bytes,
            bincode::config::standard(),
        ) {
            Ok((payload, _len)) => {
                // 1️⃣ Deserialize Identifier
                let peer_id = frost_ed25519::Identifier::deserialize(&payload.node_id)
                    .expect("invalid peer identifier");

                // 2️⃣ Deserialize Round1 package
                let pkg = dkg::round1::Package::deserialize(&payload.package)
                    .expect("invalid peer package");

                peer_map.insert(peer_id, pkg);
            }
            Err(e) => eprintln!("⚠️ failed to decode peer payload: {}", e),
        }
    }

    if peer_map.is_empty() {
        return HttpResponse::BadRequest().body("no valid peer packages received");
    }

    // ---- Step 3: retrieve my Round1 secret ----
    let my_secret_opt = data.r1_secret.lock().unwrap();
    let Some(my_secret) = my_secret_opt.as_ref() else {
        return HttpResponse::BadRequest().body("run /dkg/init first");
    };

    // ---- Step 3.5: store the received Round1 peer packages ----
    {
        let mut received_guard = data.r1_received.lock().unwrap();
        *received_guard = peer_map.clone();
    }

    // ---- Step 4: run Round 2 ----
    let (r2_secret, r2_pkgs) = match dkg::part2(my_secret.clone(), &peer_map) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("part2 error: {:?}", e));
        }
    };

    // ---- Step 5: store Round 2 state ----
    {
        let mut r2s = data.r2_secret.lock().unwrap();
        *r2s = Some(r2_secret);
        let mut out = data.r2_outgoing.lock().unwrap();
        *out = Some(r2_pkgs.clone());
    }

    println!("✅ node {:?} DKG Round 2 complete", data.node_id);

    HttpResponse::Ok().json(serde_json::json!({
        "node_id": format!("{:?}", data.node_id),
        "message": "Round 2 complete"
    }))
}

#[post("/dkg/fetch_shares")]
async fn fetch_peer_shares(data: web::Data<AppState>) -> impl Responder {
    let client = reqwest::Client::new();
    let mut incoming_r2_pkgs = BTreeMap::new();

    // ---- Step 1: ask each peer for their Round2 share addressed to me ----
    for peer in &data.peer_urls {
        let node_id_b64 = general_purpose::STANDARD.encode(data.node_id.serialize());
        let rpc_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_my_share",
            "params": { "node_id": node_id_b64 },
            "id": 1
        });

        let url = format!("{}/rpc", peer);
        match client.post(&url).json(&rpc_body).send().await {
            Ok(resp) => match resp.bytes().await {
                Ok(bytes) => {
                    println!("📥 got share from {}", peer);

                    // ---- Step 2: decode the CommitmentsPayload ----
                    let payload: CommitmentsPayload = match bincode::serde::decode_from_slice(
                        &bytes,
                        bincode::config::standard(),
                    ) {
                        Ok((p, _)) => p,
                        Err(e) => {
                            eprintln!("⚠️ failed to decode payload from {}: {}", peer, e);
                            continue;
                        }
                    };

                    // ---- Step 3: deserialize the package ----
                    match dkg::round2::Package::deserialize(&payload.package) {
                        Ok(pkg) => {
                            let peer_id = Identifier::deserialize(&payload.node_id)
                                .expect("peer id deserialize");
                            incoming_r2_pkgs.insert(peer_id, pkg);
                        }
                        Err(e) => {
                            eprintln!("⚠️ failed to deserialize package from {}: {}", peer, e)
                        }
                    }
                }
                Err(e) => eprintln!("⚠️ failed reading bytes from {}: {}", peer, e),
            },
            Err(e) => eprintln!("❌ failed to reach {}: {}", peer, e),
        }
    }

    // ---- Step 4: prepare Round1 peer map ----
    let mut round1_peers = BTreeMap::new();
    {
        let r1_guard = data.r1_package.lock().unwrap();
        let my_r1 = r1_guard.as_ref().expect("round1 not found");

        let mut peers_guard = data.r1_received.lock().unwrap();
        for (id, pkg) in peers_guard.iter() {
            round1_peers.insert(*id, pkg.clone());
        }
    }

    // ---- Step 5: get my Round2 secret ----
    let r2_secret_guard = data.r2_secret.lock().unwrap();
    let Some(r2_secret) = r2_secret_guard.as_ref() else {
        return HttpResponse::BadRequest().body("run /dkg/fetch first");
    };

    // ---- Step 6: finalize DKG with part3 ----
    let (key_pkg, pubkey_pkg) = match dkg::part3(&r2_secret, &round1_peers, &incoming_r2_pkgs) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("❌ DKG part3 failed: {:?}", e);
            return HttpResponse::InternalServerError().body("part3 failed");
        }
    };

    {
        let mut k = data.key_package.lock().unwrap();
        *k = Some(key_pkg);
        let mut p = data.pubkey_package.lock().unwrap();
        *p = Some(pubkey_pkg.clone());
    } 

    // ---- Step 7: print and return public key ----
    let vk_bytes = pubkey_pkg.verifying_key().serialize().unwrap();
    let group_hex = hex::encode(vk_bytes.clone());
    println!("✅ DKG complete! Shared verifying key (hex): {}", group_hex);

    //SOL ADDREESS BASE58
    let vk_arr: [u8; 32] = match vk_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::InternalServerError().body("wrong key length"),
    };
    let dalek = match DalekPubkey::from_bytes(&vk_arr) {
        Ok(d) => d,
        Err(_) => return HttpResponse::InternalServerError().body("invalid dalek key"),
    };
    let sol_pk = Pubkey::new_from_array(dalek.to_bytes());
    println!("Solana address: {}", sol_pk);

    HttpResponse::Ok().json(serde_json::json!({
        "verifying_key_hex": group_hex,
        "solana_addresss": sol_pk,
        "participants": incoming_r2_pkgs.len(),
        "message": "Round3 complete"
    }))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Node arguments: <id> <listen_addr>
    let node_id: u32 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "1".to_string())
        .parse()
        .unwrap();
    let listen = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8000".to_string());

    let peer_urls: Vec<String> = match node_id {
        1 => vec![
            "http://127.0.0.1:8001".into(),
            "http://127.0.0.1:8002".into(),
        ],
        2 => vec![
            "http://127.0.0.1:8000".into(),
            "http://127.0.0.1:8002".into(),
        ],
        3 => vec![
            "http://127.0.0.1:8000".into(),
            "http://127.0.0.1:8001".into(),
        ],
        _ => vec![],
    };

    println!("{:?}", peer_urls);
    // Shared state between routes
    let state = web::Data::new(AppState {
        // DKG parameters
        node_id: frost_ed25519::Identifier::try_from(node_id as u16).expect("invalid identifier"),
        n: 3,
        t: 2,

        // DKG round states
        peer_urls,
        r1_secret: Arc::new(Mutex::new(None)),
        r1_package: Arc::new(Mutex::new(None)),
        r1_received: Arc::new(Mutex::new(BTreeMap::new())),
        r2_secret: Arc::new(Mutex::new(None)),
        r2_outgoing: Arc::new(Mutex::new(None)),
        r2_incoming: Arc::new(Mutex::new(BTreeMap::new())),
        key_package: Arc::new(Mutex::new(None)),
        pubkey_package: Arc::new(Mutex::new(None)),
    });

    println!("🚀 Node {} running at http://{}", node_id, listen);
    println!("➡️  POST to /dkg/init to generate participant material");

    HttpServer::new({
        let state = state.clone();
        move || {
            App::new()
                .app_data(state.clone())
                .service(handle_dkg_init)
                .service(rpc_handler) // 👈 add
                .service(fetch_peer_commitments)
                .service(fetch_peer_shares)
        } // 👈 add
    })
    .bind(&listen)?
    .run()
    .await
}

//RPC METHODS ------------------------------------------------------------------------------------------------
async fn get_my_commitments(data: web::Data<AppState>) -> Result<HttpResponse, HttpResponse> {
    let guard = data.r1_package.lock().unwrap();
    let Some(pkg) = guard.as_ref() else {
        return Err(HttpResponse::BadRequest().body("run /dkg/init first"));
    };

    let encoded_pkg = pkg.serialize().map_err(|e| {
        HttpResponse::InternalServerError().body(format!("serialize error: {:?}", e))
    })?;

    let payload = CommitmentsPayload {
        node_id: data.node_id.serialize(),
        package: encoded_pkg,
    };

    let encoded = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
        .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?;

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(encoded))
}

async fn get_my_share(
    data: &web::Data<AppState>,
    params: &serde_json::Value,
) -> Result<HttpResponse, HttpResponse> {
    // ---- Step 1: extract target node id ----
    let target_node_id_b64 = params
        .get("node_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HttpResponse::BadRequest().body("missing node_id"))?;

    // decode the serialized identifier sent by requester
    let target_id_bytes = general_purpose::STANDARD
        .decode(target_node_id_b64)
        .map_err(|_| HttpResponse::BadRequest().body("invalid base64 node_id"))?;

    let target_id = frost_ed25519::Identifier::deserialize(&target_id_bytes)
        .map_err(|_| HttpResponse::BadRequest().body("invalid serialized identifier"))?;

    // ---- Step 2: get our outgoing round2 packages ----
    let r2_out_guard = data.r2_outgoing.lock().unwrap();
    let Some(r2_outgoing) = r2_out_guard.as_ref() else {
        return Err(HttpResponse::BadRequest().body("run /dkg/fetch first"));
    };

    // ---- Step 3: find the package addressed to that node ----
    let Some(pkg) = r2_outgoing.get(&target_id) else {
        return Err(HttpResponse::BadRequest().body("no package for requested node"));
    };

    // ---- Step 4: serialize and wrap into payload ----
    let pkg_bytes = pkg.serialize().map_err(|e| {
        HttpResponse::InternalServerError().body(format!("serialize error: {:?}", e))
    })?;

    let payload = CommitmentsPayload {
        node_id: data.node_id.serialize(), // this node’s ID (the sender)
        package: pkg_bytes,
    };

    // ---- Step 5: encode and respond ----
    let encoded = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
        .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?;

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(encoded))
}
