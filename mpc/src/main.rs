mod utils; // if in src/utils.rs
use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use base64::{
    Engine as _,
    engine::general_purpose::{self, STANDARD},
};
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
use reqwest;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

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
    node_id: u32,
    commitments: Vec<[u8; 32]>, // the compressed Ristretto bytes
    proof_r: [u8; 32],
    proof_s: [u8; 32],
}

#[derive(Clone)]
struct AppState {
    node_id: u32,
    participant: Arc<Mutex<Option<Participant>>>,
    peer_urls: Vec<String>,
    coeffs: Arc<Mutex<Option<Coefficients>>>,
    dkg_state: Arc<Mutex<Option<DistributedKeyGeneration<RoundOne>>>>,
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
async fn handle_dkg_init(data: web::Data<AppState>) -> impl Responder {
    let mut p_guard = data.participant.lock().unwrap();

    // Prevent double initialization
    if p_guard.is_some() {
        return HttpResponse::Ok().json(InitResponse {
            node_id: data.node_id,
            commitments_count: 0,
            message: "Already initialized".into(),
        });
    }

    // Step 1: Setup parameters (t = 2, n = 3 for demo)
    let params = Parameters { t: 2, n: 3 };

    // Step 2: Create participant and coefficients
    let (participant, coeffs) = Participant::new(&params, data.node_id);

    //debugimg
    let compressed_commitments: Vec<[u8; 32]> = participant
        .commitments
        .iter()
        .map(|p| p.compress().to_bytes())
        .collect();
    
    println!(
        "[commitment for node  : {:?}",participant
    );


    println!(
        "[node {}] commitments ({} points): {:?}",
        data.node_id,
        compressed_commitments.len(),
        compressed_commitments
    );
    // Step 3: Store participant in state

    let commitments_count = participant.commitments.len();
    *p_guard = Some(participant);

    let mut coeff_guard = data.coeffs.lock().unwrap();
    *coeff_guard = Some(coeffs);

    // Step 4: Respond with summary
    HttpResponse::Ok().json(InitResponse {
        node_id: data.node_id,
        commitments_count: commitments_count,
        message: "DKG material initialized successfully".into(),
    })
}

//RPC END POINT
#[post("/rpc")]
async fn rpc_handler(data: web::Data<AppState>, body: web::Json<RpcRequest>) -> impl Responder {
    match body.method.as_str() {
        "get_commitments" => match get_my_commitments(&data).await {
            Ok(resp) => resp, // <-- don't wrap it in .json()
            Err(err) => err,
        },
        "get_my_share" => match get_my_share(&data, &body.params).await {
            Ok(json) => HttpResponse::Ok().json(json),
            Err(err) => err,
        },
        _ => HttpResponse::BadRequest().body("unknown method"),
    }
}

// 👇 fetch commitments from peers
#[post("/dkg/fetch")]
async fn fetch_peer_commitments(data: web::Data<AppState>) -> impl Responder {
    let client = reqwest::Client::new();
    let mut all: Vec<Vec<u8>> = vec![];

    let rpc_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "get_commitments",
        "params": {},
        "id": 1
    });

    for peer in &data.peer_urls {
        println!("{}", peer);
        let url = format!("{}/rpc", peer);
        match client.post(&url).json(&rpc_body).send().await {
            Ok(resp) => {
                match resp.bytes().await {
                    Ok(bytes) => {
                        println!("📥 got commitments from {}", peer);
                        all.push(bytes.to_vec()); // store raw bincode bytes
                    }
                    Err(e) => eprintln!("⚠️ failed to read bytes from {}: {}", peer, e),
                }
            }
            Err(e) => eprintln!("❌ failed to reach {}: {}", peer, e),
        }
    }

    // ---- decode raw bincode payloads ----
    let mut peers: Vec<PeerCommitments> = Vec::new();
    for bytes in &all {
        match bincode::serde::decode_from_slice::<PeerCommitments, _>(
            bytes,
            bincode::config::standard(),
        ) {
            Ok((payload, _len)) => {
                // convert CommitmentsPayload into PeerCommitments if needed
                peers.push(payload);
            }
            Err(e) => eprintln!("⚠️ failed to decode peer commitment: {}", e),
        }
    }

    // println!("{:?} here we have peers commitment", peers);

    let mut others = build_peer_participants(peers);
    let params = Parameters { t: 2, n: 3 };

    // ---- get my own participant + coefficients ----
    let my_participant = data.participant.lock().unwrap();
    let my_coeffs = data.coeffs.lock().unwrap();

    if my_participant.is_none() || my_coeffs.is_none() {
        return HttpResponse::BadRequest().body("run /dkg/init first");
    }

    let my_p = my_participant.as_ref().unwrap();
    let my_c = my_coeffs.as_ref().unwrap();

    let dkg = DistributedKeyGeneration::<_>::new(&params, &my_p.index, &my_c, &mut others)
        .expect("DKG round1 init");

    let mut dkg_guard = data.dkg_state.lock().unwrap();
    *dkg_guard = Some(dkg.clone());

    println!("✅ node {} DKG Round 1 prepared", data.node_id,);

    HttpResponse::Ok().json(all)
}

#[post("/dkg/fetch_shares")]
async fn fetch_peer_shares(data: web::Data<AppState>) -> impl Responder {
    let client = reqwest::Client::new();
    let mut all_shares: Vec<serde_json::Value> = vec![];

    //  want the share for each peer
    for peer in &data.peer_urls {
        let rpc_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "get_my_share",
            "params": { "node_id": data.node_id },
            "id": 1 //not used at all
        });

        let url = format!("{}/rpc", peer);
        match client.post(&url).json(&rpc_body).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    println!("📥 got share from {}", peer);
                    all_shares.push(json);
                }
            }
            Err(e) => eprintln!("❌ failed to reach {}: {}", peer, e),
        }
    }



    let othershares = parse_peer_shares(&all_shares);

    let p_guard = data.participant.lock().unwrap();

    let participant = match p_guard.as_ref() {
        Some(p) => p,
        None => return HttpResponse::BadRequest().body("Participant not initialized"),
    };
    let mut dkg_state_guard = data.dkg_state.lock().unwrap();

    // Take ownership of the RoundOne state
    let round_one_state = match dkg_state_guard.take() {
        Some(s) => s,
        None => return HttpResponse::BadRequest().body("DKG state not initialized"),
    };

    // Compute RoundTwo (consumes RoundOne)
    let my_round2 = match round_one_state.to_round_two(othershares) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("⚠️ Failed to compute Round 2: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed round 2");
        }
    };

    // Optionally store the RoundTwo state back in the mutex if you need it later
    // *dkg_state_guard = Some(my_round2.clone().into_round_one()); // optional

    // Finish DKG
    let (group_key, _secret_key) = match my_round2.finish(participant.public_key().unwrap()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("⚠️ Failed to Finish DKG : {:?}", e);
            return HttpResponse::InternalServerError().body("❌ Failed to finish DKG");
        }
    };

    // ---- Encode for JSON ----
    let compressed = group_key.to_bytes();
    let group_b64 = general_purpose::STANDARD.encode(&compressed);

    println!("✅ Group key (base64): {}", group_b64);

    HttpResponse::Ok().json(serde_json::json!({
        "group_key": group_b64,
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
        node_id,
        participant: Arc::new(Mutex::new(None)),
        coeffs: Arc::new(Mutex::new(None)),
        dkg_state: Arc::new(Mutex::new(None)),
        peer_urls, // 👈 added here
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

fn build_peer_participants(peers: Vec<PeerCommitments>) -> Vec<Participant> {
    let mut others = Vec::new();

    for peer in peers {
        // ---- decode commitments ----
        let decoded_points: Vec<RistrettoPoint> = peer
            .commitments
            .iter()
            .map(|s| {
                let compressed = CompressedRistretto::from_slice(s);
                compressed.decompress().expect("valid point")
            })
            .collect();

        // ---- decode proof fields (r, s) ----
        let r = Scalar::from_bytes_mod_order(peer.proof_r);
        let s = Scalar::from_bytes_mod_order(peer.proof_s);
        let proof = NizkOfSecretKey::from_scalars(r, s);

        // ---- construct full Participant ----
        let p = Participant {
            index: peer.node_id,
            commitments: decoded_points.clone(),
            proof_of_secret_key: proof,
        };
        
        println!("[node {}] 🔍 Decoded commitments:", peer.node_id);
        println!(" Decoded commitments: {:?}", decoded_points);
        
        for (i, point) in decoded_points.iter().enumerate() {
            let compressed_bytes = point.compress().to_bytes();
            println!(
                "   commitment[{}] compressed bytes: {:?}",
                i, compressed_bytes
            );
        }
        

        others.push(p);
    }

    others
}

// Helper to print points deterministically
fn print_points(name: &str, points: &[RistrettoPoint]) {
    println!("{}:", name);
    for (i, pt) in points.iter().enumerate() {
        let bytes = pt.compress().to_bytes();
        println!("Point {}: {:?}", i, bytes);
    }
}

//RPC METHODS ------------------------------------------------------------------------------------------------
async fn get_my_commitments(data: &web::Data<AppState>) -> Result<HttpResponse, HttpResponse> {
    let guard = data.participant.lock().unwrap();
    let Some(p) = guard.as_ref() else {
        return Err(HttpResponse::BadRequest().body("init first"));
    };

    // ✅ deterministic print before encoding
    print_points("Before encoding", &p.commitments);

    // Serialize commitments as bytes
    let commitments: Vec<[u8; 32]> = p
        .commitments
        .iter()
        .map(|pt| pt.compress().to_bytes())
        .collect();
    let (r_bytes, s_bytes) = p.proof_of_secret_key.to_bytess();

    let payload = PeerCommitments {
        node_id: data.node_id,
        commitments: commitments.clone(),
        proof_r: r_bytes,
        proof_s: s_bytes,
    };

    // Encode
    let encoded = bincode::serde::encode_to_vec(&payload, bincode::config::standard())
        .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?;

    // Decode immediately
    let decoded: PeerCommitments =
        bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
            .map_err(|e| HttpResponse::InternalServerError().body(e.to_string()))?
            .0;

    // Rebuild points for round-trip check
    let decoded_points: Vec<RistrettoPoint> = decoded
        .commitments
        .iter()
        .map(|b| {
            CompressedRistretto::from_slice(b)
                .decompress()
                .expect("invalid point")
        })
        .collect();

    // ✅ deterministic print after decoding
    print_points("After decoding", &decoded_points);

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(encoded))
}

async fn get_my_share(
    data: &web::Data<AppState>,
    params: &serde_json::Value,
) -> Result<serde_json::Value, HttpResponse> {
    let node_id = match params.get("node_id").and_then(|v| v.as_u64()) {
        Some(id) => id as usize,
        None => return Err(HttpResponse::BadRequest().body("missing or invalid node_id")),
    };

    let dkg_state = data.dkg_state.lock().unwrap();
    let state = dkg_state.as_ref().ok_or_else(|| {
        HttpResponse::BadRequest().body("DKG state not initialized you need dkg/inti and dkg/fetch")
    })?;

    let shares = state.their_secret_shares().expect("Current node shares");

    for share in shares.iter() {
        println!(
            "🟢 share index: {}, bytes: {:?}",
            share.index,
            share.to_bytes()
        );
    }

    let other_share = shares
        .iter()
        .find(|s| s.index as usize == node_id)
        .ok_or_else(|| HttpResponse::BadRequest().body("node_id not found"))?
        .clone();

    let share_bytes = STANDARD.encode(other_share.to_bytes());

    Ok(serde_json::json!({
        "node_id": data.node_id,
        "your_share": share_bytes,
    }))
}
