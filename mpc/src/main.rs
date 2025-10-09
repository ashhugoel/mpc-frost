use actix_web::{App, HttpResponse, HttpServer, Responder, post, web};
use base64::{Engine as _, engine::general_purpose::STANDARD};
// use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use frost_dalek::{
    DistributedKeyGeneration, Parameters, Participant,
    keygen::{Coefficients, RoundOne},
    nizk::NizkOfSecretKey,
};
use reqwest;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

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

#[derive(Deserialize, Debug)]
struct PeerCommitments {
    node_id: u32,
    commitments: Vec<String>,
    proof_r: String, // base64 of scalar bytes
    proof_s: String, // base64 of scalar bytes
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

    println!(
        "[node {}] ✅ DKG initialized | commitments: {:?}",
        data.node_id, participant.commitments
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

// 👇 expose your commitments
#[post("/dkg/commitments")]
async fn get_my_commitments(data: web::Data<AppState>) -> impl Responder {
    let guard = data.participant.lock().unwrap();
    let Some(p) = guard.as_ref() else {
        return HttpResponse::BadRequest().body("init first");
    };
    // pseudocode: needs access to proof fields (see Options below)
    let commits_b64: Vec<String> = p
        .commitments
        .iter()
        .map(|pt| STANDARD.encode(pt.compress().to_bytes()))
        .collect();

    let (r_bytes, s_bytes) = p.proof_of_secret_key.to_bytess();

    let proof_r_b64 = STANDARD.encode(r_bytes);
    let proof_s_b64 = STANDARD.encode(s_bytes);

    // build final JSON
    HttpResponse::Ok().json(serde_json::json!({
        "node_id": data.node_id,
        "commitments": commits_b64,
        "proof_r": proof_r_b64,
        "proof_s": proof_s_b64
    }))
}

// 👇 fetch commitments from peers
#[post("/dkg/fetch")]
async fn fetch_peer_commitments(data: web::Data<AppState>) -> impl Responder {
    let client = reqwest::Client::new();
    let mut all: Vec<serde_json::Value> = vec![];

    for peer in &data.peer_urls {
        let url = format!("{}/dkg/commitments", peer);
        match client.post(&url).send().await {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    println!("📥 got commitments from {}", peer);
                    all.push(json);
                }
            }
            Err(e) => eprintln!("❌ failed to reach {}: {}", peer, e),
        }
    }

    // ---- decode them ----
    let peers: Vec<PeerCommitments> =
        serde_json::from_value(serde_json::Value::Array(all.clone())).unwrap();
    println!("{:?}", peers);

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

    println!("✅ node {} DKG Round 1 prepared {:?}", data.node_id, dkg.their_secret_shares() );

    HttpResponse::Ok().json(all)
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
                .service(get_my_commitments) // 👈 add
                .service(fetch_peer_commitments)
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
                let bytes = STANDARD.decode(s).expect("valid base64");
                let compressed = CompressedRistretto::from_slice(&bytes);
                compressed.decompress().expect("valid point")
            })
            .collect();

        // ---- decode proof fields (r, s) ----
        let r_bytes = STANDARD
            .decode(&peer.proof_r)
            .expect("valid base64 for proof_r");
        let s_bytes = STANDARD
            .decode(&peer.proof_s)
            .expect("valid base64 for proof_s");

        let r = Scalar::from_bytes_mod_order(r_bytes.try_into().expect("32 bytes for r"));
        let s = Scalar::from_bytes_mod_order(s_bytes.try_into().expect("32 bytes for s"));

        let proof = NizkOfSecretKey::from_scalars(r, s);

        // ---- construct full Participant ----
        let p = Participant {
            index: peer.node_id,
            commitments: decoded_points,
            proof_of_secret_key: proof,
        };

        others.push(p);
    }

    others
}
