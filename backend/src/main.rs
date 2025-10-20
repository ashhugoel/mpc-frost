use actix_web::{App, HttpResponse, HttpServer, Responder, get, post, web};
use ed25519_dalek::Signature as DalekSig;
use ed25519_dalek::VerifyingKey as DalekPubkey;
use frost_ed25519::keys::PublicKeyPackage;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, Signature, SigningPackage, VerifyingKey, aggregate};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

// ---------- GLOBAL MPC NODE LIST ----------
const MPC_NODES: [MpcNode; 3] = [
    MpcNode {
        id: 1,
        address: "127.0.0.1:8000",
    },
    MpcNode {
        id: 2,
        address: "127.0.0.1:8001",
    },
    MpcNode {
        id: 3,
        address: "127.0.0.1:8002",
    },
];

// ---------- SHARED APP STATE ----------
struct AppState {
    gmail_to_solana: Mutex<HashMap<String, PublicKeyPackage>>,
    signing_commitments: Mutex<BTreeMap<Identifier, SigningCommitments>>,
    signing_package: Mutex<Option<SigningPackage>>,
}

// ---------- MODELS ----------

#[derive(Serialize, Deserialize, Clone, Copy)]
struct MpcNode {
    id: u32,
    address: &'static str,
}

#[derive(Serialize, Deserialize)]
struct SignupRequest {
    gmail: String,
}

#[derive(Serialize, Deserialize)]
struct SignupResponse {
    name: String,
    solana_address: Option<String>,
    status: String,
}

// ---------- ROUTE HANDLER ----------
#[post("/signup")]
async fn signup(payload: web::Json<SignupRequest>, data: web::Data<AppState>) -> impl Responder {
    let client = Client::new();
    let mut all_ok = true;
    let mut solana_address: Option<String> = None;

    // ROUND 1
    for node in MPC_NODES {
        let url = format!("http://{}/dkg/init", node.address);
        println!("→ Sending round 1 to {}", url);
        let resp = client.post(&url).send().await;

        match resp {
            Ok(res) if res.status().is_success() => {
                println!("✔ Node {} responded 200 OK", node.id);
            }
            Ok(res) => {
                println!("✖ Node {} failed with status {}", node.id, res.status());
                all_ok = false;
            }
            Err(e) => {
                println!("⚠ Node {} not reachable: {}", node.id, e);
                all_ok = false;
            }
        }
    }

    // ROUND 2
    for node in MPC_NODES {
        let url = format!("http://{}/dkg/fetch", node.address);
        println!("→ Sending round 2 to {}", url);
        let resp = client.post(&url).send().await;

        match resp {
            Ok(res) if res.status().is_success() => println!("✔ Node {} responded 200 OK", node.id),
            Ok(res) => {
                println!("✖ Node {} failed with status {}", node.id, res.status());
                all_ok = false;
            }
            Err(e) => {
                println!("⚠ Node {} not reachable: {}", node.id, e);
                all_ok = false;
            }
        }
    }

    // ROUND 3
    for node in MPC_NODES {
        let url = format!("http://{}/dkg/fetch_shares", node.address);
        println!("→ Sending round 3 to {}", url);

        let resp = client.post(&url).send().await;

        match resp {
            Ok(res) if res.status().is_success() => {
                // Parse JSON body
                let json_body: serde_json::Value = res
                    .json()
                    .await
                    .unwrap_or_else(|_| serde_json::json!({"error": "invalid json"}));

                println!("✔ Node {} responded 200 OK", node.id);

                // 🪪 Extract Solana address (for display/logging)
                if let Some(addr) = json_body.get("solana_address") {
                    if let Some(addr_str) = addr.as_str() {
                        println!("🔹 Solana address: {}", addr_str);
                        solana_address = Some(addr_str.to_string());
                    }
                }

                // 🧠 Extract and store full PublicKeyPackage (decoded)
                if let Some(pkg_val) = json_body.get("pubkey_package_b58") {
                    if let Some(pkg_b58) = pkg_val.as_str() {
                        println!(
                            "🧩 Received PublicKeyPackage ({} bytes base58)",
                            pkg_b58.len()
                        );

                        // Decode Base58 → bytes
                        match bs58::decode(pkg_b58).into_vec() {
                            Ok(pkg_bytes) => {
                                // Deserialize bytes → PublicKeyPackage
                                match PublicKeyPackage::deserialize(&pkg_bytes) {
                                    Ok(pubkey_pkg) => {
                                        let mut map = data.gmail_to_solana.lock().unwrap();
                                        map.insert(node.id.to_string(), pubkey_pkg);
                                        println!(
                                            "✅ Stored deserialized PublicKeyPackage for node {}",
                                            node.id
                                        );
                                    }
                                    Err(e) => {
                                        println!(
                                            "❌ Failed to deserialize PublicKeyPackage from node {}: {:?}",
                                            node.id, e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!("⚠️ Node {} sent invalid base58 package: {}", node.id, e);
                            }
                        }
                    } else {
                        println!("⚠️ Node {} has invalid pubkey_package_b58 format", node.id);
                    }
                } else {
                    println!("⚠️ Node {} did not include pubkey_package_b58", node.id);
                }
            }

            Ok(res) => {
                println!("✖ Node {} failed with status {}", node.id, res.status());
                all_ok = false;
            }
            Err(e) => {
                println!("⚠ Node {} not reachable: {}", node.id, e);
                all_ok = false;
            }
        }
    }

    // FINAL RESPONSE
    if all_ok {
        let response = SignupResponse {
            name: payload.gmail.clone(),
            solana_address,
            status: "All nodes initialized successfully ✅".to_string(),
        };
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "Some nodes failed during DKG init"
        }))
    }
}

#[post("/aggregate_nonce_commitments")]
async fn aggregate_nonce_commitments(data: web::Data<AppState>) -> impl Responder {
    let client = Client::new();
    let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    let mut results = vec![];

    let rpc_body = json!({
        "jsonrpc": "2.0",
        "method": "get_nonce_commitment",
        "params": {},
        "id": 1
    });

    for node in MPC_NODES.iter() {
        let url = format!("http://{}/rpc", node.address);
        println!(
            "Requesting nonce commitment from Node {} ({})",
            node.id, url
        );

        match client.post(&url).json(&rpc_body).send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => {
                    println!("✅ Node {} ", node.id);

                    let parsed: serde_json::Value = match serde_json::from_str(&body) {
                        Ok(p) => p,
                        Err(e) => {
                            println!("⚠️ Node {} returned invalid JSON: {}", node.id, e);
                            continue;
                        }
                    };

                    // ---- Step 2: decode node_id
                    let id_b58 = parsed.get("node_id").and_then(|v| v.as_str());
                    let Some(id_str) = id_b58 else {
                        println!("⚠️ Node {} missing node_id", node.id);
                        continue;
                    };

                    let id_bytes = match bs58::decode(id_str).into_vec() {
                        Ok(b) => b,
                        Err(e) => {
                            println!("⚠️ Node {}: invalid base58 id: {}", node.id, e);
                            continue;
                        }
                    };

                    let identifier = match Identifier::deserialize(&id_bytes) {
                        Ok(i) => i,
                        Err(e) => {
                            println!(
                                "⚠️ Node {}: failed to deserialize Identifier: {:?}",
                                node.id, e
                            );
                            continue;
                        }
                    };

                    // ---- Step 3: decode nonce_commitment_b58
                    let comm_b58 = parsed.get("nonce_commitment_b58").and_then(|v| v.as_str());
                    let Some(comm_str) = comm_b58 else {
                        println!("⚠️ Node {} missing nonce_commitment_b58", node.id);
                        continue;
                    };

                    let comm_bytes = match bs58::decode(comm_str).into_vec() {
                        Ok(v) => v,
                        Err(e) => {
                            println!("⚠️ Node {} invalid base58 commitment: {}", node.id, e);
                            continue;
                        }
                    };

                    // ---- Step 4: deserialize to Commitments
                    match SigningCommitments::deserialize(&comm_bytes) {
                        Ok(c) => {
                            commitments.insert(identifier, c);
                            results.push(json!({
                                "node_id": node.id,
                                "status": "ok"
                            }));
                        }
                        Err(e) => {
                            println!(
                                "⚠️ Node {} failed to deserialize commitments: {:?}",
                                node.id, e
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("⚠️ Failed to read response from node {}: {}", node.id, e);
                }
            },
            Err(e) => {
                println!("❌ Node {} unreachable: {}", node.id, e);
            }
        }
    }

    {
        let mut commitment_guard = data
            .signing_commitments
            .lock()
            .expect("Unable to get the lock");
        *commitment_guard = commitments.clone()
    }

    let message = b"im the best ";

    let signing_pkg = SigningPackage::new(commitments, message);

    {
        let mut sign_pkg = data.signing_package.lock().expect("Unable to get lock");
        *sign_pkg = Some(signing_pkg);
    }

    HttpResponse::Ok().json(json!({
        "message": "Fetched nonce commitments from all nodes",
        "results": results
    }))
}

#[get("/get_signing_package")]
async fn get_signing_package(data: web::Data<AppState>) -> impl Responder {
    // Acquire the lock
    let guard = data.signing_package.lock().expect("lock poisoned");

    // Check if SigningPackage is initialized
    let Some(sign_pkg) = guard.as_ref() else {
        return HttpResponse::BadRequest().json(json!({
            "error": "Signing package not yet initialized. Run /aggregate_nonce_commitments first."
        }));
    };

    let serialized = sign_pkg
        .serialize()
        .expect("Unable to serialzie the signing package");
    // Encode bytes in Base58 for safe transport
    let b58 = bs58::encode(serialized).into_string();

    HttpResponse::Ok().json(json!({
        "signing_package_b58": b58,
        "message": "Signing package ready for nodes to sign"
    }))
}

#[post("/aggregate_signature_shares")]
async fn aggregate_signature_shares(data: web::Data<AppState>) -> impl Responder {
    let client = Client::new();
    let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    let mut results = vec![];

    for node in MPC_NODES.iter() {
        let url = format!("http://{}/dkg/signature", node.address);
        println!(
            "📡 Requesting signature share from Node {} ({})",
            node.id, url
        );

        match client.post(&url).send().await {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(json_resp) => {
                    println!("✅ Node {} responded", node.id);

                    let Some(id_str) = json_resp.get("node_id").and_then(|v| v.as_str()) else {
                        println!("⚠️ Node {} missing node_id", node.id);
                        continue;
                    };

                    let id_bytes = match bs58::decode(id_str).into_vec() {
                        Ok(b) => b,
                        Err(e) => {
                            println!("⚠️ Invalid base58 node_id from node {}: {}", node.id, e);
                            continue;
                        }
                    };

                    let identifier = match Identifier::deserialize(&id_bytes) {
                        Ok(i) => i,
                        Err(e) => {
                            println!(
                                "⚠️ Failed to deserialize Identifier from node {}: {:?}",
                                node.id, e
                            );
                            continue;
                        }
                    };

                    // ---- Extract signature share
                    let Some(sig_b58) = json_resp.get("node_sig").and_then(|v| v.as_str()) else {
                        println!("⚠️ Node {} missing node_sig", node.id);
                        continue;
                    };

                    let sig_bytes = match bs58::decode(sig_b58).into_vec() {
                        Ok(b) => b,
                        Err(e) => {
                            println!(
                                "⚠️ Invalid base58 signature share from node {}: {}",
                                node.id, e
                            );
                            continue;
                        }
                    };

                    match SignatureShare::deserialize(&sig_bytes) {
                        Ok(sig_share) => {
                            shares.insert(identifier, sig_share);
                            results.push(json!({
                                "node_id": node.id,
                                "status": "ok"
                            }));
                        }
                        Err(e) => {
                            println!(
                                "⚠️ Node {}: failed to deserialize signature share: {:?}",
                                node.id, e
                            );
                            results.push(json!({
                                "node_id": node.id,
                                "status": format!("deserialize error: {:?}", e)
                            }));
                        }
                    }
                }
                Err(e) => {
                    println!("⚠️ Invalid JSON from node {}: {}", node.id, e);
                    results.push(json!({
                        "node_id": node.id,
                        "status": "invalid JSON"
                    }));
                }
            },
            Err(e) => {
                println!("❌ Node {} unreachable: {}", node.id, e);
                results.push(json!({
                    "node_id": node.id,
                    "status": "unreachable"
                }));
            }
        }
    }

    let signpkg_guard = data.signing_package.lock().expect("Unable to get lock");
    let Some(sign_pkg) = signpkg_guard.as_ref() else {
        return HttpResponse::BadRequest()
            .body("Please singing package not made yet run  /aggregate_nonce_commitments ");
    };

    let gmail_to_solana_guard = data.gmail_to_solana.lock().unwrap();
    let pubkey_pkg = gmail_to_solana_guard.values().next().cloned();

    let Some(pubkey_pkg) = pubkey_pkg else {
        return HttpResponse::BadRequest()
            .body("⚠️ No valid PublicKeyPackage found in gmail_to_solana");
    };
    let group_sig = aggregate(sign_pkg, &shares, &pubkey_pkg);
    println!("✅ Collected {:?} signature shares.", group_sig);

    let _ = verify_group_signature(&group_sig.unwrap(), &pubkey_pkg, b"im the best ");

    HttpResponse::Ok().json(json!({
        "message": "Fetched signature shares from all nodes",
        "shares_collected": shares.len(),
        "results": results
    }))
}

// ---------- MAIN ----------
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Server running at http://127.0.0.1:3000");

    let state = web::Data::new(AppState {
        gmail_to_solana: Mutex::new(HashMap::new()),
        signing_commitments: Mutex::new(BTreeMap::new()),
        signing_package: Mutex::new(None),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(signup)
            .service(get_signing_package)
            .service(aggregate_signature_shares)
            .service(aggregate_nonce_commitments)
    })
    .bind(("127.0.0.1", 3000))?
    .run()
    .await
}

fn verify_group_signature(
    group_sig: &Signature,
    group_pubkey: &PublicKeyPackage,
    message: &[u8],
) -> Result<bool, anyhow::Error> {
    // ---- Step 1: Extract verifying key bytes
    let vk_bytes = group_pubkey.verifying_key().serialize()?;
    let vk_arr: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong verifying key length"))?;
    let dalek_vk = DalekPubkey::from_bytes(&vk_arr)?;

    // ---- Step 2: Serialize FROST group signature
    let sig_bytes_vec = group_sig.serialize()?; // Vec<u8> (64 bytes)
    println!(
        "📦 Base58 encoded group signature: {}",
        bs58::encode(&sig_bytes_vec).into_string()
    );

    let sig_bytes: [u8; 64] = sig_bytes_vec
        .try_into()   
        .map_err(|_| anyhow::anyhow!("wrong signature length"))?;

    // ---- Step 3: Convert to dalek signature
    let dalek_sig = DalekSig::from_bytes(&sig_bytes);

    // ---- Step 4: Verify
    match dalek_vk.verify_strict(message, &dalek_sig) {
        Ok(_) => {
            println!("✅ Signature verified successfully");
            Ok(true)
        }
        Err(e) => {
            eprintln!("❌ Signature verification failed: {:?}", e);
            Ok(false)
        }
    }
}
