use axum::{extract::Json, http::StatusCode, response::IntoResponse, routing::post, Router};
use base64::Engine;
use bs58;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use solana_sdk::{instruction::Instruction, pubkey::Pubkey, system_instruction};
use spl_token::instruction as token_ops;
use std::{net::SocketAddr, str::FromStr};

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn ok(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }

    fn err(msg: &str) -> Self {
        Self { success: false, data: None, error: Some(msg.to_string()) }
    }
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

/// 1. Generate Keypair
async fn handle_keypair() -> impl IntoResponse {
    let mut rng = OsRng;
    let kp = Keypair::generate(&mut rng);
    let data = serde_json::json!({
        "pubkey": bs58::encode(kp.public.as_bytes()).into_string(),
        "secret": bs58::encode(kp.secret.as_bytes()).into_string()
    });
    (StatusCode::OK, Json(ApiResponse::ok(data)))
}

/// 2. Create Token (initialize mint)
#[derive(Deserialize)]
struct CreateTokenReq {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

async fn handle_create_token(Json(req): Json<CreateTokenReq>) -> impl IntoResponse {
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(m) => m,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid mint"))),
    };
    let authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid authority"))),
    };
    let ix = match token_ops::initialize_mint(&spl_token::id(), &mint, &authority, None, req.decimals) {
        Ok(ix) => ix,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Failed to build instruction"))),
    };
    let resp = instruction_to_response(ix);
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

/// 3. Mint Token
#[derive(Deserialize)]
struct MintTokenReq {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn handle_mint_token(Json(req): Json<MintTokenReq>) -> impl IntoResponse {
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid mint"))),
    };
    let dest = match Pubkey::from_str(&req.destination) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid destination"))),
    };
    let auth = match Pubkey::from_str(&req.authority) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid authority"))),
    };
    let ix = match token_ops::mint_to(&spl_token::id(), &mint, &dest, &auth, &[], req.amount) {
        Ok(ix) => ix,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Failed to build instruction"))),
    };
    let resp = instruction_to_response(ix);
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

/// 4. Sign Message
#[derive(Deserialize)]
struct SignMsgReq {
    message: String,
    secret: String,
}

async fn handle_sign_msg(Json(req): Json<SignMsgReq>) -> impl IntoResponse {
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid secret"))),
    };
    let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
    let public = PublicKey::from(&secret);
    let kp = Keypair { secret, public };
    let sig = kp.sign(req.message.as_bytes());
    let data = serde_json::json!({
        "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        "public_key": bs58::encode(public.as_bytes()).into_string(),
        "message": req.message
    });
    (StatusCode::OK, Json(ApiResponse::ok(data)))
}

/// 5. Verify Message
#[derive(Deserialize)]
struct VerifyMsgReq {
    message: String,
    signature: String,
    pubkey: String,
}

async fn handle_verify_msg(Json(req): Json<VerifyMsgReq>) -> impl IntoResponse {
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.signature) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid signature"))),
    };
    let signature = match ed25519_dalek::Signature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid signature format"))),
    };
    let key_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid public key"))),
    };
    let pubkey = match PublicKey::from_bytes(&key_bytes) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Bad public key"))),
    };
    let is_valid = pubkey.verify(req.message.as_bytes(), &signature).is_ok();
    let data = serde_json::json!({
        "valid": is_valid,
        "message": req.message,
        "pubkey": req.pubkey
    });
    (StatusCode::OK, Json(ApiResponse::ok(data)))
}

/// 6. Send SOL
#[derive(Deserialize)]
struct SendSolReq {
    from: String,
    to: String,
    lamports: u64,
}

async fn handle_send_sol(Json(req): Json<SendSolReq>) -> impl IntoResponse {
    let sender = match Pubkey::from_str(&req.from) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid from"))),
    };
    let receiver = match Pubkey::from_str(&req.to) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid to"))),
    };
    let ix = system_instruction::transfer(&sender, &receiver, req.lamports);
    let resp = instruction_to_response(ix);
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

/// 7. Send Token
#[derive(Deserialize)]
struct SendTokenReq {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn handle_send_token(Json(req): Json<SendTokenReq>) -> impl IntoResponse {
    let dest = match Pubkey::from_str(&req.destination) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid destination"))),
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid mint"))),
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Invalid owner"))),
    };
    let ix = match token_ops::transfer(&spl_token::id(), &dest, &mint, &owner, &[], req.amount) {
        Ok(ix) => ix,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(ApiResponse::err("Failed to build instruction"))),
    };
    let resp = instruction_to_response(ix);
    (StatusCode::OK, Json(ApiResponse::ok(resp)))
}

/// Helper to format sol instruction result
fn instruction_to_response(ix: Instruction) -> InstructionData {
    InstructionData {
        program_id: ix.program_id.to_string(),
        accounts: ix.accounts.into_iter().map(|a| AccountInfo {
            pubkey: a.pubkey.to_string(),
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        }).collect(),
        instruction_data: base64::engine::general_purpose::STANDARD.encode(ix.data),
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(handle_keypair))
        .route("/token/create", post(handle_create_token))
        .route("/token/mint", post(handle_mint_token))
        .route("/message/sign", post(handle_sign_msg))
        .route("/message/verify", post(handle_verify_msg))
        .route("/send/sol", post(handle_send_sol))
        .route("/send/token", post(handle_send_token));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
