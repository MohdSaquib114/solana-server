use axum::{extract::Json, response::IntoResponse, routing::post, Router};
use base64::Engine;
use bs58;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use solana_sdk::{instruction::Instruction, pubkey::Pubkey, system_instruction};
use spl_token::instruction as token_ops;
use std::{net::SocketAddr, str::FromStr};

#[derive(Debug, Serialize)]
struct ResponseBody<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ResponseBody<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn failure(message: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.to_string()),
        }
    }
}

#[tokio::main]
async fn main() {
    let api_routes = Router::new()
        .route("/keypair", post(handle_keypair_generation))
        .route("/mint/init", post(handle_mint_initialization))
        .route("/mint/issue", post(handle_token_minting))
        .route("/message/sign", post(handle_message_signing))
        .route("/message/verify", post(handle_signature_verification))
        .route("/transfer/sol", post(handle_sol_transfer))
        .route("/transfer/token", post(handle_token_transfer));

    let address = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running at http://{}", address);

    axum::Server::bind(&address)
        .serve(api_routes.into_make_service())
        .await
        .unwrap();
}

async fn handle_keypair_generation() -> impl IntoResponse {
    let mut rng = OsRng;
    let keys = Keypair::generate(&mut rng);

    let json = serde_json::json!({
        "pubkey": bs58::encode(keys.public.as_bytes()).into_string(),
        "secret": bs58::encode(keys.secret.as_bytes()).into_string()
    });

    Json(ResponseBody::success(json))
}

#[derive(Deserialize)]
struct NewMintParams {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

async fn handle_mint_initialization(Json(payload): Json<NewMintParams>) -> impl IntoResponse {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(m) => m,
        Err(_) => return Json(ResponseBody::failure("Invalid mint address")),
    };
    let authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(a) => a,
        Err(_) => return Json(ResponseBody::failure("Invalid mint authority")),
    };
    let instruction_data = match token_ops::initialize_mint(&spl_token::id(), &mint, &authority, None, payload.decimals) {
        Ok(ix) => ix,
        Err(_) => return Json(ResponseBody::failure("Failed to initialize mint")),
    };
    Json(ResponseBody::success(serialize_instruction(&instruction_data)))
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    recipient: String,
    authority: String,
    amount: u64,
}

async fn handle_token_minting(Json(payload): Json<TokenMintRequest>) -> impl IntoResponse {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(m) => m,
        Err(_) => return Json(ResponseBody::failure("Invalid mint")),
    };
    let destination = match Pubkey::from_str(&payload.recipient) {
        Ok(d) => d,
        Err(_) => return Json(ResponseBody::failure("Invalid recipient")),
    };
    let issuer = match Pubkey::from_str(&payload.authority) {
        Ok(a) => a,
        Err(_) => return Json(ResponseBody::failure("Invalid authority")),
    };
    let instruction_data = match token_ops::mint_to(&spl_token::id(), &mint, &destination, &issuer, &[], payload.amount) {
        Ok(ix) => ix,
        Err(_) => return Json(ResponseBody::failure("Minting failed")),
    };
    Json(ResponseBody::success(serialize_instruction(&instruction_data)))
}

#[derive(Deserialize)]
struct MessageSigningPayload {
    message: String,
    secret: String,
}

async fn handle_message_signing(Json(payload): Json<MessageSigningPayload>) -> impl IntoResponse {
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => return Json(ResponseBody::failure("Invalid secret key")),
    };
    let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
    let public = PublicKey::from(&secret);
    let keys = Keypair { secret, public };
    let signature = keys.sign(payload.message.as_bytes());

    let output = serde_json::json!({
        "signature": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        "public_key": bs58::encode(public.as_bytes()).into_string(),
        "message": payload.message
    });

    Json(ResponseBody::success(output))
}

#[derive(Deserialize)]
struct SignatureVerificationPayload {
    message: String,
    signature: String,
    pubkey: String,
}

async fn handle_signature_verification(Json(payload): Json<SignatureVerificationPayload>) -> impl IntoResponse {
    let decoded_sig = match base64::engine::general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Json(ResponseBody::failure("Invalid signature format")),
    };
    let signature = match ed25519_dalek::Signature::from_bytes(&decoded_sig) {
        Ok(sig) => sig,
        Err(_) => return Json(ResponseBody::failure("Bad signature")),
    };
    let decoded_key = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Json(ResponseBody::failure("Invalid public key")),
    };
    let pubkey = match PublicKey::from_bytes(&decoded_key) {
        Ok(pk) => pk,
        Err(_) => return Json(ResponseBody::failure("Bad public key format")),
    };
    let is_valid = pubkey.verify(payload.message.as_bytes(), &signature).is_ok();

    Json(ResponseBody::success(serde_json::json!({
        "valid": is_valid,
        "message": payload.message,
        "pubkey": payload.pubkey
    })))
}

#[derive(Deserialize)]
struct SolTransferPayload {
    from: String,
    to: String,
    lamports: u64,
}

async fn handle_sol_transfer(Json(payload): Json<SolTransferPayload>) -> impl IntoResponse {
    let sender = match Pubkey::from_str(&payload.from) {
        Ok(f) => f,
        Err(_) => return Json(ResponseBody::failure("Invalid sender address")),
    };
    let receiver = match Pubkey::from_str(&payload.to) {
        Ok(t) => t,
        Err(_) => return Json(ResponseBody::failure("Invalid receiver address")),
    };
    let sol_transfer = system_instruction::transfer(&sender, &receiver, payload.lamports);
    Json(ResponseBody::success(serialize_instruction(&sol_transfer)))
}

#[derive(Deserialize)]
struct TokenTransferPayload {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn handle_token_transfer(Json(payload): Json<TokenTransferPayload>) -> impl IntoResponse {
    let dest = match Pubkey::from_str(&payload.destination) {
        Ok(d) => d,
        Err(_) => return Json(ResponseBody::failure("Invalid destination")),
    };
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(m) => m,
        Err(_) => return Json(ResponseBody::failure("Invalid mint")),
    };
    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(o) => o,
        Err(_) => return Json(ResponseBody::failure("Invalid owner")),
    };
    let token_transfer = match token_ops::transfer(&spl_token::id(), &dest, &mint, &owner, &[], payload.amount) {
        Ok(ix) => ix,
        Err(_) => return Json(ResponseBody::failure("Token transfer instruction failed")),
    };
    Json(ResponseBody::success(serialize_instruction(&token_transfer)))
}

fn serialize_instruction(ix: &Instruction) -> serde_json::Value {
    let meta_info = ix.accounts.iter().map(|acc| {
        serde_json::json!({
            "pubkey": acc.pubkey.to_string(),
            "is_signer": acc.is_signer,
            "is_writable": acc.is_writable,
        })
    }).collect::<Vec<_>>();

    serde_json::json!({
        "program_id": ix.program_id.to_string(),
        "accounts": meta_info,
        "instruction_data": base64::engine::general_purpose::STANDARD.encode(&ix.data)
    })
}
