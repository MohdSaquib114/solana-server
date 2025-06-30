use axum::{extract::Json, response::IntoResponse, routing::post, Router};
use base64::Engine;
use bs58;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use solana_sdk::{instruction::Instruction, pubkey::Pubkey, system_instruction};
use spl_token::instruction as token_ix;
use std::{net::SocketAddr, str::FromStr};

#[derive(Debug, Serialize)]
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

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(gen_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(transfer_sol))
        .route("/send/token", post(transfer_token));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server is running on port {}",addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn gen_keypair() -> impl IntoResponse {
    let mut rng = OsRng;
    let kp = Keypair::generate(&mut rng);
    let res = serde_json::json!({
        "pubkey": bs58::encode(kp.public.as_bytes()).into_string(),
        "secret": bs58::encode(kp.secret.as_bytes()).into_string()
    });
    Json(ApiResponse::ok(res))
}

#[derive(Deserialize)]
struct CreateTokenParams {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

async fn create_token(Json(params): Json<CreateTokenParams>) -> impl IntoResponse {
    let mint = match Pubkey::from_str(&params.mint) {
        Ok(m) => m,
        Err(_) => return Json(ApiResponse::err("invalid mint")),
    };
    let authority = match Pubkey::from_str(&params.mint_authority) {
        Ok(a) => a,
        Err(_) => return Json(ApiResponse::err("invalid authority")),
    };
    let ix = match token_ix::initialize_mint(&spl_token::id(), &mint, &authority, None, params.decimals) {
        Ok(ix) => ix,
        Err(_) => return Json(ApiResponse::err("failed to build mint instruction")),
    };
    Json(ApiResponse::ok(serialize_instruction(&ix)))
}

#[derive(Deserialize)]
struct MintParams {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(Json(params): Json<MintParams>) -> impl IntoResponse {
    let mint = match Pubkey::from_str(&params.mint) {
        Ok(m) => m,
        Err(_) => return Json(ApiResponse::err("invalid mint")),
    };
    let dest = match Pubkey::from_str(&params.destination) {
        Ok(d) => d,
        Err(_) => return Json(ApiResponse::err("invalid destination")),
    };
    let authority = match Pubkey::from_str(&params.authority) {
        Ok(a) => a,
        Err(_) => return Json(ApiResponse::err("invalid authority")),
    };
    let ix = match token_ix::mint_to(&spl_token::id(), &mint, &dest, &authority, &[], params.amount) {
        Ok(ix) => ix,
        Err(_) => return Json(ApiResponse::err("failed to build mint instruction")),
    };
    Json(ApiResponse::ok(serialize_instruction(&ix)))
}

#[derive(Deserialize)]
struct SignParams {
    message: String,
    secret: String,
}

async fn sign_message(Json(params): Json<SignParams>) -> impl IntoResponse {
    let secret_bytes = match bs58::decode(&params.secret).into_vec() {
        Ok(b) if b.len() == 32 => b,
        _ => return Json(ApiResponse::err("invalid secret")),
    };
    let secret = SecretKey::from_bytes(&secret_bytes).unwrap();
    let public = PublicKey::from(&secret);
    let kp = Keypair { secret, public };
    let sig = kp.sign(params.message.as_bytes());
    let res = serde_json::json!({
        "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        "public_key": bs58::encode(public.as_bytes()).into_string(),
        "message": params.message
    });
    Json(ApiResponse::ok(res))
}

#[derive(Deserialize)]
struct VerifyParams {
    message: String,
    signature: String,
    pubkey: String,
}

async fn verify_message(Json(params): Json<VerifyParams>) -> impl IntoResponse {
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&params.signature) {
        Ok(b) => b,
        Err(_) => return Json(ApiResponse::err("invalid signature encoding")),
    };
    let sig = match ed25519_dalek::Signature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return Json(ApiResponse::err("invalid signature format")),
    };
    let pub_bytes = match bs58::decode(&params.pubkey).into_vec() {
        Ok(b) => b,
        Err(_) => return Json(ApiResponse::err("invalid public key encoding")),
    };
    let pubkey = match PublicKey::from_bytes(&pub_bytes) {
        Ok(pk) => pk,
        Err(_) => return Json(ApiResponse::err("bad public key format")),
    };
    let valid = pubkey.verify(params.message.as_bytes(), &sig).is_ok();
    Json(ApiResponse::ok(serde_json::json!({
        "valid": valid,
        "message": params.message,
        "pubkey": params.pubkey
    })))
}

#[derive(Deserialize)]
struct SolTransferParams {
    from: String,
    to: String,
    lamports: u64,
}

async fn transfer_sol(Json(params): Json<SolTransferParams>) -> impl IntoResponse {
    let from = match Pubkey::from_str(&params.from) {
        Ok(f) => f,
        Err(_) => return Json(ApiResponse::err("invalid from")),
    };
    let to = match Pubkey::from_str(&params.to) {
        Ok(t) => t,
        Err(_) => return Json(ApiResponse::err("invalid to")),
    };
    let ix = system_instruction::transfer(&from, &to, params.lamports);
    Json(ApiResponse::ok(serialize_instruction(&ix)))
}

#[derive(Deserialize)]
struct TokenTransferParams {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn transfer_token(Json(params): Json<TokenTransferParams>) -> impl IntoResponse {
    let dest = match Pubkey::from_str(&params.destination) {
        Ok(d) => d,
        Err(_) => return Json(ApiResponse::err("invalid destination")),
    };
    let mint = match Pubkey::from_str(&params.mint) {
        Ok(m) => m,
        Err(_) => return Json(ApiResponse::err("invalid mint")),
    };
    let owner = match Pubkey::from_str(&params.owner) {
        Ok(o) => o,
        Err(_) => return Json(ApiResponse::err("invalid owner")),
    };
    let ix = match token_ix::transfer(&spl_token::id(), &dest, &mint, &owner, &[], params.amount) {
        Ok(ix) => ix,
        Err(_) => return Json(ApiResponse::err("failed token transfer instruction")),
    };
    Json(ApiResponse::ok(serialize_instruction(&ix)))
}

fn serialize_instruction(ix: &Instruction) -> serde_json::Value {
    let accounts = ix.accounts.iter().map(|a| {
        serde_json::json!({
            "pubkey": a.pubkey.to_string(),
            "is_signer": a.is_signer,
            "is_writable": a.is_writable,
        })
    }).collect::<Vec<_>>();
    serde_json::json!({
        "program_id": ix.program_id.to_string(),
        "accounts": accounts,
        "instruction_data": base64::engine::general_purpose::STANDARD.encode(&ix.data)
    })
}
