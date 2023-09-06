// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![forbid(unsafe_code)]
#![warn(
    missing_copy_implementations,
    missing_debug_implementations,
    unused_crate_dependencies,
    clippy::missing_const_for_fn,
    unused_extern_crates
)]

#[macro_use]
extern crate tracing;

mod config;
mod error;
mod version;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::any,
    Json, Router,
};
use clap::Parser;
use ethers::{prelude::*, signers::coins_bip39::English, utils::keccak256};
use k256::ecdsa::SigningKey;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::json;

use config::Config;
use error::AppError;
use tokio::sync::OnceCell;
use version::Version;

fn clap_about() -> String {
    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION");
    let authors = env!("CARGO_PKG_AUTHORS");
    name + " " + version + "\n" + authors
}

#[derive(Parser)]
#[clap(version, about = clap_about())]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// run this service
    #[clap(name = "run")]
    Run(RunOpts),
}

/// A subcommand for run
#[derive(Parser)]
struct RunOpts {
    /// Chain config path
    #[clap(short = 'c', long = "config", default_value = "config.toml")]
    config_path: String,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    match opts.subcmd {
        SubCommand::Run(opts) => {
            if let Err(e) = run(opts) {
                warn!("err: {:?}", e);
            }
        }
    }
}

static ONCE: OnceCell<String> = OnceCell::const_new();

async fn set_master_key(m: String) {
    ONCE.get_or_init(|| async { m }).await;
}
fn get_master_key() -> &'static String {
    ONCE.get().unwrap()
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<()> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let config = Config::new(&opts.config_path);
    set_master_key(config.master_key.clone()).await;

    // init tracer
    cloud_util::tracer::init_tracer("cloud_kms".to_string(), &config.log_config)
        .map_err(|e| println!("tracer init err: {e}"))
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let app = Router::new()
        .with_state(Arc::new(RwLock::new(config)))
        .route("/api/:version/keys", any(handle_keys))
        .route("/api/:version/keys/addr", any(handle_keys_addr))
        .route("/api/:version/keys/sign", any(handle_sign))
        .route("/api/:version/keys/verify", any(handle_verify))
        .route_layer(middleware::from_fn(handle_http_error))
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "code": 404,
                    "message": "Not Found",
                })),
            )
        });

    info!("kms listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    anyhow::bail!("unreachable!")
}

async fn handle_http_error<B>(req: Request<B>, next: Next<B>) -> impl IntoResponse {
    let response = next.run(req).await;
    let status_code = response.status();
    if status_code != StatusCode::OK && status_code != StatusCode::INTERNAL_SERVER_ERROR {
        (
            status_code,
            Json(json!({
                "code": status_code.as_u16(),
                "message": status_code.canonical_reason().unwrap_or_default(),
            })),
        )
            .into_response()
    } else {
        response
    }
}

fn ok<T: serde::Serialize>(data: T) -> Result<impl IntoResponse, AppError> {
    Ok((
        StatusCode::OK,
        Json(json!({
            "code": 200,
            "message": "OK",
            "data": data,
        })),
    ))
}

#[derive(Debug, Serialize, Deserialize)]
enum CryptoType {
    SM2,
    Secp256k1,
}

#[derive(Debug, Serialize, Default, Deserialize)]
#[serde(default)]
struct RequestParams {
    #[serde(skip_serializing_if = "String::is_empty")]
    user_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_type: Option<CryptoType>,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<Signature>,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
}

fn derive_wallet(user_code: &str) -> Result<Wallet<SigningKey>, AppError> {
    let user_code_hash = keccak256(user_code);
    let account = u32::from_be_bytes(user_code_hash[0..4].try_into().unwrap());
    let index = u32::from_be_bytes(user_code_hash[4..8].try_into().unwrap());
    let path = format!("m/44'/60'/{}'/0/{}", account, index);
    debug!("path: {}", path);
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(get_master_key().as_str())
        .derivation_path(&path)?
        .build()?;
    Ok(wallet)
}

async fn handle_keys(
    _version: Version,
    Json(params): Json<RequestParams>,
) -> Result<impl IntoResponse, AppError> {
    debug!("params: {:?}", params);
    if params.user_code.is_empty() {
        return Err(anyhow::anyhow!("user_code missing").into());
    }
    match params.crypto_type {
        Some(CryptoType::SM2) => Err(anyhow::anyhow!("SM2 unimplemented").into()),
        Some(CryptoType::Secp256k1) => {
            let wallet = derive_wallet(&params.user_code)?;
            // TODO: rm
            debug!("{}", hex::encode_upper(wallet.signer().to_bytes()));
            let public_key = hex::encode_upper(wallet.signer().verifying_key().to_sec1_bytes());
            ok(json!({
                "user_code": params.user_code,
                "crypto_type": params.crypto_type,
                "address": wallet.address(),
                "public_key": public_key,
            }))
        }
        None => Err(anyhow::anyhow!("crypto_type missing").into()),
    }
}

async fn handle_keys_addr(
    _version: Version,
    Json(params): Json<RequestParams>,
) -> Result<impl IntoResponse, AppError> {
    debug!("params: {:?}", params);
    if params.address.is_empty() {
        return Err(anyhow::anyhow!("address missing").into());
    }
    match params.crypto_type {
        Some(CryptoType::SM2) => Err(anyhow::anyhow!("SM2 unimplemented").into()),
        Some(CryptoType::Secp256k1) => {
            let wallet: Wallet<SigningKey> = params.address.parse()?;
            // TODO: rm
            debug!("{}", hex::encode_upper(wallet.signer().to_bytes()));
            let public_key = hex::encode_upper(wallet.signer().verifying_key().to_sec1_bytes());
            ok(json!({
                "user_code": params.user_code,
                "crypto_type": params.crypto_type,
                "address": wallet.address(),
                "public_key": public_key,
            }))
        }
        None => Err(anyhow::anyhow!("crypto_type missing").into()),
    }
}

async fn handle_sign(
    _version: Version,
    Json(params): Json<RequestParams>,
) -> Result<impl IntoResponse, AppError> {
    debug!("params: {:?}", params);
    if params.user_code.is_empty() {
        return Err(anyhow::anyhow!("user_code missing").into());
    }
    if params.message.is_empty() {
        return Err(anyhow::anyhow!("message missing").into());
    }
    match params.crypto_type {
        Some(CryptoType::SM2) => Err(anyhow::anyhow!("SM2 unimplemented").into()),
        Some(CryptoType::Secp256k1) => {
            let wallet = derive_wallet(&params.user_code)?;
            let signature = wallet.sign_message(params.message.as_bytes()).await?;
            ok(json!({
                "signature": signature,
            }))
        }
        None => Err(anyhow::anyhow!("crypto_type missing").into()),
    }
}

async fn handle_verify(
    _version: Version,
    Json(params): Json<RequestParams>,
) -> Result<impl IntoResponse, AppError> {
    debug!("params: {:?}", params);
    if params.user_code.is_empty() {
        return Err(anyhow::anyhow!("user_code missing").into());
    }
    if params.message.is_empty() {
        return Err(anyhow::anyhow!("message missing").into());
    }
    if params.signature.is_none() {
        return Err(anyhow::anyhow!("signature missing").into());
    }
    match params.crypto_type {
        Some(CryptoType::SM2) => Err(anyhow::anyhow!("SM2 unimplemented").into()),
        Some(CryptoType::Secp256k1) => {
            let wallet = derive_wallet(&params.user_code)?;
            let verify_result = match params.signature {
                Some(signature) => signature.verify(params.message, wallet.address()).is_ok(),
                None => false,
            };
            ok(verify_result)
        }
        None => Err(anyhow::anyhow!("crypto_type missing").into()),
    }
}
