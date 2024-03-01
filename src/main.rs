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

#[macro_use]
extern crate tracing;

mod config;

use std::sync::Arc;

use clap::Parser;
use color_eyre::{eyre::eyre, Result};
use ethers::{prelude::*, signers::coins_bip39::English, utils::keccak256};
use k256::ecdsa::SigningKey;
use parking_lot::RwLock;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use config::Config;

use common_rs::{
    configure::{config_hot_reload, file_config},
    error::CALError,
    etcd, log,
    restful::{err, err_msg, http_serve, ok, RESTfulError},
    sm,
};

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

#[derive(Clone)]
struct AppState {
    config: Arc<RwLock<Config>>,
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<()> {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let config: Config = file_config(&opts.config_path).map_err(|e| {
        println!("config init err: {e}");
        e
    })?;

    // init tracer
    log::init_tracing(&config.name, &config.log_config)
        .map_err(|e| println!("tracer init err: {e}"))
        .unwrap();

    if let Some(service_register_config) = &config.service_register_config {
        let etcd = etcd::Etcd::new(config.etcd_endpoints.clone()).await?;
        etcd.keep_service_register_in_k8s(
            &config.name,
            config.port,
            service_register_config.clone(),
        )
        .await
        .ok();
    }

    let service_name = config.name.clone();
    let port = config.port;

    let config = Arc::new(RwLock::new(config));

    let cloned_config_path = opts.config_path.clone();
    let cloned_config = Arc::clone(&config);

    // reload config
    config_hot_reload(cloned_config, cloned_config_path)?;

    let app_state = AppState { config };

    let router = Router::new()
        .hoop(affix::inject(app_state))
        .push(Router::with_path("/api/keys/key").post(handle_keys))
        .push(Router::with_path("/api/keys/addr").post(handle_keys_addr))
        .push(Router::with_path("/api/keys/sign").post(handle_sign))
        .push(Router::with_path("/api/keys/verify").post(handle_verify));

    http_serve(&service_name, port, router).await;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
enum CryptoType {
    #[serde(alias = "sm2")]
    SM2,
    #[serde(alias = "secp256k1")]
    Secp256k1,
}

#[derive(Debug, Serialize, Default, Deserialize, ToSchema)]
#[serde(default)]
struct RequestParams {
    #[serde(skip_serializing_if = "String::is_empty")]
    user_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_type: Option<CryptoType>,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    address: String,
}

fn derive_wallet(master_key: &str, user_code: &str) -> Result<Wallet<SigningKey>, RESTfulError> {
    let user_code_hash = keccak256(user_code);
    // account is hardened must be less than 0x80000000
    let account = u32::from_be_bytes(user_code_hash[0..4].try_into().unwrap()) & (0x80000000 - 1);
    let index = u32::from_be_bytes(user_code_hash[4..8].try_into().unwrap());
    let path = format!("m/44'/60'/{}'/0/{}", account, index);
    debug!("path: {}", path);
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(master_key)
        .derivation_path(&path)?
        .build()
        .map_err(|e| eyre!("derive wallet failed: {e}"))?;
    Ok(wallet)
}

#[handler]
async fn handle_keys(depot: &Depot, req: &mut Request) -> Result<impl Writer, RESTfulError> {
    let state = depot
        .obtain::<AppState>()
        .map_err(|e| eyre!("get app_state failed: {e:?}"))?;

    let params = req.parse_body::<RequestParams>().await?;
    debug!("params: {:?}", params);
    if params.user_code.is_empty() {
        return err(CALError::BadRequest, "user_code missing");
    }

    let wallet = derive_wallet(&state.config.read().master_key, &params.user_code)?;

    let (public_key, address) = match params.crypto_type {
        Some(CryptoType::SM2) => {
            let privkey = wallet.signer().to_bytes();
            let public_key = sm::private_key_to_public_key(&privkey)?;
            (
                hex::encode_upper(public_key),
                hex::encode_upper(sm::pk2address(&public_key)),
            )
        }
        Some(CryptoType::Secp256k1) => (
            hex::encode_upper(wallet.signer().verifying_key().to_sec1_bytes()),
            hex::encode_upper(wallet.address()),
        ),
        None => return err(CALError::BadRequest, "crypto_type missing"),
    };

    ok(json!({
        "user_code": params.user_code,
        "crypto_type": params.crypto_type,
        "address": address,
        "public_key": public_key,
    }))
}

#[handler]
async fn handle_keys_addr(req: &mut Request) -> Result<impl Writer, RESTfulError> {
    let params = req.parse_body::<RequestParams>().await?;
    debug!("params: {:?}", params);
    if params.address.is_empty() {
        return err(CALError::BadRequest, "address missing");
    }
    let wallet: Wallet<SigningKey> = params
        .address
        .parse()
        .map_err(|e| eyre!("address parse failed: {e}"))?;

    let (public_key, address) = match params.crypto_type {
        Some(CryptoType::SM2) => {
            let privkey = wallet.signer().to_bytes();
            let public_key = sm::private_key_to_public_key(&privkey)?;
            (
                hex::encode_upper(public_key),
                hex::encode_upper(sm::pk2address(&public_key)),
            )
        }
        Some(CryptoType::Secp256k1) => (
            hex::encode_upper(wallet.signer().verifying_key().to_sec1_bytes()),
            hex::encode_upper(wallet.address()),
        ),
        None => return err(CALError::BadRequest, "crypto_type missing"),
    };
    ok(json!({
        "user_code": params.user_code,
        "crypto_type": params.crypto_type,
        "address": address,
        "public_key": public_key,
    }))
}

#[handler]
async fn handle_sign(depot: &Depot, req: &mut Request) -> Result<impl Writer, RESTfulError> {
    let state = depot
        .obtain::<AppState>()
        .map_err(|e| eyre!("get app_state failed: {e:?}"))?;

    let params = req.parse_body::<RequestParams>().await?;
    debug!("params: {:?}", params);
    if params.user_code.is_empty() {
        return err(CALError::BadRequest, "user_code missing");
    }
    if params.message.is_empty() {
        return err(CALError::BadRequest, "message missing");
    }
    let wallet = derive_wallet(&state.config.read().master_key, &params.user_code)?;
    let message = hex::decode(params.message).map_err(|e| eyre!("message decode failed: {e}"))?;
    if message.len() != 32 {
        return err_msg("message decode failed: not match H256 type");
    }
    match params.crypto_type {
        Some(CryptoType::SM2) => {
            let privkey = wallet.signer().to_bytes();
            let mut signature_raw_vec = sm::sign(
                &sm::private_key_to_public_key(&privkey)?,
                &privkey,
                &message,
            )?;
            let (signature_vec, public_key_vec) = signature_raw_vec.split_at_mut(64);
            let mut public_key = vec![4u8];
            public_key.append(&mut public_key_vec.to_vec());
            ok(json!({
                "signature": hex::encode(signature_vec),
                "public_key": hex::encode(public_key)
            }))
        }
        Some(CryptoType::Secp256k1) => {
            let signature = wallet
                .sign_hash(H256::from_slice(&message))
                .map_err(|e| eyre!("Secp256k1 sign message failed: {e}"))?;
            let signature = hex::encode(signature.to_vec());
            ok(json!({
                "signature": signature,
            }))
        }
        None => err(CALError::BadRequest, "crypto_type missing"),
    }
}

#[handler]
async fn handle_verify(depot: &Depot, req: &mut Request) -> Result<impl Writer, RESTfulError> {
    let state = depot
        .obtain::<AppState>()
        .map_err(|e| eyre!("get app_state failed: {e:?}"))?;

    let params = req.parse_body::<RequestParams>().await?;
    debug!("params: {:?}", params);
    if params.user_code.is_empty() {
        return err(CALError::BadRequest, "user_code missing");
    }
    if params.message.is_empty() {
        return err(CALError::BadRequest, "message missing");
    }
    if params.signature.is_empty() {
        return err(CALError::BadRequest, "signature missing");
    }
    let signature =
        hex::decode(params.signature).map_err(|e| eyre!("signature decode failed: {e}"))?;
    let message = hex::decode(params.message).map_err(|e| eyre!("message decode failed: {e}"))?;
    if message.len() != 32 {
        return err_msg("message decode failed: not match H256 type");
    }
    let wallet = derive_wallet(&state.config.read().master_key, &params.user_code)?;
    match params.crypto_type {
        Some(CryptoType::SM2) => {
            let privkey = wallet.signer().to_bytes();
            let public_key = sm::private_key_to_public_key(&privkey)?;
            let address = sm::pk2address(&public_key);
            let verify_result = sm::verify(&address, &signature, &message).is_ok();
            ok(verify_result)
        }
        Some(CryptoType::Secp256k1) => {
            let signature = Signature::try_from(signature.as_slice())
                .map_err(|e| eyre!("signature decode failed: {e:?}"))?;
            let verify_result = signature
                .verify(H256::from_slice(&message), wallet.address())
                .is_ok();
            ok(verify_result)
        }
        None => err(CALError::BadRequest, "crypto_type missing"),
    }
}

#[test]
fn msg_hash() {
    let hash_bytes = keccak256(b"hello world!");
    println!("hash_bytes: {hash_bytes:?}");
    println!("hash: {}", hex::encode(hash_bytes));
}
