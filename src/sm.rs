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

use anyhow::Result;

pub const SM2_SIGNATURE_BYTES_LEN: usize = 128;

pub fn sm2_sign(
    pubkey: &[u8],
    privkey: &[u8],
    msg: &[u8],
) -> Result<[u8; SM2_SIGNATURE_BYTES_LEN]> {
    let key_pair = efficient_sm2::KeyPair::new(privkey)
        .map_err(|e| anyhow::anyhow!("sm2_sign: KeyPair_new failed: {:?}", e))?;
    let sig = key_pair
        .sign(msg)
        .map_err(|e| anyhow::anyhow!("sm2_sign: KeyPair_sign failed: {:?}", e))?;

    let mut sig_bytes = [0u8; SM2_SIGNATURE_BYTES_LEN];
    sig_bytes[..32].copy_from_slice(&sig.r());
    sig_bytes[32..64].copy_from_slice(&sig.s());
    sig_bytes[64..].copy_from_slice(pubkey);
    Ok(sig_bytes)
}

pub fn sm2_verify(signature: &[u8], message: &[u8]) -> Result<bool> {
    let r = &signature[0..32];
    let s = &signature[32..64];
    let pk = &signature[64..];

    let public_key = efficient_sm2::PublicKey::new(&pk[..32], &pk[32..]);
    let sig = efficient_sm2::Signature::new(r, s)
        .map_err(|e| anyhow::anyhow!("sm2_recover: Signature_new failed: {:?}", e))?;

    Ok(sig
        .verify(&public_key, message)
        .map_err(|e| anyhow::anyhow!("sm2_recover: Signature_verify failed: {:?}", e))
        .is_ok())
}
