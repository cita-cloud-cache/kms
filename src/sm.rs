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
