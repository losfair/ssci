use std::ffi::{c_char, c_void, CStr};

use alloy_primitives::{keccak256, Address, B256, U256};
use anyhow::Context;
use attestation_doc_validation::attestation_doc;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use base64::Engine;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use ecdsa::signature::Verifier;
use p256::{
    elliptic_curve::sec1::{Coordinates, ToEncodedPoint},
    pkcs8::ObjectIdentifier,
    PublicKey,
};
use rekor::{
    verify_consistency_proof, verify_inclusion_proof, verify_tree_head_signature,
    CanonicalInclusionProof,
};
use serde::{Deserialize, Serialize};
use sigstore::rekor::models::ConsistencyProof;
use types::{EthProof, RekorLogEntry};
use x509_verify::{
    der::{Decode, DecodePem},
    x509_cert::Certificate,
};

mod helpers;
mod rekor;
mod types;

pub struct VwContext {
    scroll_l1_proxy: Address,
    rekor_witness_on_scroll: Address,
    rekor_public_key: PublicKey,
    unsafe_allow_unwitnessed_entries: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VwContextInit {
    pub scroll_l1_proxy: Address,
    pub rekor_witness_on_scroll: Address,
    pub rekor_public_key: (String, String),
    #[serde(default)]
    pub unsafe_allow_unwitnessed_entries: bool,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FullProof {
    pub finalization_proof: EthProof,
    pub l2_proof: EthProof,
    pub rekor_entry: RekorLogEntry,
    pub consistency_proof: Option<ConsistencyProof>,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StorageKeySet {
    pub eth_l2_state_root_key: U256,
    pub scr_witnessed_tree_size_key: U256,
    pub scr_witnessed_tree_root_key: U256,
}

impl StorageKeySet {
    pub fn new(batch_index: U256, rekor_public_key: &PublicKey, origin: &[u8]) -> Self {
        let rekor_public_key_point = rekor_public_key.to_encoded_point(false);
        let Coordinates::Uncompressed { x, y } = rekor_public_key_point.coordinates() else {
            panic!("failed to get coordinates from rekor public key");
        };

        let eth_l2_state_root_key = U256::from_be_bytes(
            keccak256(
                [
                    &batch_index.to_be_bytes::<32>()[..],
                    &U256::from(0x9e).to_be_bytes::<32>()[..],
                ]
                .concat(),
            )
            .0,
        );
        let scr_witnessed_tree_size_key = U256::from_be_bytes(
            keccak256(
                [
                    origin,
                    &keccak256([&y[..], &keccak256([&x[..], &[0u8; 32]].concat()).0[..]].concat())
                        .0[..],
                ]
                .concat(),
            )
            .0,
        );
        let scr_witnessed_tree_root_key = scr_witnessed_tree_size_key + U256::from(1);
        Self {
            eth_l2_state_root_key,
            scr_witnessed_tree_size_key,
            scr_witnessed_tree_root_key,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedProof {
    pub body: String,
    pub origin: String,
    pub log_index: u64,
}

#[no_mangle]
pub unsafe extern "C" fn vw_malloc(len: usize) -> *mut c_void {
    libc::malloc(len)
}

#[no_mangle]
pub unsafe extern "C" fn vw_free(ptr: *mut c_void) {
    libc::free(ptr)
}

#[no_mangle]
pub extern "C" fn _initialize() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .init();

    zktrie::init_hash_scheme_simple(helpers::poseidon_hash_scheme);

    tracing::info!("vwcrypto initialized");
}

#[no_mangle]
pub unsafe extern "C" fn vw_context_create(init: *const c_char) -> *mut VwContext {
    let init = CStr::from_ptr(init).to_str().expect("invalid init cstr");
    let Ok(init) = serde_json::from_str::<VwContextInit>(init) else {
        tracing::error!("failed to parse init");
        return std::ptr::null_mut();
    };
    // decode Rekor public key
    let Ok(rekor_public_key) = PublicKey::from_jwk_str(&{
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];

        faster_hex::hex_decode(init.rekor_public_key.0.as_bytes(), &mut x).unwrap();
        faster_hex::hex_decode(init.rekor_public_key.1.as_bytes(), &mut y).unwrap();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);

        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        })
        .to_string()
    }) else {
        tracing::error!("failed to decode rekor public key");
        return std::ptr::null_mut();
    };
    let out = Box::new(VwContext {
        scroll_l1_proxy: init.scroll_l1_proxy,
        rekor_witness_on_scroll: init.rekor_witness_on_scroll,
        rekor_public_key,
        unsafe_allow_unwitnessed_entries: init.unsafe_allow_unwitnessed_entries,
    });
    Box::into_raw(out)
}

#[no_mangle]
pub unsafe extern "C" fn vw_get_storage_key_set(
    ctx: &VwContext,
    batch_index: u64,
    origin: *const c_char,
) -> *mut u8 {
    let origin = CStr::from_ptr(origin);
    let storage_keys = StorageKeySet::new(
        U256::from(batch_index),
        &ctx.rekor_public_key,
        origin.to_bytes(),
    );
    make_malloc_cstring(&serde_json::to_vec(&storage_keys).unwrap())
}

#[no_mangle]
pub unsafe extern "C" fn vw_verify_proof(
    ctx: &VwContext,
    trusted_state_root: *const c_char,
    proof: *const c_char,
) -> *mut u8 {
    let trusted_state_root = CStr::from_ptr(trusted_state_root)
        .to_str()
        .expect("invalid trusted_state_root cstr");
    let proof = CStr::from_ptr(proof).to_str().expect("invalid proof cstr");
    match do_verify_proof(ctx, trusted_state_root, proof) {
        Ok(x) => {
            let output = serde_json::to_string(&x).expect("failed to serialize verified proof");
            make_malloc_cstring(&output.as_bytes())
        }
        Err(error) => {
            tracing::error!(?error, "error verifying proof");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn vw_deserialize_and_verify_attestation_doc(
    doc: *const u8,
    doc_len: u32,
) -> *mut u8 {
    let doc = std::slice::from_raw_parts(doc, doc_len as usize);
    let doc = match do_deserialize_and_verify_attestation_doc(doc) {
        Ok(x) => x,
        Err(error) => {
            tracing::error!(?error, "failed to deserialize and verify attestation doc");
            return std::ptr::null_mut();
        }
    };

    make_malloc_cstring(serde_json::to_string(&doc).unwrap().as_bytes())
}

#[no_mangle]
pub unsafe extern "C" fn vw_x25519_public_key(secret: *const [u8; 32], output: *mut [u8; 32]) {
    let secret = x25519_dalek::StaticSecret::from(*secret);
    *output = x25519_dalek::PublicKey::from(&secret).to_bytes();
}

#[no_mangle]
pub unsafe extern "C" fn vw_x25519_diffie_hellman(
    our_secret: *const [u8; 32],
    their_public: *const [u8; 32],
    output: *mut [u8; 32],
) {
    let our_secret = x25519_dalek::StaticSecret::from(*our_secret);
    let their_public = x25519_dalek::PublicKey::from(*their_public);
    *output = our_secret.diffie_hellman(&their_public).to_bytes();
}

#[no_mangle]
pub unsafe extern "C" fn vw_blake3_derive_key_256(
    context: *const c_char,
    key_material: *const u8,
    key_material_len: u32,
    output: *mut [u8; 32],
) {
    let context = CStr::from_ptr(context)
        .to_str()
        .expect("invalid context cstr");
    let key_material = std::slice::from_raw_parts(key_material, key_material_len as usize);
    std::ptr::write(output, blake3::derive_key(context, key_material));
}

#[no_mangle]
pub unsafe extern "C" fn vw_chacha20poly1305_unseal(
    key: *mut [u8; 32],
    nonce_: u64,
    data: *mut u8,
    data_len: u32,
) -> i32 {
    let data = std::slice::from_raw_parts_mut(data, data_len as usize);
    if data.len() < 16 {
        return -1;
    }
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&nonce_.to_be_bytes());
    let payload_len = data.len() - 16;
    let tag = <[u8; 16]>::try_from(&data[payload_len..]).unwrap();
    let data = &mut data[..payload_len];

    if ChaCha20Poly1305::new(&(*key).into())
        .decrypt_in_place_detached(&nonce.into(), &[], data, (&tag).into())
        .is_err()
    {
        return -2;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn vw_chacha20poly1305_seal(
    key: *mut [u8; 32],
    nonce_: u64,
    data: *mut u8,
    data_len: u32,
) -> i32 {
    let data = std::slice::from_raw_parts_mut(data, data_len as usize);
    if data.len() < 16 {
        return -1;
    }
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&nonce_.to_be_bytes());
    let payload_len = data.len() - 16;

    let Ok(tag) = ChaCha20Poly1305::new(&(*key).into()).encrypt_in_place_detached(
        &nonce.into(),
        &[],
        &mut data[..payload_len],
    ) else {
        return -2;
    };

    data[payload_len..].copy_from_slice(&tag);
    0
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeafCertInfo {
    oidc_issuer: Option<String>,
    build_signer_uri: Option<String>,
    build_signer_digest: Option<String>,
}

#[no_mangle]
pub unsafe extern "C" fn vw_x509_verify_message(
    output_ptr: *mut *mut u8,
    ca: *const u8,
    ca_len: u32,
    cert: *const u8,
    cert_len: u32,
    message: *const u8,
    message_len: u32,
    signature: *const u8,
    signature_len: u32,
) -> i32 {
    let ca = std::slice::from_raw_parts(ca, ca_len as usize);
    let cert = std::slice::from_raw_parts(cert, cert_len as usize);
    let message = std::slice::from_raw_parts(message, message_len as usize);
    let signature = std::slice::from_raw_parts(signature, signature_len as usize);

    let ca = match Certificate::from_pem(ca) {
        Ok(x) => x,
        Err(error) => {
            tracing::error!(?error, "failed to parse CA certificate");
            return -1;
        }
    };
    let cert = match Certificate::from_pem(cert) {
        Ok(x) => x,
        Err(error) => {
            tracing::error!(?error, "failed to parse leaf certificate");
            return -1;
        }
    };
    let key = match x509_verify::VerifyingKey::try_from(&ca) {
        Ok(x) => x,
        Err(error) => {
            tracing::error!(?error, "failed to create verifying key from CA certificate");
            return -1;
        }
    };

    match key.verify(&cert) {
        Ok(()) => {}
        Err(_) => {
            return -2;
        }
    }

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let Some(public_key) = spki.subject_public_key.as_bytes() else {
        tracing::error!("invalid public key in leaf certificate");
        return -1;
    };

    let spki_param: Option<ObjectIdentifier> = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|x| x.decode_as().ok());

    // id-ecPublicKey + prime256v1
    if spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
        && spki_param == Some(ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
    {
        let key = match p256::PublicKey::from_sec1_bytes(public_key) {
            Ok(x) => x,
            Err(error) => {
                tracing::error!(?error, "failed to parse public key from leaf certificate");
                return -1;
            }
        };

        let sig = match p256::ecdsa::DerSignature::from_bytes(signature) {
            Ok(x) => x,
            Err(error) => {
                tracing::error!(?error, "failed to parse signature");
                return -1;
            }
        };

        match ecdsa::VerifyingKey::from(&key).verify(message, &sig) {
            Ok(()) => {}
            Err(_) => {
                return -4;
            }
        }

        let mut info = LeafCertInfo::default();
        for ext in cert
            .tbs_certificate
            .extensions
            .as_deref()
            .unwrap_or_default()
        {
            // https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md

            // Issuer (V2)
            if ext.extn_id == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8") {
                if let Ok(value) = String::from_der(ext.extn_value.as_bytes()) {
                    info.oidc_issuer = Some(value);
                }
            }

            // Build Signer URI
            if ext.extn_id == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.9") {
                if let Ok(value) = String::from_der(ext.extn_value.as_bytes()) {
                    info.build_signer_uri = Some(value);
                }
            }

            // Build Signer Digest
            if ext.extn_id == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.10") {
                if let Ok(value) = String::from_der(ext.extn_value.as_bytes()) {
                    info.build_signer_digest = Some(value);
                }
            }
        }

        *output_ptr = make_malloc_cstring(&serde_json::to_string(&info).unwrap().as_bytes());
        return 0;
    }

    // unsupported algorithm
    tracing::error!(
        oid = spki.algorithm.oid.to_string(),
        param = ?spki_param,
        "unknown spki algorithm"
    );

    -3
}

fn do_deserialize_and_verify_attestation_doc(
    attestation_doc_cose_sign_1_bytes: &[u8],
) -> anyhow::Result<AttestationDoc> {
    attestation_doc_validation::validate_attestation_doc(attestation_doc_cose_sign_1_bytes)
        .with_context(|| "failed to validate attestation doc")?;
    let (_, doc) = attestation_doc::decode_attestation_document(attestation_doc_cose_sign_1_bytes)?;
    Ok(doc)
}

fn do_verify_proof(
    ctx: &VwContext,
    trusted_state_root_hex: &str,
    proof: &str,
) -> anyhow::Result<VerifiedProof> {
    let mut trusted_state_root = [0u8; 32];
    faster_hex::hex_decode(trusted_state_root_hex.as_bytes(), &mut trusted_state_root)
        .with_context(|| "failed to decode trusted state root")?;
    let trusted_state_root = trusted_state_root;

    let proof: FullProof = serde_json::from_str(proof).with_context(|| "failed to parse proof")?;

    let Some(inclusion_proof) = proof.rekor_entry.verification.inclusion_proof else {
        anyhow::bail!("missing inclusion proof");
    };

    let inclusion_proof = CanonicalInclusionProof::decode(&inclusion_proof)
        .with_context(|| "failed to decode inclusion proof")?;

    proof
        .finalization_proof
        .verify(trusted_state_root.into())
        .with_context(|| "failed to verify finalization proof")?;

    if proof.finalization_proof.address != ctx.scroll_l1_proxy {
        anyhow::bail!("invalid scroll l1 proxy address");
    }

    let Some(batch_index) = proof
        .finalization_proof
        .storage_proof
        .iter()
        .find(|x| x.key == U256::from(0x9c))
        .map(|x| x.value)
    else {
        anyhow::bail!("missing batch index");
    };

    let storage_keys = StorageKeySet::new(
        batch_index,
        &ctx.rekor_public_key,
        inclusion_proof.origin.as_bytes(),
    );

    let Some(l2_state_root) = proof
        .finalization_proof
        .storage_proof
        .iter()
        .find(|x| x.key == storage_keys.eth_l2_state_root_key)
        .map(|x| B256::from(x.value.to_be_bytes()))
    else {
        anyhow::bail!("missing l2 state root");
    };

    proof
        .l2_proof
        .verify_l2(l2_state_root)
        .with_context(|| "failed to verify l2 proof")?;

    if proof.l2_proof.address != ctx.rekor_witness_on_scroll {
        anyhow::bail!("invalid scroll rekor witness address");
    }

    let Some(witnessed_tree_size) = proof
        .l2_proof
        .storage_proof
        .iter()
        .find(|x| x.key == storage_keys.scr_witnessed_tree_size_key)
        .map(|x| x.value)
    else {
        anyhow::bail!("missing witnessed tree size");
    };

    let Some(witnessed_tree_root) = proof
        .l2_proof
        .storage_proof
        .iter()
        .find(|x| x.key == storage_keys.scr_witnessed_tree_root_key)
        .map(|x| x.value)
    else {
        anyhow::bail!("missing witnessed tree root");
    };

    let witnessed_tree_size =
        u64::try_from(witnessed_tree_size).with_context(|| "witnessed tree size out of bounds")?;

    let witnessed_tree_root = witnessed_tree_root.to_be_bytes::<32>();

    if witnessed_tree_root != inclusion_proof.root_hash
        || witnessed_tree_size != inclusion_proof.tree_size as u64
    {
        let Some(consistency_proof) = &proof.consistency_proof else {
            anyhow::bail!("missing consistency proof");
        };

        verify_consistency_proof(
            consistency_proof,
            witnessed_tree_root,
            inclusion_proof.root_hash,
            witnessed_tree_size,
            inclusion_proof.tree_size as u64,
        )
        .with_context(|| "failed to verify consistency proof")?;
    }

    if inclusion_proof.log_index >= witnessed_tree_size {
        if ctx.unsafe_allow_unwitnessed_entries {
            tracing::warn!(
                "log index is newer than witnessed tree head, but unwitnessed entries are allowed"
            );
        } else {
            anyhow::bail!("log index is newer than witnessed tree head");
        }
    }

    let body = verify_inclusion_proof(&proof.rekor_entry.body, &inclusion_proof)
        .with_context(|| "failed to verify inclusion proof")?;

    // Independently verify tree head signature
    let signer = inclusion_proof.origin.split(' ').next().unwrap();
    verify_tree_head_signature(&ctx.rekor_public_key, &inclusion_proof, signer)
        .with_context(|| "failed to verify tree head signature")?;

    let body = String::from_utf8(body).with_context(|| "body is not valid utf-8")?;

    Ok(VerifiedProof {
        body,
        origin: inclusion_proof.origin,
        log_index: inclusion_proof.log_index,
    })
}

fn make_malloc_cstring(data: &[u8]) -> *mut u8 {
    unsafe {
        let buf = libc::malloc(data.len() + 1) as *mut u8;
        if buf.is_null() {
            tracing::error!("make_malloc_cstring: malloc failed");
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len());
        buf.add(data.len()).write(0);
        buf
    }
}
