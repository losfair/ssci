use std::collections::HashMap;

use anyhow::Context;
use base64::Engine;
use p256::{
    ecdsa::{signature::Verifier, DerSignature, VerifyingKey},
    PublicKey,
};
use sha2::{Digest, Sha256};
use sigstore::rekor::models::{log_entry::InclusionProof, ConsistencyProof};

pub fn verify_consistency_proof(
    proof: &ConsistencyProof,
    root1: [u8; 32],
    root2: [u8; 32],
    size1: u64,
    size2: u64,
) -> anyhow::Result<()> {
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(proof.hashes.len());

    for h in &proof.hashes {
        let mut b = [0u8; 32];
        faster_hex::hex_decode(h.as_bytes(), &mut b).with_context(|| "hex decode failed")?;
        hashes.push(b);
    }

    let proof = hashes;

    do_verify_consistency(&proof, root1, root2, size1, size2)
}

pub struct CanonicalInclusionProof {
    pub origin: String,
    pub root_hash: [u8; 32],
    pub tree_size: u64,
    pub hashes: Vec<[u8; 32]>,
    pub signatures: HashMap<String, (u32, Vec<u8>)>,
    pub log_index: u64,
}

impl CanonicalInclusionProof {
    pub fn decode(that: &InclusionProof) -> anyhow::Result<Self> {
        let mut checkpoint = that.checkpoint.split('\n');
        let origin = checkpoint
            .next()
            .with_context(|| "missing origin")?
            .to_string();
        let tree_size: u64 = checkpoint
            .next()
            .with_context(|| "missing tree_size")?
            .parse()
            .with_context(|| "invalid tree_size")?;
        let root_hash = <[u8; 32]>::try_from(
            &base64::engine::general_purpose::STANDARD
                .decode(&checkpoint.next().with_context(|| "missing root_hash")?)
                .with_context(|| "invalid root_hash")?[..],
        )
        .with_context(|| "bad root_hash length")?;
        if checkpoint.next() != Some("") {
            anyhow::bail!("unexpected end of checkpoint");
        }
        let mut signatures: HashMap<String, (u32, Vec<u8>)> = HashMap::new();
        for line in checkpoint {
            if line.is_empty() {
                continue;
            }
            let Some((signer, sig)) = line.split_once(' ').and_then(|(_, x)| x.split_once(' '))
            else {
                anyhow::bail!("invalid signature line");
            };
            let sig = base64::engine::general_purpose::STANDARD
                .decode(sig)
                .with_context(|| "invalid signature")?;
            if sig.len() < 5 {
                anyhow::bail!("invalid signature length");
            }
            let hash = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
            let sig = sig[4..].to_vec();
            signatures.insert(signer.to_string(), (hash, sig));
        }

        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(that.hashes.len());

        for h in &that.hashes {
            let mut b = [0u8; 32];
            faster_hex::hex_decode(h.as_bytes(), &mut b)
                .with_context(|| "hex decode failed on 'hashes'")?;
            hashes.push(b);
        }

        Ok(Self {
            origin,
            root_hash,
            tree_size,
            hashes,
            signatures,
            log_index: that.log_index as u64,
        })
    }
}

pub fn verify_inclusion_proof(
    body: &str,
    proof: &CanonicalInclusionProof,
) -> anyhow::Result<Vec<u8>> {
    let body = base64::engine::general_purpose::STANDARD.decode(body)?;
    let leaf_hash = sha2::Sha256::new()
        .chain_update(&[0u8])
        .chain_update(&body)
        .finalize();

    let calc_root = root_from_inclusion_proof(
        proof.log_index as u64,
        proof.tree_size as u64,
        leaf_hash.into(),
        &proof.hashes,
    )?;
    if calc_root != proof.root_hash {
        anyhow::bail!("calc_root != root");
    }
    Ok(body)
}

pub fn verify_tree_head_signature(
    public_key: &PublicKey,
    proof: &CanonicalInclusionProof,
    signer: &str,
) -> anyhow::Result<()> {
    let Some((_, sig)) = proof.signatures.get(signer) else {
        anyhow::bail!("missing signature from the requested signer");
    };
    let sig = DerSignature::from_bytes(sig).with_context(|| "cannot parse asn1 signature")?;
    let serialized_checkpoint = format!(
        "{}\n{}\n{}\n",
        proof.origin,
        proof.tree_size,
        base64::engine::general_purpose::STANDARD.encode(proof.root_hash)
    );
    VerifyingKey::from(public_key)
        .verify(serialized_checkpoint.as_bytes(), &sig)
        .with_context(|| "signature verification failed")?;
    Ok(())
}

fn do_verify_consistency(
    proof: &[[u8; 32]],
    root1: [u8; 32],
    root2: [u8; 32],
    size1: u64,
    size2: u64,
) -> anyhow::Result<()> {
    if proof.is_empty() || size1 == 0 || size2 <= size1 || size2 > (1u64 << 48) {
        anyhow::bail!("P001");
    }

    let (inner, border) = decomp_incl_proof(size1 - 1, size2);
    let shift = size1.trailing_zeros() as u64;
    let inner = inner.saturating_sub(shift);

    let (seed, start) = if size1 == (1 << shift) {
        (root1, 0)
    } else {
        (proof[0], 1)
    };

    if proof.len() as u64 != start + inner + border {
        anyhow::bail!("P002");
    }

    let proof = &proof[start as usize..];
    let mask = (size1 - 1) >> shift;

    let hash1 = chain_border_right(
        chain_inner_right(seed, &proof[..inner as usize], mask),
        &proof[inner as usize..],
    );

    if hash1 != root1 {
        anyhow::bail!("hash1 != root1");
    }

    let hash2 = chain_border_right(
        chain_inner(seed, &proof[..inner as usize], mask),
        &proof[inner as usize..],
    );

    if hash2 != root2 {
        anyhow::bail!("hash2 != root2");
    }

    Ok(())
}

fn root_from_inclusion_proof(
    index: u64,
    size: u64,
    leaf_hash: [u8; 32],
    proof: &[[u8; 32]],
) -> anyhow::Result<[u8; 32]> {
    if index >= size || size >= 0xffffffff_ffffffff {
        anyhow::bail!("P003");
    }

    let (inner, border) = decomp_incl_proof(index, size);
    if proof.len() as u64 != inner + border {
        anyhow::bail!("P004");
    }

    let res = chain_inner(leaf_hash, &proof[..inner as usize], index);
    Ok(chain_border_right(res, &proof[inner as usize..]))
}

fn decomp_incl_proof(index: u64, size: u64) -> (u64, u64) {
    let inner = inner_proof_size(index, size);
    let border = (index >> inner).count_ones() as u64;
    (inner, border)
}

fn chain_inner(seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
    proof.iter().enumerate().fold(seed, |acc, (i, &p)| {
        if (index >> i) & 1 == 0 {
            hash_children(acc, p)
        } else {
            hash_children(p, acc)
        }
    })
}

fn chain_inner_right(seed: [u8; 32], proof: &[[u8; 32]], index: u64) -> [u8; 32] {
    proof.iter().enumerate().fold(seed, |acc, (i, &p)| {
        if (index >> i) & 1 == 1 {
            hash_children(p, acc)
        } else {
            acc
        }
    })
}

fn chain_border_right(seed: [u8; 32], proof: &[[u8; 32]]) -> [u8; 32] {
    proof.iter().fold(seed, |acc, &p| hash_children(p, acc))
}

fn hash_children(l: [u8; 32], r: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(l);
    hasher.update(r);
    hasher.finalize().into()
}

fn inner_proof_size(index: u64, size: u64) -> u64 {
    64 - ((index ^ (size - 1)) as u64).leading_zeros() as u64
}
