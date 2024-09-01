use std::rc::Rc;

use alloy_primitives::keccak256;
use alloy_primitives::{Address, Bytes, B256, U256, U64};
use alloy_rlp::{Encodable, RlpDecodable, RlpEncodable};
use anyhow::Context;
use nybbles::Nibbles;
use serde::{Deserialize, Serialize};
use sigstore::rekor::models::log_entry::Verification;
use zktrie::ZkMemoryDb;

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq)]
struct EthAccountRlp {
    nonce: alloy_primitives::U64,
    value: alloy_primitives::U256,
    storage_hash: alloy_primitives::B256,
    code_hash: alloy_primitives::B256,
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RekorLogEntry {
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<serde_json::Value>,
    pub body: String,
    pub integrated_time: i64,
    pub log_i_d: String,
    pub log_index: i64,
    pub verification: Verification,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthProof {
    pub address: Address,
    pub balance: U256,
    #[serde(alias = "keccakCodeHash")]
    pub code_hash: B256,
    pub nonce: U64,
    pub storage_hash: B256,
    pub account_proof: Vec<Bytes>,
    pub storage_proof: Vec<StorageProof>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub poseidon_code_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_size: Option<U64>,
}

impl EthProof {
    pub fn verify_l2(&self, state_root: B256) -> anyhow::Result<()> {
        let (Some(poseidon_code_hash), Some(code_size)) = (self.poseidon_code_hash, self.code_size)
        else {
            anyhow::bail!("missing poseidon code hash or code size");
        };

        let mut db = ZkMemoryDb::new();
        for (i, node) in self.account_proof.iter().enumerate() {
            db.add_node_bytes(node, None)
                .map_err(|e| anyhow::anyhow!("failed to add account proof node {}: {}", i, e))?;
        }
        let db = Rc::new(db);
        let trie = db
            .new_trie(&state_root.0)
            .with_context(|| "root not found in zktrie")?;
        let verified_account = trie
            .get_account(&self.address.0[..])
            .with_context(|| "failed to get account from zktrie")?;
        let mut expected_account = [
            [0u8; 32],
            self.balance.to_be_bytes(),
            self.storage_hash.0,
            self.code_hash.0,
            poseidon_code_hash.0,
        ];
        expected_account[0][16..24].copy_from_slice(&code_size.to_be_bytes::<8>());
        expected_account[0][24..32].copy_from_slice(&self.nonce.to_be_bytes::<8>());
        if verified_account != expected_account {
            anyhow::bail!("account verification failed");
        }
        drop(db);

        for storage_proof in &self.storage_proof {
            let mut db = ZkMemoryDb::new();
            for (i, node) in storage_proof.proof.iter().enumerate() {
                db.add_node_bytes(node, None).map_err(|e| {
                    anyhow::anyhow!("failed to add storage proof node {}: {}", i, e)
                })?;
            }
            let db = Rc::new(db);
            let trie = db
                .new_trie(&self.storage_hash.0)
                .with_context(|| "root not found in zktrie")?;
            let verified_storage = trie
                .get_store(&storage_proof.key.to_be_bytes::<32>()[..])
                .with_context(|| "failed to get storage from zktrie")?;
            let expected_storage = storage_proof.value.to_be_bytes();
            if verified_storage != expected_storage {
                anyhow::bail!("storage verification failed");
            }
        }

        Ok(())
    }

    pub fn verify(&self, state_root: B256) -> anyhow::Result<()> {
        let account_proof = self
            .account_proof
            .iter()
            .map(|x| alloy_primitives::Bytes(x.0.clone()))
            .collect::<Vec<_>>();
        let mut account_rlp_bytes: Vec<u8> = vec![];
        let account_rlp = EthAccountRlp {
            nonce: self.nonce,
            value: self.balance,
            storage_hash: self.storage_hash,
            code_hash: self.code_hash,
        };
        account_rlp.encode(&mut account_rlp_bytes);
        alloy_trie::proof::verify_proof(
            alloy_primitives::B256::from(state_root.0),
            Nibbles::unpack(keccak256(self.address)),
            Some(account_rlp_bytes),
            &account_proof,
        )
        .with_context(|| "failed to verify account proof")?;

        for storage_proof in &self.storage_proof {
            let proof = storage_proof
                .proof
                .iter()
                .map(|x| alloy_primitives::Bytes(x.0.clone()))
                .collect::<Vec<_>>();
            let key = storage_proof.key.to_be_bytes::<32>();
            let value = if storage_proof.value.is_zero() {
                None
            } else {
                let mut rlp: Vec<u8> = vec![];
                storage_proof.value.encode(&mut rlp);
                Some(rlp)
            };
            alloy_trie::proof::verify_proof(
                alloy_primitives::B256::new(self.storage_hash.0),
                Nibbles::unpack(keccak256(key)),
                value,
                &proof,
            )
            .with_context(|| {
                format!(
                    "failed to verify storage proof at key {}",
                    storage_proof.key
                )
            })?;
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StorageProof {
    pub key: U256,
    pub proof: Vec<Bytes>,
    pub value: U256,
}
