import type { Proof } from "@ethereumjs/common";
import { VwCrypto } from "./wasm.ts";
import * as ethers from "ethers";

const ethRpc = new ethers.JsonRpcProvider("https://mainnet.gateway.tenderly.co", 1);
const scrRpc = new ethers.JsonRpcProvider("https://rpc.scroll.io", 534352);

export async function getUnverifiedFullProof(vw: VwCrypto, blockNumber_: number, rekorEntryIndex: number): Promise<unknown> {
    const blockNumber = ethers.toQuantity(blockNumber_);

    // ### Prove finalized state root
    // 0x9c: lastFinalizedBatchIndex
    // 0x9e: finalizedStateRoots
    const finalizationProof: Proof = await ethRpc.send("eth_getProof", [vw.init.scrollL1Proxy, [
        "0x9c",
    ], blockNumber]);
    const lastFinalizedBatchIndex = ethers.toBigInt(finalizationProof.storageProof[0].value)
    if (lastFinalizedBatchIndex === 0n) {
        throw new Error("No finalized batches");
    }
    {
        const finalizedStateRootProof: Proof = await ethRpc.send("eth_getProof", [vw.init.scrollL1Proxy, [
            ethers.keccak256(ethers.toBeHex(lastFinalizedBatchIndex, 32) + "00".repeat(31) + "9e"),
        ], blockNumber]);
        finalizationProof.storageProof.push(finalizedStateRootProof.storageProof[0]);
    }

    // Lookup the event that committed the batch
    const commitLog = (await ethRpc.getLogs({
        address: vw.init.scrollL1Proxy,
        topics: [
            // CommitBatch
            "0x2c32d4ae151744d0bf0b9464a3e897a1d17ed2f1af71f7c9a75f12ce0d28238f",
            ethers.toBeHex(lastFinalizedBatchIndex, 32),
        ],
        fromBlock: blockNumber_ - 999,
        toBlock: blockNumber_,
    }))[0];
    if (!commitLog) throw new Error("No commit event found");

    const commitTx = await ethRpc.getTransaction(commitLog.transactionHash);
    if (!commitTx) throw new Error("No commit transaction found");
    if (commitTx.to !== vw.init.scrollL1Proxy) throw new Error("Invalid commit transaction");

    let chunks: unknown[];
    {
        const iface = new ethers.Interface([
            "function commitBatch(uint8,bytes,bytes[],bytes)",
            "function commitBatchWithBlobProof(uint8,bytes,bytes[],bytes,bytes)"
        ]);

        // decode calldata
        if (commitTx.data.startsWith(iface.getFunction("commitBatchWithBlobProof")!.selector!)) {
            const calldata = iface.decodeFunctionData("commitBatchWithBlobProof", commitTx.data);
            chunks = calldata[2];
        } else if (commitTx.data.startsWith(iface.getFunction("commitBatch")!.selector!)) {
            const calldata = iface.decodeFunctionData("commitBatch", commitTx.data);
            chunks = calldata[2];
        } else {
            throw new Error("Invalid commit transaction");
        }
    }
    let lastL2Block = 0n;
    for (const chunk_ of chunks) {
        const chunk = ethers.toBeArray(chunk_ as ethers.BigNumberish);
        if (chunk.length === 0) {
            throw new Error("empty chunk");
        }
        const numBlocks = chunk[0];
        if (chunk.length !== 1 + numBlocks * 60) {
            throw new Error("invalid chunk length");
        }

        for (let i = 0; i < numBlocks; i++) {
            const block = chunk.subarray(1 + i * 60, 1 + (i + 1) * 60);
            const blockNumber = ethers.toBigInt(block.subarray(0, 8));
            lastL2Block = blockNumber > lastL2Block ? blockNumber : lastL2Block;
        }
    }
    if (lastL2Block === 0n) throw new Error("No L2 blocks");

    // this is guaranteed to return a tree size greater than or equal to the witnessed value
    const rekorEntry = await fetchRekorLogEntry(rekorEntryIndex);

    const origin = rekorEntry.verification.inclusionProof.checkpoint.split("\n")[0];

    const storageKey0 = ethers.toBigInt(ethers.keccak256(
        ethers.hexlify(new TextEncoder().encode(origin)) +
        ethers.keccak256("0x" + vw.init.rekorPublicKey[1] + ethers.keccak256("0x" + vw.init.rekorPublicKey[0] + "00".repeat(32)).substring(2)).substring(2)
    ));
    const storageKeys = [storageKey0, storageKey0 + 1n].map(ethers.toQuantity);

    const l2Proof: Proof = await scrRpc.send("eth_getProof", [vw.init.rekorWitnessOnScroll, storageKeys, ethers.toQuantity(lastL2Block)]);
    const witnessedTreeSize = ethers.toBigInt(l2Proof.storageProof[0].value);

    if (witnessedTreeSize === 0n) {
        throw new Error("Tree not found");
    }

    // Prove consistency
    // Request consistency proof from Sigstore Rekor API
    const inclusionProofTreeSize = BigInt(rekorEntry.verification.inclusionProof.treeSize);

    if (witnessedTreeSize >= inclusionProofTreeSize) {
        throw new Error(`Witnessed tree size is not less than inclusion proof tree size: ${witnessedTreeSize} > ${inclusionProofTreeSize}`);
    }

    // if (witnessedTreeSize <= BigInt(rekorEntry.verification.inclusionProof.logIndex)) {
    //     throw new Error(`Witnessed tree size is not greater than the log index: ${witnessedTreeSize} <= ${rekorEntry.verification.inclusionProof.logIndex}`);
    // }

    let consistencyProof: unknown;
    if (witnessedTreeSize === inclusionProofTreeSize) {
        consistencyProof = null;
    } else {
        const consistencyProofUrl = new URL("https://rekor.sigstore.dev/api/v1/log/proof");
        consistencyProofUrl.searchParams.append("firstSize", witnessedTreeSize.toString());
        consistencyProofUrl.searchParams.append("lastSize", inclusionProofTreeSize.toString());
        consistencyProofUrl.searchParams.append("treeID", origin.substring(origin.lastIndexOf(" ") + 1));

        const consistencyProofResponse = await fetch(consistencyProofUrl);

        if (!consistencyProofResponse.ok) {
            throw new Error(`Failed to fetch consistency proof: ${consistencyProofResponse.status} ${await consistencyProofResponse.text()}`);
        }

        consistencyProof = await consistencyProofResponse.json();
    }

    return {
        finalizationProof,
        l2Proof,
        rekorEntry,
        consistencyProof,
    };
}

interface RekorLogEntry {
    uuid: string,
    body: string,
    integratedTime: number,
    logID: string,
    logIndex: number,
    verification: {
        inclusionProof: {
            checkpoint: string,
            hashes: string[],
            logIndex: number,
            rootHash: string,
            treeSize: string,
        },
        signedEntryTimestamp: string,
    }
}

async function fetchRekorLogEntry(index: number): Promise<RekorLogEntry> {
    const res = await fetch(`https://rekor.sigstore.dev/api/v1/log/entries?logIndex=${index}`);
    if (!res.ok) {
        throw new Error(`Failed to fetch Rekor log entry: ${res.status} ${await res.text()}`);
    }

    const body = await res.json();
    if (typeof body !== "object" || body === null || Object.keys(body).length !== 1) {
        throw new Error(`Invalid Rekor log entry response: ${JSON.stringify(body)}`);
    }

    const output = Object.values(body)[0] as RekorLogEntry;
    output.uuid = Object.keys(body)[0];
    return output;
}