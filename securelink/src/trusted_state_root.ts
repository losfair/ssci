import * as ethers from "ethers";

export interface IExecutionLayerHeaderProvider {
    description(): string;
    getFinalizedStateRoot(abort: AbortSignal): Promise<{ description: string, blockNumber: number, stateRoot: string }>;
}

export class BeaconAPI implements IExecutionLayerHeaderProvider {
    constructor(public endpoint: string) { }

    description(): string {
        return `Beacon API at ${this.endpoint}`;
    }

    async getFinalizedStateRoot(abort: AbortSignal): Promise<{ description: string, blockNumber: number; stateRoot: string }> {
        const res = await fetch(`${this.endpoint}/eth/v2/beacon/blocks/finalized`, { signal: abort })
        if (!res.ok) {
            res.body?.cancel();
            throw new Error(`HTTP error: ${res.status}`);
        }

        const { data: { message: { body: { execution_payload: { state_root, block_number } } } } } = await res.json();
        if (typeof state_root !== "string" || !state_root.startsWith("0x")) throw new Error(`Invalid state root`);
        const blockNumber = parseInt(block_number);
        if (!Number.isSafeInteger(blockNumber) || blockNumber <= 0) throw new Error(`Invalid block number`);

        return {
            description: this.description(),
            stateRoot: state_root.substring(2),
            blockNumber,
        }
    }
}

export class ExecutionAPI implements IExecutionLayerHeaderProvider {
    constructor(public endpoint: string) { }

    description(): string {
        return `Execution API at ${this.endpoint}`;
    }

    async getFinalizedStateRoot(abort: AbortSignal): Promise<{ description: string, blockNumber: number; stateRoot: string }> {
        const res = await fetch(`${this.endpoint}`, {
            signal: abort,
            method: "POST",
            headers: {
                "content-type": "application/json",
            },
            body: JSON.stringify({
                "method": "eth_getBlockByNumber",
                "params": ["finalized", false],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        });
        if (!res.ok) {
            res.body?.cancel();
            throw new Error(`HTTP error: ${res.status}`);
        }

        const { number, stateRoot } = (await res.json()).result;
        if (typeof number !== "string" || !number.startsWith("0x")) throw new Error(`Invalid block number`);
        const blockNumber = ethers.toNumber(number);
        if (blockNumber <= 0) throw new Error(`Invalid block number`);
        if (typeof stateRoot !== "string" || !stateRoot.startsWith("0x")) throw new Error(`Invalid state root`);
        return {
            description: this.description(),
            stateRoot: stateRoot.substring(2),
            blockNumber,
        }
    }
}

export function defaultExecutionLayerHeaderProviders(): IExecutionLayerHeaderProvider[] {
    return [
        new BeaconAPI("https://www.lightclientdata.org"), // AS14618 - AWS
        new BeaconAPI("https://sync-mainnet.beaconcha.in"), // AS24940 - Hetzner
        new BeaconAPI("https://mainnet.checkpoint.sigp.io"), // AS16276 - OVH
        new BeaconAPI("https://mainnet-checkpoint-sync.attestant.io"), // AS25369 - Hydra Communications Ltd
        new BeaconAPI("https://beaconstate.ethstaker.cc"), // AS16276 - OVH
        new ExecutionAPI("https://rpc.flashbots.net"), // AS13335 - Cloudflare
        new ExecutionAPI("https://rpc.ankr.com/eth"), // AS13335 - Cloudflare
        new ExecutionAPI("https://eth-mainnet.public.blastapi.io"), // AS13335 - Cloudflare
        new ExecutionAPI("https://rpc.payload.de"), // AS24940 - Hetzner
        new ExecutionAPI("https://rpc.mevblocker.io"), // AS16509 - AWS
        new ExecutionAPI("https://mainnet.gateway.tenderly.co"), // AS396982 - GCP
        new ExecutionAPI("https://1rpc.io/eth"), // AS8075 - Azure?
    ];
}


export async function getTrustedStateRoot(providers: IExecutionLayerHeaderProvider[]): Promise<{
    blockNumber: number, stateRoot: string, responses: {
        description: string;
        blockNumber: number;
        stateRoot: string;
    }[], failed: string[]
}> {
    if (providers.length === 0) throw new Error("No providers");

    const abort = new AbortController();
    const timeoutId = setTimeout(() => abort.abort(), 5000);
    const failed: string[] = [];
    const responses = await Promise.all(providers.map(async provider => {
        try {
            return await provider.getFinalizedStateRoot(abort.signal);
        } catch (e) {
            console.error(`Failed to fetch finalized state root from '${provider.description()}': ${e}`);
            failed.push(provider.description());
            return null;
        }
    }));
    clearTimeout(timeoutId);

    const quorum = Math.floor(providers.length / 2) + 1;
    const blockNumberCounts = new Map<number, number>();
    for (const resp of responses) {
        if (!resp) continue;
        blockNumberCounts.set(resp.blockNumber, (blockNumberCounts.get(resp.blockNumber) || 0) + 1);
    }

    let quorumBlockNumber: number | undefined = undefined;
    for (const [blockNumber, count] of blockNumberCounts) {
        if (count >= quorum) {
            quorumBlockNumber = blockNumber;
            break;
        }
    }

    if (quorumBlockNumber === undefined) throw new Error("No quorum block number");

    const quorumStateRoots = [...new Set(responses.filter(resp => resp?.blockNumber === quorumBlockNumber).map(resp => resp!.stateRoot))];
    if (quorumStateRoots.length !== 1) {
        throw new Error(`Quorum state roots at block ${quorumBlockNumber} mismatch: ${JSON.stringify(quorumStateRoots)}`);
    }

    return {
        blockNumber: quorumBlockNumber,
        stateRoot: quorumStateRoots[0],
        responses: responses.filter(x => x).map(x => x!),
        failed,
    }
}