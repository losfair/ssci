import { VwCrypto } from "./wasm.ts";
import ipaddr from "ipaddr.js";

const internal = Symbol("SecurelinkSession");
const closedErr = new Error("WebSocket closed");

interface State {
    send: (msg: Uint8Array) => void;
    unsealedMessages: (Uint8Array | Error)[];
    waiters: (() => void)[];
}

export class Session {
    [internal]: State
    readonly pcrs: readonly string[];

    constructor(sym: typeof internal, st: State, pcrs: string[], public readonly rekorLogIndex: number) {
        if (sym !== internal) throw new Error("Session is not a constructor");
        this[internal] = st;
        this.pcrs = Object.freeze([...pcrs]);
    }

    send(m: Uint8Array) {
        this[internal].send(m);
    }

    next(): Promise<Uint8Array | null> {
        const st = this[internal];
        return (async () => {
            while (!st.unsealedMessages.length) {
                await new Promise<void>(resolve => st.waiters.push(resolve));
            }

            const head = st.unsealedMessages[0];
            if (head instanceof Error) {
                if (head === closedErr) return null;
                throw new Error(`Failed to receive message: ${head}`);
            } else {
                st.unsealedMessages.shift();
                return head;
            }
        })();
    }

    static async open(vw: VwCrypto, ws: WebSocket, port: number): Promise<Session> {
        ws.binaryType = "arraybuffer";
        const fail = new Promise<any>((_resolve, reject) => {
            ws.onclose = () => reject(new Error("WebSocket closed before handshake completion"));
            ws.onerror = () => reject(new Error(`WebSocket error during handshake: ${ws.readyState}`));
        });

        await Promise.race([new Promise(resolve => {
            if (ws.readyState === ws.OPEN) return resolve(null);
            ws.onopen = resolve;
        }), fail]);

        const dhSecret = crypto.getRandomValues(new Uint8Array(32));
        const dhPublic = vw.x25519PublicKey(dhSecret);
        ws.send(dhPublic);

        const pendingMessages: ArrayBuffer[] = [];
        const { metadata, theirPublic, attestation: attestation_ }: { metadata: unknown, theirPublic: ArrayBuffer, attestation: ArrayBuffer } = await Promise.race([new Promise((resolve, reject) => {
            const catchIt = (...handlers: ((data: unknown, last: unknown) => unknown)[]) => {
                let last: unknown = null;
                let merged: (({ data }: { data: unknown }) => void) | null = null;

                for (const h of [...handlers].reverse()) {
                    const lastMerged = merged;
                    merged = ({ data }) => {
                        try {
                            last = h(data, last);
                        } catch (e) {
                            return reject(e);
                        }

                        if (lastMerged) ws.onmessage = lastMerged;
                    }
                }
                if (merged) ws.onmessage = merged;
            };
            catchIt(
                (metadata_, _last) => {
                    if (typeof metadata_ !== "string") throw new Error("metadata is not a string");
                    const metadata = JSON.parse(metadata_);
                    return { metadata };
                },
                (theirPublic, last) => {
                    if (!(theirPublic instanceof ArrayBuffer)) throw new Error("unexpected message type");
                    return { ...last as any, theirPublic };
                },
                (attestation, last) => {
                    if (!(attestation instanceof ArrayBuffer)) throw new Error("unexpected message type");
                    resolve({ ...last as any, attestation });
                },
                (data, _last) => {
                    if (!(data instanceof ArrayBuffer)) throw new Error("unexpected message type");
                    pendingMessages.push(data);
                }
            )
        }), fail]);

        if (typeof metadata !== "object" || metadata === null) throw new Error("metadata is not an object");
        const { rekorLogIndex } = metadata as Record<string, unknown>;
        if (typeof rekorLogIndex !== "number" || !Number.isSafeInteger(rekorLogIndex) || rekorLogIndex < 0) {
            throw new Error("rekorLogIndex is not a safe non-negative integer");
        }

        const sharedSecret = vw.x25519DiffieHellman(dhSecret, new Uint8Array(theirPublic));

        const keys = {
            attestation: vw.blake3DeriveKey256("attestation", sharedSecret),
            proxyReq: vw.blake3DeriveKey256("proxy_req", sharedSecret),
            c2s: vw.blake3DeriveKey256("c2s", sharedSecret),
            s2c: vw.blake3DeriveKey256("s2c", sharedSecret),
        }

        const prefixedAttestation = vw.chacha20poly1305Unseal(keys.attestation, 0n, new Uint8Array(attestation_));
        if (prefixedAttestation[0] !== 1) {
            throw new Error("attestation prefix not recognized");
        }

        const attestation = vw.deserializeAndVerifyAttestationDoc(prefixedAttestation.subarray(1));

        // check for MITM
        if (toHex(Uint8Array.from(attestation.user_data ?? [])) !== toHex(dhPublic)) {
            throw new Error("attestation user_data does not match dhPublic");
        }

        const pcrs = [
            toHex(Uint8Array.from(attestation.pcrs["0"])),
            toHex(Uint8Array.from(attestation.pcrs["1"])),
            toHex(Uint8Array.from(attestation.pcrs["2"])),
        ];

        {
            const port_ = new DataView(new ArrayBuffer(2))
            port_.setUint16(0, port);
            const backendAddr = [...ipaddr.parse("::ffff:127.0.0.1").toByteArray(), ...new Uint8Array(port_.buffer)];
            const msg = vw.chacha20poly1305Seal(keys.proxyReq, 0n, Uint8Array.from(backendAddr));
            ws.send(msg);
        }

        let c2sNonce = 1n;
        let s2cNonce = 1n;

        const st: State = {
            send: (msg) => {
                ws.send(vw.chacha20poly1305Seal(keys.c2s, c2sNonce++, msg));
            },
            unsealedMessages: [],
            waiters: [],
        }

        const pushAndWake = (m: Uint8Array | Error) => {
            st.unsealedMessages.push(m);
            while (st.unsealedMessages.length && st.waiters.length) {
                const w = st.waiters.shift()!;
                w();
            }

        }
        const processMessage = (msg: ArrayBuffer) => {
            if (!(msg instanceof ArrayBuffer)) throw new Error("processMessage: expecting ArrayBuffer");
            const unsealed = vw.chacha20poly1305Unseal(keys.s2c, s2cNonce++, new Uint8Array(msg));
            pushAndWake(unsealed);
        };

        ws.onmessage = ({ data }) => processMessage(data);
        ws.onerror = (e) => pushAndWake(new Error(`WebSocket error: ${e}`));
        ws.onclose = () => pushAndWake(closedErr);

        for (const m of pendingMessages) {
            processMessage(m);
        }

        return new Session(internal, st, pcrs, rekorLogIndex);
    }
}

export function toHex(input: Uint8Array): string {
    return [...input].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

