import * as uwasi from "uwasi";

const getBytecode = async () => {
    const url = new URL("./vwcrypto.wasm", (globalThis as any).__injectedModuleUrl ?? import.meta.url);

    if ("Deno" in globalThis || "window" in globalThis) {
        return fetch(url);
    } else {
        // node, built by esbuild
        const fs = await import("fs/promises");
        return new Response(await fs.readFile(url), {
            headers: {
                "Content-Type": "application/wasm",
            },
        });
    }
}

let vwcryptoBytecode: Promise<WebAssembly.Module> | (() => Promise<WebAssembly.Module>) = async () => {
    const stream = getBytecode();
    if ("compileStreaming" in WebAssembly) {
        return WebAssembly.compileStreaming(stream);
    } else {
        const res = await stream;
        if (!res.ok) {
            throw new Error(`Failed to fetch vwcrypto.wasm: ${res.status} ${await res.text()}`);
        }
        return WebAssembly.compile(await res.arrayBuffer());
    }
};

function getVwcryptoBytecode(): Promise<WebAssembly.Module> {
    if (typeof vwcryptoBytecode === "function") {
        vwcryptoBytecode = vwcryptoBytecode();
    }
    return vwcryptoBytecode;
}

const internal = Symbol("securelink.vwcrypto.internal");

export interface VwContextInit {
    scrollL1Proxy: string;
    rekorWitnessOnScroll: string;
    rekorPublicKey: [string, string];
    unsafeAllowUnwitnessedEntries?: boolean;
}

export interface VerifiedProof {
    body: string;
    origin: string;
    logIndex: number;
}

export interface AttestationDoc {
    module_id: string;
    digest: "SHA256" | "SHA384" | "SHA512",
    timestamp: number,
    pcrs: Record<string, number[]>,
    certificate: number[],
    cabundle: number[][],
    public_key: number[] | null,
    user_data: number[] | null,
    nonce: number[] | null,
}

export function defaultVwContextInit(): VwContextInit {
    return {
        scrollL1Proxy: "0xa13BAF47339d63B743e7Da8741db5456DAc1E556",
        rekorWitnessOnScroll: "0x91249a54EfEFF79e333D4c9C49fcfAbE72687909",
        rekorPublicKey: [
            "D86D98FB6B5A6DD4D5E41706881231D1AF5F005C2B9016E62D21AD92CE0BDEA5",
            "FAC98634CEE7C19E10BC52BFE2CB9E468563FFF40FDB6362E10B7D0CF7E458B7",
        ],
    };
}

export class VwCrypto {
    constructor(sym: typeof internal, public readonly init: VwContextInit, public readonly instance: WebAssembly.Instance, private readonly wasi: uwasi.WASI, private readonly ctx: number) {
        if (sym !== internal) throw new Error("VwCrypto is not a constructor");
    }

    static async load(init: VwContextInit): Promise<VwCrypto> {
        const m = await getVwcryptoBytecode();
        const wasi = new uwasi.WASI({
            args: [],
            features: [uwasi.useAll()],
        });
        const instance = await WebAssembly.instantiate(m, {
            wasi_snapshot_preview1: wasi.wasiImport,
        });
        wasi.initialize(instance);

        const ctx: number = withCString(instance, JSON.stringify(init), init => (instance.exports.vw_context_create as any)(init));
        if (typeof ctx !== "number" || ctx === 0) throw new Error("Could not create context");

        return new VwCrypto(internal, init, instance, wasi, ctx);
    }

    getStorageKeySet(batchIndex: bigint, origin: string): {
        ethL2StateRootKey: string;
        scrWitnessedTreeSizeKey: string;
        scrWitnessedTreeRootKey: string;
    } {
        return withCString(this.instance, origin, origin => JSON.parse(takeCString(this.instance, (this.instance.exports.vw_get_storage_key_set as any)(this.ctx, batchIndex, origin))));
    }

    verifyProof(trustedStateRoot: string, proof: string): VerifiedProof {
        return withCString(this.instance, trustedStateRoot, trustedStateRoot => withCString(this.instance, proof, proof => {
            const result = (this.instance.exports.vw_verify_proof as any)(this.ctx, trustedStateRoot, proof);
            if (typeof result !== "number" || result === 0) throw new Error("Could not verify proof");
            return JSON.parse(takeCString(this.instance, result));
        }));
    }

    deserializeAndVerifyAttestationDoc(doc: Uint8Array): AttestationDoc {
        return withBytes(this.instance, doc, (doc_) => {
            const output: number = (this.instance.exports.vw_deserialize_and_verify_attestation_doc as any)(doc_, doc.length);
            if (typeof output !== "number" || output === 0) throw new Error("Could not deserialize and verify attestation doc");
            return JSON.parse(takeCString(this.instance, output));
        });
    }

    blake3DeriveKey256(context: string, keyMaterial: Uint8Array): Uint8Array {
        return withCString(this.instance, context, context => withBytes(this.instance, keyMaterial, keyMaterial_ =>
            withBytes(this.instance, new Uint8Array(32), (output, m) => {
                (this.instance.exports.vw_blake3_derive_key_256 as any)(context, keyMaterial_, keyMaterial.length, output);
                return m.slice();
            })
        ))
    }

    x25519PublicKey(secret: Uint8Array): Uint8Array {
        return withBytes(this.instance, secret, secret_ => withBytes(this.instance, new Uint8Array(32), (output, m) => {
            if (secret.length !== 32) throw new Error("secret must be 32 bytes");
            (this.instance.exports.vw_x25519_public_key as any)(secret_, output);
            return m.slice();
        }));
    }

    x25519DiffieHellman(ourSecret: Uint8Array, theirPublic: Uint8Array): Uint8Array {
        return withBytes(this.instance, ourSecret, ourSecret_ => withBytes(this.instance, theirPublic, theirPublic_ =>
            withBytes(this.instance, new Uint8Array(32), (output, m) => {
                if (ourSecret.length !== 32) throw new Error("ourSecret must be 32 bytes");
                if (theirPublic.length !== 32) throw new Error("theirPublic must be 32 bytes");

                (this.instance.exports.vw_x25519_diffie_hellman as any)(ourSecret_, theirPublic_, output);
                return m.slice();
            })
        ));
    }

    chacha20poly1305Seal(key: Uint8Array, nonce: bigint, data: Uint8Array): Uint8Array {
        return withBytes(this.instance, key, key_ => withBytes(this.instance, { data, capacity: data.length + 16 }, (data_, m) => {
            if (key.length !== 32) throw new Error("key must be 32 bytes");
            const ret = (this.instance.exports.vw_chacha20poly1305_seal as any)(key_, nonce, data_, m.length);
            if (ret !== 0) throw new Error(`Seal failed with code ${ret}`);
            return m.slice();
        }))
    }

    chacha20poly1305Unseal(key: Uint8Array, nonce: bigint, data: Uint8Array): Uint8Array {
        return withBytes(this.instance, key, key_ => withBytes(this.instance, data, (data_, m) => {
            if (key.length !== 32) throw new Error("key must be 32 bytes");
            const ret = (this.instance.exports.vw_chacha20poly1305_unseal as any)(key_, nonce, data_, m.length);
            if (ret !== 0) throw new Error(`Unseal failed with code ${ret}`);
            return m.slice(0, m.length - 16);
        }))
    }

    x509VerifyMessage(ca: Uint8Array, cert: Uint8Array, message: Uint8Array, signature: Uint8Array): string {
        return withBytes(this.instance, ca, ca_ => withBytes(this.instance, cert, cert_ => withBytes(this.instance, message, message_ => withBytes(this.instance, signature, signature_ =>
            withBytes(this.instance, new Uint8Array(4), (outPtr, outPtrM) => {
                const ret = (this.instance.exports.vw_x509_verify_message as any)(outPtr, ca_, ca.length, cert_, cert.length, message_, message.length, signature_, signature.length);
                if (ret !== 0) throw new Error(`X509 verify failed with code ${ret}`);
                const ptr = new Uint32Array(outPtrM.buffer, outPtrM.byteOffset, 1)[0];
                if (ptr === 0) throw new Error("X509 verify succeeded but returned null pointer");
                return takeCString(this.instance, ptr);
            })
        ))))
    }
}

function withBytes<T>(instance: WebAssembly.Instance, bytes_: Uint8Array | { data: Uint8Array, capacity: number }, callback: (ptr: number, buf: Uint8Array) => T): T {
    const bytes__ = bytes_ instanceof Uint8Array ? [bytes_, bytes_.length] as const : (bytes_.data instanceof Uint8Array && Number.isSafeInteger(bytes_.capacity)) ? [bytes_.data, bytes_.capacity] as const : null;
    if (!bytes__) throw new Error("invalid input data");
    const [bytes, capacity] = bytes__;

    const ptr = (instance.exports.vw_malloc as any)(capacity);
    if (typeof ptr !== "number" || ptr === 0) {
        throw new Error("Could not allocate memory");
    }

    const memory = new Uint8Array(
        (instance.exports.memory as WebAssembly.Memory).buffer,
        ptr,
        capacity,
    );
    memory.set(bytes);
    try {
        return callback(ptr, memory);
    } finally {
        (instance.exports.vw_free as any)(ptr);
    }
}

function withCString<T>(instance: WebAssembly.Instance, str: string, callback: (ptr: number) => T): T {
    const bytes = new TextEncoder().encode(str);
    const ptr = (instance.exports.vw_malloc as any)(bytes.length + 1);
    if (ptr === 0) {
        throw new Error("Could not allocate memory");
    }
    const memory = new Uint8Array(
        (instance.exports.memory as WebAssembly.Memory).buffer,
        ptr,
        bytes.length + 1,
    );
    memory.set(bytes);
    memory[bytes.length] = 0;
    try {
        return callback(ptr);
    } finally {
        (instance.exports.vw_free as any)(ptr);
    }
}

function takeCString(instance: WebAssembly.Instance, ptr: number) {
    if (typeof ptr !== "number" || ptr === 0) throw new Error("Attempting to take a null pointer as a C string");

    const memory = new Uint8Array((instance.exports.memory as WebAssembly.Memory).buffer);
    const start = ptr;
    let end = start;
    while (memory[end] !== 0) {
        end += 1;
    }
    const str = new TextDecoder().decode(memory.subarray(start, end));
    (instance.exports.vw_free as any)(ptr);
    return str;
}