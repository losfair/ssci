import { Base64 } from "js-base64";
import { getUnverifiedFullProof } from "./proof.ts";
import { toHex } from "./session.ts";
import * as wasm from "./wasm.ts";

export interface LeafCertInfo {
    oidcIssuer?: string | null;
    buildSignerUri?: string | null;
    buildSignerDigest?: string | null;
}

export async function verifyPCRs(vw: wasm.VwCrypto, { stateRoot, blockNumber }: { stateRoot: string, blockNumber: number }, pcrs: readonly string[], rekorLogIndex: number): Promise<LeafCertInfo> {
    const signedPayload = new TextEncoder().encode(pcrs.join(","));
    const pcrhash = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", signedPayload)));

    const intermediateCA_ = (async () => {
        const res = await fetch("https://fulcio.sigstore.dev/api/v2/trustBundle");
        if (!res.ok) throw new Error(`Failed to fetch Fulcio trust bundle: ${res.status} ${await res.text()}`);
        const { chains: [{ certificates: [intermediateCA] }] } = await res.json();
        if (typeof intermediateCA !== "string") throw new Error("unexpected intermediate CA");
        return intermediateCA;
    })();

    const unverifiedProof_ = getUnverifiedFullProof(vw, blockNumber, rekorLogIndex);

    const [intermediateCA, unverifiedProof] = await Promise.all([intermediateCA_, unverifiedProof_]);

    const proof = vw.verifyProof(stateRoot, JSON.stringify(unverifiedProof));
    const body = JSON.parse(proof.body);
    if (body.kind !== "hashedrekord") {
        throw new Error("unexpected proof body kind, expected hashedrekord");
    }

    const { spec: { data: { hash: { algorithm: hashAlgorithm, value: hashValue } }, signature: { content: signatureContent, publicKey: { content: leafCertContent } } } } = body;
    if (typeof hashAlgorithm !== "string" || typeof hashValue !== "string" || typeof signatureContent !== "string" || typeof leafCertContent !== "string") {
        throw new Error("unexpected payload");
    }
    if (`${hashAlgorithm}:${hashValue}` !== `sha256:${pcrhash}`) {
        throw new Error("hash mismatch");
    }

    const info = vw.x509VerifyMessage(
        new TextEncoder().encode(intermediateCA),
        Base64.toUint8Array(leafCertContent),
        signedPayload,
        Base64.toUint8Array(signatureContent),
    );

    return JSON.parse(info);
}