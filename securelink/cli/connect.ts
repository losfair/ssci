import { defaultVwContextInit, VwCrypto } from "../src/wasm.ts";
import WebSocket from "isomorphic-ws";
import process from "node:process";
import { Session } from "../src/session.ts";
import { defaultExecutionLayerHeaderProviders, getTrustedStateRoot } from "../src/trusted_state_root.ts";
import { verifyPCRs } from "../src/verify.ts";
import arg from "arg"

(async () => {
    const args = arg({
        "--help": Boolean,
        "--unsafe-allow-unwitnessed-entries": Boolean,
        "--unsafe-no-verify": Boolean,
        "--github-repository": String,
        "--github-commit-sha": String,
        "--remote-url": String,
    });

    const githubRepoNameRegex = /^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/;

    const vw = await VwCrypto.load({ ...defaultVwContextInit(), unsafeAllowUnwitnessedEntries: !!args["--unsafe-allow-unwitnessed-entries"] });

    let ws: WebSocket;
    const httpProxy = process.env.http_proxy || process.env.HTTP_PROXY;
    const remoteUrl = args["--remote-url"];

    if (!remoteUrl) {
        throw new Error("Missing required argument --remote-url");
    }

    if ("WebSocket" in globalThis || !httpProxy) {
        // native websocket support detected or no proxy needed, do not manually configure proxy
        ws = new WebSocket(remoteUrl);
    } else {
        const { setGlobalDispatcher, ProxyAgent } = await import("undici");
        const { HttpsProxyAgent } = await import("https-proxy-agent");

        const dispatcher = new ProxyAgent({ uri: httpProxy });
        setGlobalDispatcher(dispatcher);

        ws = new WebSocket(remoteUrl, {
            agent: new HttpsProxyAgent(httpProxy)
        });
    }
    const session = await Session.open(vw, ws as unknown as globalThis.WebSocket, 22);
    console.warn("Remote PCRs verified with Nitro Enclave attestation:");
    for (let i = 0; i < session.pcrs.length; i++) {
        console.warn(` ${i}: ${session.pcrs[i]}`);
    }

    if (args["--unsafe-no-verify"]) {
        console.warn("⚠️  WARNING: --unsafe-no-verify is enabled, skipping transparency log check");
    } else {
        if (vw.init.unsafeAllowUnwitnessedEntries) {
            console.warn("⚠️  WARNING: --unsafe-allow-unwitnessed-entries is enabled, this allows Rekor entries that are not yet witnessed on Ethereum to be accepted");
        }

        console.warn(`Verifying remote PCRs with provided Rekor log index ${session.rekorLogIndex}...`);
        const tsr = await getTrustedStateRoot(defaultExecutionLayerHeaderProviders());
        const info = await verifyPCRs(vw, tsr, session.pcrs, session.rekorLogIndex);

        const githubRepoName = args["--github-repository"];
        const githubCommitSha = args["--github-commit-sha"];

        if (!githubRepoName) throw new Error("--unsafe-no-verify is not enabled but missing required argument --github-repository");
        if (!githubRepoName.match(githubRepoNameRegex)) throw new Error("Invalid GitHub repository name");

        if (info.oidcIssuer !== "https://token.actions.githubusercontent.com") {
            throw new Error(`OIDC issuer '${info.oidcIssuer}' does not match expected value 'https://token.actions.githubusercontent.com'`);
        }
        if (!info.buildSignerUri?.startsWith(`https://github.com/${githubRepoName}/`)) {
            throw new Error(`Build signer URI '${info.buildSignerUri}' does not match expected GitHub repository '${githubRepoName}'`);
        }
        if (githubCommitSha && info.buildSignerDigest !== githubCommitSha) {
            throw new Error(`Build signer digest '${info.buildSignerDigest}' does not match expected commit SHA '${githubCommitSha}'`);
        }

        console.warn(info);

        if (vw.init.unsafeAllowUnwitnessedEntries) {
            console.warn("🟡 Remote PCRs are signed with a Fulcio certificate and logged to Rekor, but may not be witnessed on Ethereum yet");
        } else {
            console.warn("✅ Remote PCRs are signed with a Fulcio certificate, logged to Rekor, and witnessed on Ethereum");
        }
    }

    process.stdin.on("data", (data) => {
        session.send(data);
    });

    while (true) {
        const m = await session.next();
        if (!m) process.exit(0);
        await new Promise<void>(resolve => {
            if (process.stdout.write(m)) return resolve();
            process.stdout.once("drain", resolve);
        });
    }
})().catch(e => {
    console.error(e);
    process.exit(1);
})
