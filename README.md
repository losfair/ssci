# SSCI

Server Side Code Integrity.

Verify that a remote service runs the expected code before connecting to it.
Specifically, verify that the service runs in an
[AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/), is signed
by [Sigstore](https://www.sigstore.dev/)'s
[Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) code signing
CA, is built by a GitHub Actions workflow in a specific repository, is logged to
Sigstore's [Rekor](https://docs.sigstore.dev/logging/overview/) transparency
log, and the state of the Rekor log has been
[witnessed on Ethereum](https://github.com/losfair/rekor-evm).

The connection is secured by X25519 + ChaCha20-Poly1305. Nobody between you and
the enclave can see the data.

## Demo

The following demo application
([source](https://github.com/losfair/whoami.ssci.dev)) is accessible via SSH. It
prints the SSH public keys that your client uses to authenticate, but nobody
except you can see them - not even us.

Try it out:

```bash
proxy_command="deno run --allow-net --allow-env https://ssci.dev/run/connect.min.mjs --remote-url "ws://demo.ssci.dev:8000" --github-repository losfair/whoami.ssci.dev"
ssh -o "ProxyCommand $proxy_command" -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking no" user@enclave
```

If you don't trust `ssci.dev`, you can also pull the `securelink` package from
[Releases](https://github.com/losfair/ssci/releases), verify its signature using
[cosign](https://github.com/sigstore/cosign), and run `connect.mjs` locally with
Deno or Node:

```bash
mkdir securelink
cd securelink
wget -O securelink.tar.gz https://github.com/losfair/ssci/releases/download/v0.1.1/securelink-v0.1.1.tar.gz
tar -xvf securelink.tar.gz
cosign verify-blob --bundle SHA256SUMS.bundle.json --certificate-identity-regexp '^https://github\.com/losfair/ssci/' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' SHA256SUMS
sha256sum -c SHA256SUMS

proxy_command="node connect.mjs --remote-url "ws://demo.ssci.dev:8000" --github-repository losfair/whoami.ssci.dev"
ssh -o "ProxyCommand $proxy_command" -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking no" user@enclave
```
