# Service Proof Example

Serve your QueryZero service credential as a verifiable ZK proof in HTTP headers.

This demonstrates how a service can prove its identity to callers — DNS verified, KYC status, wallet address — without revealing all credential claims. Uses BBS+ blind proofs with selective disclosure.

## Prerequisites

- [Bun](https://bun.sh) v1.0+
- A registered service credential (see below)

## Setup

```bash
cd examples/service-proof
bun install
```

## Register a credential (if you don't have one)

```bash
# From the repo root — install and register CLI tools:
cd ../.. && bun install

# Register with testnet:
qz-service register myservice.com --category data-api --url http://testnet.queryzero.net

# Add the DNS TXT record shown, then verify:
qz-service verify myservice.com --url http://testnet.queryzero.net

# Your credential is now at: ~/.qz/credentials/services/myservice.com.json
```

## Serve

Start a local HTTP server that includes your credential proof on every response:

```bash
bun run serve.ts myservice.com
```

Options:
- `--port 3000` — port to listen on (default: 3000)
- `--indexes 0,1,2,5,7` — which claims to disclose (default: 0,1,2,5,7,10,13)
- `--credential ./path.json` — custom credential path

The server responds to any request with a JSON body and an `X-Service-Credential` header containing the base64-encoded proof bundle.

## Verify

Verify a proof from a running server:

```bash
bun run verify.ts http://localhost:3000
```

Or verify against a live QueryZero service:

```bash
bun run verify.ts https://invoices.org
```

Or verify a proof directly:

```bash
bun run verify.ts --proof <base64-proof-string>
```

The verifier will:
1. Fetch the `X-Service-Credential` header
2. Decode the proof bundle
3. Print all disclosed claims
4. Cryptographically verify the BBS+ blind proof
5. Show credential metadata (issuer, expiry, etc.)

## Proof Bundle Format

The `X-Service-Credential` header contains a base64-encoded JSON object:

```json
{
  "type": "QueryZeroServiceIdentity",
  "schema": "https://queryzero.net/api/v1/schemas/service-identity-v1",
  "header": "<base64 credential header>",
  "proof": "<base64 BBS+ proof>",
  "publicKey": "<base64 issuer public key>",
  "ciphersuite": "BLS12-381-SHA-256",
  "disclosedIndexes": [0, 1, 2, 5, 7, 10, 13],
  "disclosedMessages": {
    "0": "subjectDid=did:web:example.com",
    "1": "serviceDomain=example.com",
    "2": "category=data-api",
    "5": "paymentCapable=true",
    "7": "dnsVerified=true",
    "10": "walletAddress=0x...",
    "13": "kycVerified=true"
  },
  "totalMessages": 16,
  "blind": true
}
```

## Service Credential Claims (16 total)

| Index | Claim | Description |
|-------|-------|-------------|
| 0 | subjectDid | DID of the service (did:web:domain) |
| 1 | serviceDomain | Domain name |
| 2 | category | Service category |
| 3 | operator | Registry operator |
| 4 | registeredAt | Registration timestamp |
| 5 | paymentCapable | Accepts payments |
| 6 | paymentEndpoint | Payment URL |
| 7 | dnsVerified | DNS challenge passed |
| 8 | moltbookVerified | Moltbook profile verified |
| 9 | moltbookProfile | Moltbook profile URL |
| 10 | walletAddress | Ethereum wallet |
| 11 | usdcBlacklisted | USDC blacklist status |
| 12 | emailVerified | Email verified |
| 13 | kycVerified | KYC verified |
| 14 | farcasterFid | Farcaster ID |
| 15 | domainAge | Domain age in days |

Choose which indexes to disclose based on what callers need to verify.
