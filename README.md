# qz-toolkit

CLI tools for [QueryZero](https://queryzero.net) — BBS+ credential management with zero-knowledge selective disclosure.

## Tools

### qz-service

Register your service domain via DNS challenge and receive a BBS+ credential. Derive ZK proofs revealing only the claims you choose.

```bash
qz-service register api.example.com --category data-api
qz-service verify api.example.com
qz-service proof api.example.com --indexes 1,7,11
```

### qz-sign-domain

Sign your domain name with your wallet private key to prove ownership. Your key is used locally and never transmitted.

```bash
qz-sign-domain invoices.org --key 0x...
```

Then use the output to add your wallet to your service credential:

```bash
qz-service update invoices.org --wallet <address> --wallet-sig <signature>
```

### qz-agent

Register your agent via wallet signing and receive a BBS+ credential. Supports optional attestations (Moltbook, Farcaster).

```bash
qz-agent register my-agent --operator example.com --key 0x...
qz-agent proof my-agent --indexes 0,1,7
qz-agent attest farcaster my-agent
```

## Install

Requires [Bun](https://bun.sh) v1.0+.

```bash
git clone https://github.com/mcyork/qz-toolkit.git
cd qz-toolkit
bun install
```

That's it. The postinstall script automatically registers `qz-service`, `qz-sign-domain`, and `qz-agent` as global commands.

### Run directly (without global install)

```bash
bun packages/qz-service/src/cli.ts --help
bun packages/qz-agent/src/cli.ts --help
```

## Testnet

Both tools default to `https://queryzero.net`. For testnet:

```bash
qz-service register example.com --url http://testnet.queryzero.net
qz-agent register my-agent --operator example.com --key 0x... --url http://testnet.queryzero.net
```

## Examples

See the [examples/](examples/) directory for working integration samples.

## For AI Agents

See [`llms.txt`](llms.txt) for a machine-readable overview of this toolkit — what it does, how to register, and how to generate proofs.

## Known Issues

**Bun + blind BBS+ imports**: `@digitalbazaar/bbs-signatures` doesn't declare an `exports` map, so Bun can't resolve internal subpaths like `@digitalbazaar/bbs-signatures/lib/bbs/blind/interface.js`. If you're integrating proof generation into your own Bun project, use `require.resolve()` to build the path — see [`llms.txt`](llms.txt) for the workaround. This does not affect Node.js.

## License

MIT
