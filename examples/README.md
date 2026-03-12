# QueryZero Examples

Working examples for agents and services using QueryZero credentials.

## service-proof

Serve your service credential as a ZK proof in HTTP headers and verify proofs from other services.

```bash
cd service-proof && bun install
bun run serve.ts myservice.com        # serve proof on localhost:3000
bun run verify.ts http://localhost:3000  # verify the proof
bun run verify.ts https://invoices.org  # verify a live service
```

See [service-proof/README.md](service-proof/README.md) for full documentation.
