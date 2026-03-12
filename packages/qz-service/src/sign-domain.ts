#!/usr/bin/env bun
/**
 * qz-sign-domain — Sign a domain name with your wallet private key
 *
 * Produces an ECDSA signature proving you own a wallet address.
 * Used with `qz-service update --wallet-sig` to add a wallet to your
 * service credential.
 *
 * Your private key is used locally to sign and is never transmitted.
 *
 * Usage:
 *   qz-sign-domain <domain>                          # reads key from QZ_WALLET_KEY env var
 *   qz-sign-domain <domain> --key <private-key>      # pass key directly
 *
 * Examples:
 *   export QZ_WALLET_KEY=0x...
 *   qz-sign-domain invoices.org
 *
 *   qz-sign-domain invoices.org --key 0xabc123...
 *
 * Then use the output with qz-service:
 *   qz-service update invoices.org --wallet <address> --wallet-sig <output>
 */
import { privateKeyToAccount } from 'viem/accounts'

const args = process.argv.slice(2)

function getFlag(name: string): string {
  const idx = args.indexOf(name)
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1]
  return ''
}

const domain = args.find(a => !a.startsWith('-'))
const key = getFlag('--key') || process.env.QZ_WALLET_KEY

if (!domain) {
  console.error('Usage: qz-sign-domain <domain> [--key <private-key>]')
  console.error('')
  console.error('Signs the domain name with your wallet private key.')
  console.error('Set QZ_WALLET_KEY env var or pass --key.')
  console.error('')
  console.error('Your key is used locally and never transmitted.')
  process.exit(1)
}

if (!key) {
  console.error('error: No private key provided.')
  console.error('')
  console.error('Either set the QZ_WALLET_KEY environment variable:')
  console.error('  export QZ_WALLET_KEY=0x...')
  console.error('')
  console.error('Or pass it directly:')
  console.error(`  qz-sign-domain ${domain} --key 0x...`)
  process.exit(1)
}

const normalized = key.startsWith('0x') ? key : `0x${key}`
if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
  console.error('error: Invalid private key format. Must be 64 hex characters (with or without 0x prefix).')
  process.exit(1)
}

const account = privateKeyToAccount(normalized as `0x${string}`)
const signature = await account.signMessage({ message: domain })

console.error(`Wallet:    ${account.address}`)
console.error(`Domain:    ${domain}`)
console.error(`Signature: ${signature.slice(0, 10)}...${signature.slice(-6)}`)
console.error('')
console.error('Use with:')
console.error(`  qz-service update ${domain} --wallet ${account.address} --wallet-sig ${signature}`)
console.error('')

// Stdout gets just the signature (pipe-friendly)
console.log(signature)
