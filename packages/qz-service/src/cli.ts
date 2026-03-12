#!/usr/bin/env bun
/**
 * qz-service — QueryZero Service Credential CLI
 *
 * Register your service domain with QueryZero and obtain a BBS+ credential
 * with ZK selective disclosure. Prove any subset of claims about your service
 * without revealing the rest.
 *
 * Usage: qz-service <command> [options]
 * Build: bun build src/cli.ts --compile --outfile dist/qz-service
 */

import * as bbs from '@digitalbazaar/bbs-signatures'

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

const args = process.argv.slice(2)

function getFlag(name: string, defaultValue: string): string {
  const idx = args.indexOf(name)
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1]
  }
  return defaultValue
}

function hasFlag(name: string): boolean {
  return args.includes(name)
}

function getFlagValues(name: string): number[] {
  const idx = args.indexOf(name)
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1].split(',').map(Number)
  }
  return []
}

const SERVER_URL = getFlag('--url', 'https://queryzero.net')
const CIPHERSUITE = 'BLS12-381-SHA-256'

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function apiGet(path: string): Promise<any> {
  const res = await fetch(`${SERVER_URL}${path}`)
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`GET ${path} failed (${res.status}): ${body}`)
  }
  return res.json()
}

async function apiPost(path: string, body?: object): Promise<{ status: number; data: any }> {
  const res = await fetch(`${SERVER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({ error: 'Invalid response' }))
  return { status: res.status, data }
}

function die(message: string): never {
  console.error(`error: ${message}`)
  process.exit(1)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/**
 * qz-service register <domain>
 *
 * Request a service credential. The server returns a nonce that must be placed
 * in a _qz DNS TXT record to prove domain ownership.
 */
async function registerCommand(domain: string) {
  const category = getFlag('--category', '')
  const endpoint = getFlag('--endpoint', '')
  const wallet = getFlag('--wallet', '')
  const paymentCapable = hasFlag('--payment-capable')
  const paymentEndpoint = getFlag('--payment-endpoint', '')
  const moltbookProfile = getFlag('--moltbook-profile', '')

  if (!category) die('--category required. Use `qz-service categories` to list valid options.')

  console.log(`Requesting credential for ${domain}...`)

  const body: Record<string, any> = { category }
  if (endpoint) body.endpoint = endpoint
  if (wallet) body.walletAddress = wallet
  if (paymentCapable) body.paymentCapable = true
  if (paymentEndpoint) body.paymentEndpoint = paymentEndpoint
  if (moltbookProfile) body.moltbookProfile = moltbookProfile

  const { status, data } = await apiPost(`/api/v1/services/${domain}/credential`, body)

  if (status >= 400) {
    die(data.error || `Server returned ${status}`)
  }

  console.log('')
  console.log('--- DNS Challenge ---')
  console.log('')
  console.log('  Add a TXT record to your DNS:')
  console.log('')
  console.log(`    Host:  _qz.${domain}`)
  console.log(`    Value: ${data.dnsChallenge}`)
  console.log('')
  console.log('  This record becomes the permanent service discovery record.')
  console.log('  After DNS propagation (typically 1-5 minutes), run:')
  console.log('')
  console.log(`    qz-service verify ${domain}`)
  console.log('')
}

/**
 * qz-service categories
 *
 * List valid service categories from the server.
 */
async function categoriesCommand() {
  const data = await apiGet('/api/v1/categories')

  console.log('')
  console.log('--- Service Categories ---')
  console.log('')
  for (const cat of data.categories) {
    console.log(`  ${cat.slug.padEnd(20)} ${cat.description}`)
  }
  console.log('')
}

/**
 * qz-service verify <domain>
 *
 * Verify the DNS challenge and receive the BBS+ credential.
 */
async function verifyCommand(domain: string) {
  console.log(`Verifying DNS challenge for ${domain}...`)

  const { status, data } = await apiPost(`/api/v1/services/${domain}/credential/verify`)

  if (status >= 400) {
    const error = data.error || `Server returned ${status}`
    if (error.includes('DNS verification failed') || error.includes('DNS lookup failed')) {
      console.error(`\nerror: ${error}`)
      console.error('')
      console.error('The DNS TXT record was not found. This could mean:')
      console.error('  1. The record hasn\'t propagated yet (wait a few minutes and try again)')
      console.error('  2. The record was set on the wrong host (should be _qz, not @)')
      console.error('  3. The value doesn\'t match the nonce from the register step')
      console.error('')
      console.error(`You can check propagation: dig TXT _qz.${domain}`)
      process.exit(1)
    }
    die(error)
  }

  console.log('')
  console.log('--- Credential Issued ---')
  console.log('')
  console.log(`  Type:        ${data.type}`)
  console.log(`  ID:          ${data.credentialId}`)
  console.log(`  Issued:      ${data.issuedAt}`)
  console.log(`  Expires:     ${data.expiresAt}`)
  console.log(`  Messages:    ${data.messageCount}`)
  console.log(`  Ciphersuite: ${data.ciphersuite}`)
  console.log('')
  console.log('  Claims:')
  for (let i = 0; i < data.messages.length; i++) {
    console.log(`    [${i}] ${data.messages[i]}`)
  }
  console.log('')
  console.log('Your service now has a BBS+ credential with ZK selective disclosure.')
  console.log('Use `qz-service proof` to derive proofs revealing only the claims you choose.')
}

/**
 * qz-service status <domain>
 *
 * Retrieve and display the stored credential.
 */
async function statusCommand(domain: string) {
  console.log(`Fetching credential for ${domain}...`)

  let data: any
  try {
    data = await apiGet(`/api/v1/services/${domain}/credential`)
  } catch {
    console.log(`No BBS+ credential found for ${domain}.`)
    console.log(`Register with: qz-service register ${domain}`)
    return
  }

  console.log('')
  console.log(`--- Service Credential: ${domain} ---`)
  console.log('')
  console.log(`  Type:        ${data.type}`)
  console.log(`  ID:          ${data.credentialId}`)
  console.log(`  Issued:      ${data.issuedAt}`)
  console.log(`  Expires:     ${data.expiresAt}`)
  console.log(`  Messages:    ${data.messageCount}`)
  console.log(`  Ciphersuite: ${data.ciphersuite}`)
  console.log('')
  console.log('  Claims:')
  for (let i = 0; i < data.messages.length; i++) {
    console.log(`    [${String(i).padStart(2)}] ${data.messages[i]}`)
  }
}

/**
 * qz-service proof <domain> --indexes 1,2,3
 *
 * Derive a BBS+ ZK proof revealing only the specified message indexes.
 */
async function proofCommand(domain: string, indexes: number[]) {
  if (indexes.length === 0) die('--indexes required (e.g. --indexes 1,2,3)')

  console.error(`Loading credential for ${domain}...`)

  let cred: any
  try {
    cred = await apiGet(`/api/v1/services/${domain}/credential`)
  } catch {
    die(`No credential found for ${domain}. Register first with: qz-service register ${domain}`)
  }

  const header = new Uint8Array(Buffer.from(cred.header, 'base64'))
  const signature = new Uint8Array(Buffer.from(cred.signature, 'base64'))
  const publicKey = new Uint8Array(Buffer.from(cred.publicKey, 'base64'))
  const messages = (cred.messages as string[]).map(
    (m: string) => new TextEncoder().encode(m),
  )

  const disclosedIndexes = indexes.sort((a, b) => a - b)
  for (const i of disclosedIndexes) {
    if (i < 0 || i >= messages.length) die(`index ${i} out of range (0-${messages.length - 1})`)
  }

  console.error(`Deriving proof for indexes [${disclosedIndexes.join(', ')}]...`)

  const proof = await bbs.deriveProof({
    publicKey,
    header,
    signature,
    messages,
    disclosedMessageIndexes: disclosedIndexes,
    ciphersuite: CIPHERSUITE,
  })

  const proofBundle = {
    type: cred.type,
    schema: cred.schema,
    header: cred.header,
    proof: Buffer.from(proof).toString('base64'),
    publicKey: cred.publicKey,
    ciphersuite: CIPHERSUITE,
    disclosedIndexes,
    disclosedMessages: Object.fromEntries(
      disclosedIndexes.map((i) => [i, cred.messages[i]]),
    ),
    totalMessages: cred.messageCount,
  }

  // Proof JSON goes to stdout (pipe-friendly)
  console.log(JSON.stringify(proofBundle, null, 2))
}

/**
 * qz-service schema
 *
 * Fetch and display the service identity schema.
 */
async function schemaCommand() {
  console.log('Fetching service identity schema...')

  const data = await apiGet('/api/v1/schemas/service-identity-v1')

  console.log('')
  console.log(`--- ${data.name} v${data.version} ---`)
  console.log(`  Ciphersuite: ${data.ciphersuite}`)
  console.log(`  Messages:    ${data.messageCount}`)
  console.log('')
  for (let i = 0; i < data.messageCount; i++) {
    const msg = data.messages[String(i)]
    const verified = msg.verified ? ` [${msg.verified}]` : ''
    console.log(`  [${String(i).padStart(2)}] ${msg.name} (${msg.type})${verified}`)
    console.log(`       ${msg.description}`)
  }
}

// ---------------------------------------------------------------------------
// Usage / dispatch
// ---------------------------------------------------------------------------

function printUsage() {
  console.log(`qz-service — QueryZero Service Credential CLI

Register your service domain with QueryZero and obtain a BBS+ credential
with ZK selective disclosure.

Usage:
  qz-service register <domain>                  Request credential (get DNS challenge)
  qz-service verify <domain>                    Verify DNS and receive credential
  qz-service status <domain>                    Display stored credential
  qz-service proof <domain> --indexes 1,2,3     Derive ZK proof for specified claims
  qz-service schema                             View service identity schema
  qz-service categories                         List valid service categories

Register options:
  --category <type>          Service category (required)
  --endpoint <url>           Service endpoint URL
  --wallet <address>         Optional wallet address on Base
  --payment-capable          Flag: service accepts x402 payments
  --payment-endpoint <url>   Payment endpoint URL
  --moltbook-profile <url>   Moltbook social profile URL

Global options:
  --url <url>                QueryZero server URL (default: https://queryzero.net)
  --help                     Show this help

Examples:
  qz-service categories
  qz-service register api.example.com --category dns-intelligence --endpoint https://api.example.com/lookup
  qz-service verify api.example.com
  qz-service status api.example.com
  qz-service proof api.example.com --indexes 1,7
  qz-service schema
`)
}

async function main() {
  const command = args[0]

  if (!command || command === '--help' || command === '-h') {
    printUsage()
    process.exit(0)
  }

  switch (command) {
    case 'register': {
      const domain = args[1]
      if (!domain || domain.startsWith('-')) die('domain required: qz-service register <domain>')
      await registerCommand(domain)
      break
    }
    case 'verify': {
      const domain = args[1]
      if (!domain || domain.startsWith('-')) die('domain required: qz-service verify <domain>')
      await verifyCommand(domain)
      break
    }
    case 'status': {
      const domain = args[1]
      if (!domain || domain.startsWith('-')) die('domain required: qz-service status <domain>')
      await statusCommand(domain)
      break
    }
    case 'proof': {
      const domain = args[1]
      if (!domain || domain.startsWith('-')) die('domain required: qz-service proof <domain>')
      const indexes = getFlagValues('--indexes')
      await proofCommand(domain, indexes)
      break
    }
    case 'schema': {
      await schemaCommand()
      break
    }
    case 'categories': {
      await categoriesCommand()
      break
    }
    default: {
      printUsage()
      die(`unknown command: ${command}`)
    }
  }
}

main().catch((err) => {
  console.error(err.message || err)
  process.exit(1)
})
