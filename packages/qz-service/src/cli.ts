#!/usr/bin/env bun
/**
 * qz-service — QueryZero Service Credential CLI
 *
 * Register your service domain with QueryZero and obtain a BBS+ credential
 * with ZK selective disclosure. Uses blind signing — the holder secret never
 * leaves this machine. Only you can derive proofs.
 *
 * Usage: qz-service <command> [options]
 * Build: bun build src/cli.ts --compile --outfile dist/qz-service
 */

import * as bbs from '@digitalbazaar/bbs-signatures'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'
import { randomBytes } from 'crypto'

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
// Local credential storage (~/.qz/credentials/)
// ---------------------------------------------------------------------------

const QZ_DIR = join(homedir(), '.qz', 'credentials', 'services')

function ensureQzDir() {
  if (!existsSync(QZ_DIR)) {
    mkdirSync(QZ_DIR, { recursive: true })
  }
}

function credPath(domain: string): string {
  return join(QZ_DIR, `${domain}.json`)
}

function pendingPath(domain: string): string {
  return join(QZ_DIR, `${domain}.pending.json`)
}

function saveCredential(domain: string, data: any) {
  ensureQzDir()
  writeFileSync(credPath(domain), JSON.stringify(data, null, 2))
}

function loadCredential(domain: string): any | null {
  const p = credPath(domain)
  if (!existsSync(p)) return null
  return JSON.parse(readFileSync(p, 'utf-8'))
}

function savePending(domain: string, data: any) {
  ensureQzDir()
  writeFileSync(pendingPath(domain), JSON.stringify(data, null, 2))
}

function loadPending(domain: string): any | null {
  const p = pendingPath(domain)
  if (!existsSync(p)) return null
  return JSON.parse(readFileSync(p, 'utf-8'))
}

function deletePending(domain: string) {
  const p = pendingPath(domain)
  if (existsSync(p)) {
    const { unlinkSync } = require('fs')
    unlinkSync(p)
  }
}

// ---------------------------------------------------------------------------
// BBS+ blind signing helpers
// ---------------------------------------------------------------------------

let _blindModules: any = null

async function getBlindModules() {
  if (_blindModules) return _blindModules
  const blindIface = await import(
    /* @vite-ignore */ '../node_modules/@digitalbazaar/bbs-signatures/lib/bbs/blind/interface.js'
  )
  const ciphersuites = await import(
    /* @vite-ignore */ '../node_modules/@digitalbazaar/bbs-signatures/lib/bbs/ciphersuites.js'
  )
  const resolvedCiphersuite = ciphersuites.getCiphersuite(CIPHERSUITE)
  _blindModules = {
    Commit: blindIface.Commit,
    BlindProofGen: blindIface.BlindProofGen,
    BlindVerify: blindIface.BlindVerify,
    resolvedCiphersuite,
  }
  return _blindModules
}

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
 * Generate a holder secret locally, send commitment to server, get DNS challenge.
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

  // Generate holder secret and commitment client-side
  const { Commit, resolvedCiphersuite } = await getBlindModules()
  const holderSecret = new TextEncoder().encode(`holderSecret=${randomBytes(32).toString('hex')}`)
  const [commitmentWithProof, secretProverBlind] = await Commit({
    committed_messages: [holderSecret],
    ciphersuite: resolvedCiphersuite,
  })

  const body: Record<string, any> = {
    category,
    commitment: Buffer.from(commitmentWithProof).toString('base64'),
  }
  if (endpoint) body.endpoint = endpoint
  if (wallet) body.walletAddress = wallet
  if (paymentCapable) body.paymentCapable = true
  if (paymentEndpoint) body.paymentEndpoint = paymentEndpoint
  if (moltbookProfile) body.moltbookProfile = moltbookProfile

  const { status, data } = await apiPost(`/api/v1/services/${domain}/credential`, body)

  if (status >= 400) {
    die(data.error || `Server returned ${status}`)
  }

  // Save pending state locally (secret + commitment for verify step)
  savePending(domain, {
    domain,
    secretProverBlind: secretProverBlind.toString(16),
    holderSecret: Buffer.from(holderSecret).toString('base64'),
    nonce: data.nonce,
    category,
  })

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
  console.log('  Your holder secret has been saved locally. Only you can derive proofs.')
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
 * Verify the DNS challenge and receive the BBS+ blind-signed credential.
 * Saves the credential locally with the holder secret.
 */
async function verifyCommand(domain: string) {
  const pending = loadPending(domain)
  if (!pending) {
    die(`No pending registration for ${domain}. Run 'qz-service register ${domain}' first.`)
  }

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

  // Save credential locally with holder secret
  saveCredential(domain, {
    ...data,
    secretProverBlind: pending.secretProverBlind,
    holderSecret: pending.holderSecret,
  })
  deletePending(domain)

  console.log('')
  console.log('--- Credential Issued ---')
  console.log('')
  console.log(`  Type:        ${data.type}`)
  console.log(`  ID:          ${data.credentialId}`)
  console.log(`  Issued:      ${data.issuedAt}`)
  console.log(`  Expires:     ${data.expiresAt}`)
  console.log(`  Messages:    ${data.messageCount}`)
  console.log(`  Ciphersuite: ${data.ciphersuite}`)
  console.log(`  Holder-bound: ${data.blind ? 'yes' : 'no'}`)
  console.log('')
  console.log('  Claims:')
  for (let i = 0; i < data.messages.length; i++) {
    console.log(`    [${i}] ${data.messages[i]}`)
  }
  console.log('')
  console.log(`  Credential saved to: ${credPath(domain)}`)
  console.log('  This file contains your holder secret — treat it as confidential.')
  console.log('  Only you can derive proofs. Back it up; it cannot be re-downloaded.')
  console.log('  Use `qz-service proof` to derive proofs revealing only the claims you choose.')
}

/**
 * qz-service status <domain>
 *
 * Display locally stored credential.
 */
async function statusCommand(domain: string) {
  const cred = loadCredential(domain)
  if (!cred) {
    // Fall back to server
    console.log(`No local credential for ${domain}. Checking server...`)
    let data: any
    try {
      data = await apiGet(`/api/v1/services/${domain}/credential`)
    } catch {
      console.log(`No BBS+ credential found for ${domain}.`)
      console.log(`Register with: qz-service register ${domain}`)
      return
    }
    console.log('')
    console.log(`--- Service Credential: ${domain} (server-side, no holder secret) ---`)
    console.log('')
    console.log(`  Type:        ${data.type}`)
    console.log(`  ID:          ${data.credentialId}`)
    console.log(`  Issued:      ${data.issuedAt}`)
    console.log(`  Expires:     ${data.expiresAt}`)
    console.log(`  Holder-bound: ${data.blind ? 'yes' : 'no'}`)
    if (data.blind) {
      console.log('  WARNING: This is a blind credential but no local copy found.')
      console.log('  You cannot derive proofs without the holder secret.')
    }
    return
  }

  console.log('')
  console.log(`--- Service Credential: ${domain} ---`)
  console.log('')
  console.log(`  Type:        ${cred.type}`)
  console.log(`  ID:          ${cred.credentialId}`)
  console.log(`  Issued:      ${cred.issuedAt}`)
  console.log(`  Expires:     ${cred.expiresAt}`)
  console.log(`  Messages:    ${cred.messageCount}`)
  console.log(`  Ciphersuite: ${cred.ciphersuite}`)
  console.log(`  Holder-bound: ${cred.blind ? 'yes' : 'no'}`)
  console.log(`  Has secret:  ${cred.secretProverBlind ? 'yes' : 'no'}`)
  console.log('')
  console.log('  Claims:')
  for (let i = 0; i < cred.messages.length; i++) {
    console.log(`    [${String(i).padStart(2)}] ${cred.messages[i]}`)
  }
}

/**
 * qz-service proof <domain> --indexes 1,2,3
 *
 * Derive a BBS+ ZK proof revealing only the specified message indexes.
 * Uses the locally stored credential and holder secret.
 */
async function proofCommand(domain: string, indexes: number[]) {
  if (indexes.length === 0) die('--indexes required (e.g. --indexes 1,2,3)')

  const cred = loadCredential(domain)
  if (!cred) {
    die(`No local credential for ${domain}. Register first with: qz-service register ${domain}`)
  }
  if (!cred.signature) {
    die('Credential has no signature. The server may have returned metadata only.')
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

  let proof: Uint8Array

  if (cred.blind && cred.secretProverBlind && cred.holderSecret) {
    // Blind proof: requires holder secret
    const { BlindProofGen, resolvedCiphersuite } = await getBlindModules()
    const secretProverBlind = BigInt('0x' + cred.secretProverBlind)
    const holderSecret = new Uint8Array(Buffer.from(cred.holderSecret, 'base64'))

    proof = await BlindProofGen({
      PK: publicKey,
      signature,
      header,
      ph: new Uint8Array(),
      messages,
      disclosed_indexes: disclosedIndexes,
      committed_messages: [holderSecret],
      disclosed_commitment_indexes: [],
      secret_prover_blind: secretProverBlind,
      signer_blind: 0n,
      ciphersuite: resolvedCiphersuite,
    })
  } else {
    // Legacy non-blind proof
    proof = await bbs.deriveProof({
      publicKey,
      header,
      signature,
      messages,
      presentationHeader: new Uint8Array(),
      disclosedMessageIndexes: disclosedIndexes,
      ciphersuite: CIPHERSUITE,
    })
  }

  const proofBundle = {
    type: cred.type,
    schema: cred.schema,
    header: cred.header,
    proof: Buffer.from(proof).toString('base64'),
    publicKey: cred.publicKey,
    ciphersuite: CIPHERSUITE,
    disclosedIndexes,
    disclosedMessages: Object.fromEntries(
      disclosedIndexes.map((i: number) => [i, cred.messages[i]]),
    ),
    totalMessages: cred.messageCount,
    blind: cred.blind || false,
  }

  // Proof JSON goes to stdout (pipe-friendly)
  console.log(JSON.stringify(proofBundle, null, 2))
}

/**
 * qz-service update <domain> [--wallet <addr> --wallet-sig <sig>] [--payment-capable] [--payment-endpoint <url>] [--moltbook-profile <url>]
 *
 * Update an existing credential with new attestation fields.
 * Uses ZK proof to authenticate as the credential holder.
 * Wallet additions require an ECDSA signature proving ownership —
 * sign your domain name with your wallet using any tool you trust.
 * Re-issues with a new blind signature.
 */
async function updateCommand(domain: string) {
  const cred = loadCredential(domain)
  if (!cred) {
    die(`No local credential for ${domain}. Register first with: qz-service register ${domain}`)
  }
  if (!cred.signature) {
    die('Credential has no signature. Cannot generate proof for authentication.')
  }

  const wallet = getFlag('--wallet', '')
  const walletSig = getFlag('--wallet-sig', '')
  const paymentCapable = hasFlag('--payment-capable')
  const paymentEndpoint = getFlag('--payment-endpoint', '')
  const moltbookProfile = getFlag('--moltbook-profile', '')

  if (!wallet && !paymentCapable && !paymentEndpoint && !moltbookProfile) {
    die('At least one update required: --wallet, --payment-capable, --payment-endpoint, --moltbook-profile')
  }

  if (wallet && !walletSig) {
    console.error('error: --wallet-sig required when adding a wallet.')
    console.error('')
    console.error('You must prove wallet ownership by signing your domain name.')
    console.error('Sign the exact string "' + domain + '" with your wallet using any tool you trust:')
    console.error('')
    console.error('  # Foundry (cast)')
    console.error(`  cast wallet sign "${domain}" --private-key <your-key>`)
    console.error('')
    console.error('  # Node.js (viem)')
    console.error(`  import { privateKeyToAccount } from 'viem/accounts'`)
    console.error(`  const sig = await privateKeyToAccount('0x...').signMessage({ message: '${domain}' })`)
    console.error('')
    console.error('  # MetaMask (browser console)')
    console.error(`  await ethereum.request({ method: 'personal_sign', params: ['${domain}', '<your-address>'] })`)
    console.error('')
    console.error('Then pass the signature:')
    console.error(`  qz-service update ${domain} --wallet <address> --wallet-sig <0x-signature>`)
    process.exit(1)
  }

  console.log(`Updating credential for ${domain}...`)

  const body: Record<string, any> = {}
  if (wallet) {
    body.walletAddress = wallet
    body.walletSignature = walletSig
    console.log(`  Adding wallet: ${wallet}`)
    console.log(`  Wallet signature: ${walletSig.slice(0, 10)}...${walletSig.slice(-6)}`)
  }
  if (paymentCapable) { body.paymentCapable = true; console.log('  Enabling payments') }
  if (paymentEndpoint) { body.paymentEndpoint = paymentEndpoint; console.log(`  Payment endpoint: ${paymentEndpoint}`) }
  if (moltbookProfile) { body.moltbookProfile = moltbookProfile; console.log(`  Moltbook profile: ${moltbookProfile}`) }

  // Generate proof disclosing subjectDid (index 0) for authentication
  if (cred.blind && cred.secretProverBlind && cred.holderSecret) {
    console.log('  Generating ZK proof for authentication...')
    const header = new Uint8Array(Buffer.from(cred.header, 'base64'))
    const signature = new Uint8Array(Buffer.from(cred.signature, 'base64'))
    const publicKey = new Uint8Array(Buffer.from(cred.publicKey, 'base64'))
    const messages = (cred.messages as string[]).map((m: string) => new TextEncoder().encode(m))

    const { BlindProofGen, resolvedCiphersuite } = await getBlindModules()
    const secretProverBlind = BigInt('0x' + cred.secretProverBlind)
    const holderSecret = new Uint8Array(Buffer.from(cred.holderSecret, 'base64'))

    const proof = await BlindProofGen({
      PK: publicKey, signature, header,
      ph: new Uint8Array(), messages,
      disclosed_indexes: [0],
      committed_messages: [holderSecret],
      disclosed_commitment_indexes: [],
      secret_prover_blind: secretProverBlind,
      signer_blind: 0n,
      ciphersuite: resolvedCiphersuite,
    })
    body.proof = Buffer.from(proof).toString('base64')

    // Generate new commitment for re-issuance
    console.log('  Generating new commitment for re-issuance...')
    const { Commit } = await getBlindModules()
    const newHolderSecret = new TextEncoder().encode(`holderSecret=${randomBytes(32).toString('hex')}`)
    const [newCommitment, newSecretProverBlind] = await Commit({
      committed_messages: [newHolderSecret],
      ciphersuite: resolvedCiphersuite,
    })
    body.commitment = Buffer.from(newCommitment).toString('base64')

    const { status, data } = await apiPost(`/api/v1/services/${domain}/credential/update`, body)

    if (status >= 400) {
      die(data.error || `Server returned ${status}`)
    }

    const newCred = data.credential || data

    // Save updated credential with new holder secret
    saveCredential(domain, {
      ...newCred,
      secretProverBlind: newSecretProverBlind.toString(16),
      holderSecret: Buffer.from(newHolderSecret).toString('base64'),
    })

    console.log('')
    console.log('--- Credential Updated ---')
    console.log('')
    console.log(`  ID:          ${newCred.credentialId}`)
    console.log(`  Issued:      ${newCred.issuedAt}`)
    console.log(`  Holder-bound: ${newCred.blind ? 'yes' : 'no'}`)
    console.log('')
    console.log('  Updated claims:')
    for (let i = 0; i < newCred.messages.length; i++) {
      console.log(`    [${String(i).padStart(2)}] ${newCred.messages[i]}`)
    }
    console.log('')
    console.log(`  Credential saved to: ${credPath(domain)}`)
    console.log('  This file contains your holder secret — treat it as confidential.')
  } else {
    die('Only blind (holder-bound) credentials support proof-based updates.')
  }
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
with ZK selective disclosure and holder binding.

Usage:
  qz-service register <domain>                  Request credential (get DNS challenge)
  qz-service verify <domain>                    Verify DNS and receive credential
  qz-service update <domain>                    Update credential attestations
  qz-service status <domain>                    Display stored credential
  qz-service proof <domain> --indexes 1,2,3     Derive ZK proof for specified claims
  qz-service schema                             View service identity schema
  qz-service categories                         List valid service categories

Register options:
  --category <type>          Service category (required)
  --endpoint <url>           Service endpoint URL

Update options (add attestations after DNS verification):
  --wallet <address>         Wallet address on Base (triggers KYC/Farcaster checks)
  --wallet-sig <signature>   ECDSA signature proving wallet ownership (sign the domain name)
  --payment-capable          Flag: service accepts x402 payments
  --payment-endpoint <url>   Payment endpoint URL
  --moltbook-profile <url>   Moltbook social profile URL

Global options:
  --url <url>                QueryZero server URL (default: https://queryzero.net)
  --help                     Show this help

Credentials are stored locally in ~/.qz/credentials/services/
Your holder secret never leaves this machine.

Examples:
  qz-service categories
  qz-service register api.example.com --category dns-intelligence --endpoint https://api.example.com/lookup
  qz-service verify api.example.com
  qz-service update api.example.com --wallet 0x... --wallet-sig 0x...
  qz-service update api.example.com --payment-capable --payment-endpoint https://api.example.com/pay
  qz-service status api.example.com
  qz-service proof api.example.com --indexes 1,7
  qz-service schema

Wallet signature: to add a wallet, sign your domain name with your wallet key.
  cast wallet sign "api.example.com" --private-key <key>    # Foundry
  See --help for MetaMask and Node.js examples.
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
    case 'update': {
      const domain = args[1]
      if (!domain || domain.startsWith('-')) die('domain required: qz-service update <domain>')
      await updateCommand(domain)
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
