#!/usr/bin/env bun
/**
 * qz-agent — QueryZero Agent Credential CLI
 *
 * Register your agent with QueryZero using wallet signing and obtain a BBS+
 * credential with ZK selective disclosure. Uses blind signing — the holder
 * secret never leaves this machine. Only you can derive proofs.
 *
 * Usage: qz-agent <command> [options]
 * Build: bun build src/cli.ts --compile --outfile dist/qz-agent
 */

import * as bbs from '@digitalbazaar/bbs-signatures'
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'
import { randomBytes } from 'crypto'
import { privateKeyToAccount } from 'viem/accounts'
import type { PrivateKeyAccount } from 'viem'

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
// Local credential storage (~/.qz/credentials/agents/)
// ---------------------------------------------------------------------------

const QZ_DIR = join(homedir(), '.qz', 'credentials', 'agents')

function ensureQzDir() {
  if (!existsSync(QZ_DIR)) {
    mkdirSync(QZ_DIR, { recursive: true })
  }
}

function credPath(agentName: string): string {
  return join(QZ_DIR, `${agentName}.json`)
}

function pendingPath(agentName: string): string {
  return join(QZ_DIR, `${agentName}.pending.json`)
}

function saveCredential(agentName: string, data: any) {
  ensureQzDir()
  writeFileSync(credPath(agentName), JSON.stringify(data, null, 2))
}

function loadCredential(agentName: string): any | null {
  const p = credPath(agentName)
  if (!existsSync(p)) return null
  return JSON.parse(readFileSync(p, 'utf-8'))
}

function savePending(agentName: string, data: any) {
  ensureQzDir()
  writeFileSync(pendingPath(agentName), JSON.stringify(data, null, 2))
}

function loadPending(agentName: string): any | null {
  const p = pendingPath(agentName)
  if (!existsSync(p)) return null
  return JSON.parse(readFileSync(p, 'utf-8'))
}

function deletePending(agentName: string) {
  const p = pendingPath(agentName)
  if (existsSync(p)) unlinkSync(p)
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
// Wallet helpers
// ---------------------------------------------------------------------------

function getPrivateKey(): `0x${string}` {
  const keyFlag = getFlag('--key', '')
  const keyEnv = process.env.QZ_WALLET_KEY || ''
  const key = keyFlag || keyEnv

  if (!key) {
    die('Wallet private key required. Use --key <hex> or set QZ_WALLET_KEY env var.')
  }

  const normalized = key.startsWith('0x') ? key : `0x${key}`
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    die('Invalid private key format. Must be 64 hex characters (with or without 0x prefix).')
  }

  return normalized as `0x${string}`
}

function getAccount(): PrivateKeyAccount {
  return privateKeyToAccount(getPrivateKey())
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
// Proof generation helper (used by proof command and attestation commands)
// ---------------------------------------------------------------------------

async function generateProof(cred: any, disclosedIndexes: number[]): Promise<string> {
  const header = new Uint8Array(Buffer.from(cred.header, 'base64'))
  const signature = new Uint8Array(Buffer.from(cred.signature, 'base64'))
  const publicKey = new Uint8Array(Buffer.from(cred.publicKey, 'base64'))
  const messages = (cred.messages as string[]).map(
    (m: string) => new TextEncoder().encode(m),
  )

  let proof: Uint8Array

  if (cred.blind && cred.secretProverBlind && cred.holderSecret) {
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

  return Buffer.from(proof).toString('base64')
}

// ---------------------------------------------------------------------------
// Commitment generation helper (used by register and attestation re-issuance)
// ---------------------------------------------------------------------------

async function generateCommitment(): Promise<{
  commitmentBase64: string
  secretProverBlind: string
  holderSecretBase64: string
}> {
  const { Commit, resolvedCiphersuite } = await getBlindModules()
  const holderSecret = new TextEncoder().encode(`holderSecret=${randomBytes(32).toString('hex')}`)
  const [commitmentWithProof, secretProverBlind] = await Commit({
    committed_messages: [holderSecret],
    ciphersuite: resolvedCiphersuite,
  })

  return {
    commitmentBase64: Buffer.from(commitmentWithProof).toString('base64'),
    secretProverBlind: secretProverBlind.toString(16),
    holderSecretBase64: Buffer.from(holderSecret).toString('base64'),
  }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/**
 * qz-agent register <agentName>
 *
 * Generate holder secret, send commitment + wallet signature to server,
 * receive blind-signed credential and save locally.
 */
async function registerCommand(agentName: string) {
  const account = getAccount()
  const operator = getFlag('--operator', '')
  const moltbookAgent = getFlag('--moltbook-agent', '')
  const paymentCapable = hasFlag('--payment-capable')
  const walletNetwork = getFlag('--wallet-network', 'eip155:8453')

  if (!operator) die('--operator <domain> required (e.g. --operator example.com)')

  console.log(`Requesting credential for agent "${agentName}"...`)
  console.log(`  Wallet: ${account.address}`)
  console.log(`  Operator: ${operator}`)

  // Generate holder secret and commitment client-side
  const { commitmentBase64, secretProverBlind, holderSecretBase64 } = await generateCommitment()

  const body: Record<string, any> = {
    wallet_address: account.address,
    operator,
    wallet_network: walletNetwork,
    commitment: commitmentBase64,
  }
  if (moltbookAgent) body.moltbook_agent = moltbookAgent
  if (paymentCapable) body.payment_capable = true

  const { status, data } = await apiPost(`/api/v1/agents/${agentName}/credential`, body)

  if (status >= 400) {
    die(data.error || `Server returned ${status}`)
  }

  // Save pending state (secret for after verify step)
  savePending(agentName, {
    agentName,
    secretProverBlind,
    holderSecret: holderSecretBase64,
    nonce: data.nonce,
    wallet: account.address,
  })

  // Auto-sign the nonce
  console.log('')
  console.log('Nonce received. Signing with wallet...')

  const signature = await account.signMessage({ message: data.nonce })

  console.log('Verifying signature with server...')

  const verifyResult = await apiPost(`/api/v1/agents/${agentName}/credential/verify`, {
    nonce: data.nonce,
    signature,
  })

  if (verifyResult.status >= 400) {
    deletePending(agentName)
    die(verifyResult.data.error || `Verification failed (${verifyResult.status})`)
  }

  const cred = verifyResult.data.credential || verifyResult.data

  // Save credential locally with holder secret
  saveCredential(agentName, {
    ...cred,
    secretProverBlind,
    holderSecret: holderSecretBase64,
  })
  deletePending(agentName)

  console.log('')
  console.log('--- Credential Issued ---')
  console.log('')
  console.log(`  Type:        ${cred.type}`)
  console.log(`  ID:          ${cred.credentialId}`)
  console.log(`  Issued:      ${cred.issuedAt}`)
  console.log(`  Expires:     ${cred.expiresAt}`)
  console.log(`  Messages:    ${cred.messageCount}`)
  console.log(`  Ciphersuite: ${cred.ciphersuite}`)
  console.log(`  Holder-bound: ${cred.blind ? 'yes' : 'no'}`)
  console.log('')
  console.log('  Claims:')
  for (let i = 0; i < cred.messages.length; i++) {
    console.log(`    [${String(i).padStart(2)}] ${cred.messages[i]}`)
  }
  console.log('')
  console.log(`  Credential saved to: ${credPath(agentName)}`)
  console.log('  This file contains your holder secret — treat it as confidential.')
  console.log('  Only you can derive proofs. Back it up; it cannot be re-downloaded.')
  console.log('  Use `qz-agent proof` to derive proofs revealing only the claims you choose.')
}

/**
 * qz-agent status <agentName>
 *
 * Display locally stored credential, fall back to server.
 */
async function statusCommand(agentName: string) {
  const cred = loadCredential(agentName)
  if (!cred) {
    // Fall back to server
    console.log(`No local credential for "${agentName}". Checking server...`)
    let data: any
    try {
      data = await apiGet(`/api/v1/agents/${agentName}/credential`)
    } catch {
      console.log(`No BBS+ credential found for agent "${agentName}".`)
      console.log(`Register with: qz-agent register ${agentName} --operator <domain> --key <key>`)
      return
    }
    const c = data.credential || data
    console.log('')
    console.log(`--- Agent Credential: ${agentName} (server-side, no holder secret) ---`)
    console.log('')
    console.log(`  Type:        ${c.type}`)
    console.log(`  ID:          ${c.credentialId}`)
    console.log(`  Issued:      ${c.issuedAt}`)
    console.log(`  Expires:     ${c.expiresAt}`)
    console.log(`  Holder-bound: ${c.blind ? 'yes' : 'no'}`)
    if (c.blind) {
      console.log('  WARNING: This is a blind credential but no local copy found.')
      console.log('  You cannot derive proofs without the holder secret.')
    }
    return
  }

  console.log('')
  console.log(`--- Agent Credential: ${agentName} ---`)
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
 * qz-agent proof <agentName> --indexes 1,2,3
 *
 * Derive a BBS+ ZK proof revealing only the specified message indexes.
 * Uses the locally stored credential and holder secret.
 */
async function proofCommand(agentName: string, indexes: number[]) {
  if (indexes.length === 0) die('--indexes required (e.g. --indexes 1,2,3)')

  const cred = loadCredential(agentName)
  if (!cred) {
    die(`No local credential for "${agentName}". Register first with: qz-agent register ${agentName}`)
  }
  if (!cred.signature) {
    die('Credential has no signature. The server may have returned metadata only.')
  }

  const disclosedIndexes = indexes.sort((a, b) => a - b)
  for (const i of disclosedIndexes) {
    if (i < 0 || i >= cred.messages.length) die(`index ${i} out of range (0-${cred.messages.length - 1})`)
  }

  console.error(`Deriving proof for indexes [${disclosedIndexes.join(', ')}]...`)

  const proofBase64 = await generateProof(cred, disclosedIndexes)

  const proofBundle = {
    type: cred.type,
    schema: cred.schema,
    header: cred.header,
    proof: proofBase64,
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
 * qz-agent schema
 *
 * Fetch and display the agent identity schema.
 */
async function schemaCommand() {
  console.log('Fetching agent identity schema...')

  const data = await apiGet('/api/v1/schemas/agent-identity-v1')

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

/**
 * qz-agent attest moltbook <agentName>
 *
 * Initiate Moltbook attestation — get a challenge token, post it as a comment,
 * then verify.
 */
async function attestMoltbookCommand(agentName: string) {
  console.log(`Requesting Moltbook attestation for agent "${agentName}"...`)

  const moltbookAgent = getFlag('--moltbook-agent', '')

  const body: Record<string, any> = {}
  if (moltbookAgent) body.moltbook_agent = moltbookAgent

  const { status, data } = await apiPost(`/api/v1/agents/${agentName}/credential/moltbook`, body)

  if (status >= 400) {
    die(data.error || `Server returned ${status}`)
  }

  console.log('')
  console.log('--- Moltbook Challenge ---')
  console.log('')
  console.log(`  Token: ${data.token}`)
  console.log('')
  console.log(`  ${data.message}`)
  if (data.verification_thread) {
    console.log(`  Thread: ${data.verification_thread}`)
  }
  console.log('')
  console.log('After posting the comment, run:')
  console.log('')
  console.log(`  qz-agent attest moltbook-verify ${agentName} --comment-id <id>`)
}

/**
 * qz-agent attest moltbook-verify <agentName> --comment-id <id>
 *
 * Verify a Moltbook comment and re-issue credential with moltbookVerified=true.
 * For blind credentials: sends ZK proof (disclosing subjectDid at index 0)
 * and a new commitment for re-issuance.
 */
async function attestMoltbookVerifyCommand(agentName: string) {
  const commentId = getFlag('--comment-id', '')
  if (!commentId) die('--comment-id required')

  console.log(`Verifying Moltbook comment for agent "${agentName}"...`)

  const cred = loadCredential(agentName)
  const body: Record<string, any> = { comment_id: commentId }

  let newSecretProverBlind: string | undefined
  let newHolderSecretBase64: string | undefined

  if (cred && cred.blind && cred.secretProverBlind && cred.signature) {
    // Generate proof disclosing subjectDid (index 0) for authentication
    console.log('  Generating ZK proof for authentication...')
    body.proof = await generateProof(cred, [0])

    // Generate new commitment for re-issuance
    console.log('  Generating new commitment for re-issuance...')
    const commit = await generateCommitment()
    body.commitment = commit.commitmentBase64
    newSecretProverBlind = commit.secretProverBlind
    newHolderSecretBase64 = commit.holderSecretBase64
  }

  const { status, data } = await apiPost(`/api/v1/agents/${agentName}/credential/moltbook/verify`, body)

  if (status >= 400) {
    die(data.error || `Server returned ${status}`)
  }

  const newCred = data.credential || data

  // Save updated credential locally
  if (newCred.signature) {
    saveCredential(agentName, {
      ...newCred,
      secretProverBlind: newSecretProverBlind || cred?.secretProverBlind,
      holderSecret: newHolderSecretBase64 || cred?.holderSecret,
    })
  }

  console.log('')
  console.log('--- Moltbook Attestation Complete ---')
  console.log('')
  console.log(`  Status: ${data.status}`)
  console.log(`  ID:     ${newCred.credentialId}`)
  console.log('')
  console.log('Credential re-issued with moltbookVerified=true.')
  if (newCred.signature) {
    console.log(`Saved to: ${credPath(agentName)}`)
  }
}

/**
 * qz-agent attest farcaster <agentName>
 *
 * Look up Farcaster identity by wallet address and re-issue credential.
 * For blind credentials: sends ZK proof and new commitment.
 */
async function attestFarcasterCommand(agentName: string) {
  console.log(`Requesting Farcaster attestation for agent "${agentName}"...`)

  const cred = loadCredential(agentName)
  const body: Record<string, any> = {}

  let newSecretProverBlind: string | undefined
  let newHolderSecretBase64: string | undefined

  if (cred && cred.blind && cred.secretProverBlind && cred.signature) {
    // Generate proof disclosing subjectDid (index 0) for authentication
    console.log('  Generating ZK proof for authentication...')
    body.proof = await generateProof(cred, [0])

    // Generate new commitment for re-issuance
    console.log('  Generating new commitment for re-issuance...')
    const commit = await generateCommitment()
    body.commitment = commit.commitmentBase64
    newSecretProverBlind = commit.secretProverBlind
    newHolderSecretBase64 = commit.holderSecretBase64
  }

  const { status, data } = await apiPost(`/api/v1/agents/${agentName}/credential/farcaster`, body)

  if (status >= 400) {
    die(data.error || `Server returned ${status}`)
  }

  const newCred = data.credential || data

  // Save updated credential locally
  if (newCred.signature) {
    saveCredential(agentName, {
      ...newCred,
      secretProverBlind: newSecretProverBlind || cred?.secretProverBlind,
      holderSecret: newHolderSecretBase64 || cred?.holderSecret,
    })
  }

  console.log('')
  console.log('--- Farcaster Attestation Complete ---')
  console.log('')
  console.log(`  Status: ${data.status}`)
  console.log(`  ID:     ${newCred.credentialId}`)
  console.log('')
  console.log('Credential re-issued with Farcaster identity.')
  if (newCred.signature) {
    console.log(`Saved to: ${credPath(agentName)}`)
  }
}

// ---------------------------------------------------------------------------
// Usage / dispatch
// ---------------------------------------------------------------------------

function printUsage() {
  console.log(`qz-agent — QueryZero Agent Credential CLI

Register your agent with QueryZero using wallet signing and obtain a BBS+
credential with ZK selective disclosure and holder binding.

Usage:
  qz-agent register <agentName>                  Register and receive credential
  qz-agent status <agentName>                     Display stored credential
  qz-agent proof <agentName> --indexes 1,2,3      Derive ZK proof for specified claims
  qz-agent schema                                 View agent identity schema
  qz-agent attest moltbook <agentName>             Start Moltbook attestation
  qz-agent attest moltbook-verify <agentName>      Verify Moltbook comment
  qz-agent attest farcaster <agentName>            Farcaster identity attestation

Register options:
  --operator <domain>          Operator domain (required)
  --moltbook-agent <username>  Moltbook username
  --payment-capable            Flag: agent accepts x402 payments
  --wallet-network <id>        Wallet network ID (default: eip155:8453)

Wallet options:
  --key <hex>                  Wallet private key (or set QZ_WALLET_KEY env var)

Global options:
  --url <url>                  QueryZero server URL (default: https://queryzero.net)
  --help                       Show this help

Credentials are stored locally in ~/.qz/credentials/agents/
Your holder secret never leaves this machine.

Examples:
  qz-agent register my-agent --operator example.com --key 0x...
  qz-agent status my-agent
  qz-agent proof my-agent --indexes 0,1,7
  qz-agent schema
  qz-agent attest farcaster my-agent
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
      const agentName = args[1]
      if (!agentName || agentName.startsWith('-')) die('agent name required: qz-agent register <agentName>')
      await registerCommand(agentName)
      break
    }
    case 'status': {
      const agentName = args[1]
      if (!agentName || agentName.startsWith('-')) die('agent name required: qz-agent status <agentName>')
      await statusCommand(agentName)
      break
    }
    case 'proof': {
      const agentName = args[1]
      if (!agentName || agentName.startsWith('-')) die('agent name required: qz-agent proof <agentName>')
      const indexes = getFlagValues('--indexes')
      await proofCommand(agentName, indexes)
      break
    }
    case 'schema': {
      await schemaCommand()
      break
    }
    case 'attest': {
      const subcommand = args[1]
      if (subcommand === 'moltbook') {
        const agentName = args[2]
        if (!agentName || agentName.startsWith('-')) die('agent name required: qz-agent attest moltbook <agentName>')
        await attestMoltbookCommand(agentName)
      } else if (subcommand === 'moltbook-verify') {
        const agentName = args[2]
        if (!agentName || agentName.startsWith('-')) die('agent name required: qz-agent attest moltbook-verify <agentName>')
        await attestMoltbookVerifyCommand(agentName)
      } else if (subcommand === 'farcaster') {
        const agentName = args[2]
        if (!agentName || agentName.startsWith('-')) die('agent name required: qz-agent attest farcaster <agentName>')
        await attestFarcasterCommand(agentName)
      } else {
        die(`unknown attest subcommand: ${subcommand}. Use: moltbook, moltbook-verify, farcaster`)
      }
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
