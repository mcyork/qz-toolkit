#!/usr/bin/env bun
/**
 * serve.ts — Serve your QueryZero service credential as a ZK proof
 *
 * Loads your credential from ~/.qz/credentials/services/<domain>.json,
 * generates a BBS+ ZK proof disclosing selected claims, and serves it
 * as an X-Service-Credential header on every HTTP response.
 *
 * The proof is cached and regenerated every hour. Your holder secret
 * never leaves this process — only the ZK proof is exposed.
 *
 * Usage:
 *   bun run serve.ts <domain>
 *   bun run serve.ts invoices.org
 *   bun run serve.ts invoices.org --port 3000
 *   bun run serve.ts invoices.org --indexes 0,1,5,7
 *   bun run serve.ts invoices.org --credential ./my-credential.json
 */

import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { homedir } from 'os'

// ── Args ────────────────────────────────────────────────────────────

const args = process.argv.slice(2)
const domain = args.find(a => !a.startsWith('-'))

function getFlag(name: string, fallback: string): string {
  const idx = args.indexOf(name)
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1]
  return fallback
}

if (!domain) {
  console.error('Usage: bun run serve.ts <domain> [--port 3000] [--indexes 0,1,2,5,7] [--credential path]')
  console.error('')
  console.error('Serves your QZ service credential as a ZK proof in HTTP headers.')
  console.error('')
  console.error('Options:')
  console.error('  --port <n>           Port to listen on (default: 3000)')
  console.error('  --indexes <list>     Comma-separated claim indexes to disclose (default: 0,1,2,5,7,10,13)')
  console.error('  --credential <path>  Path to credential JSON (default: ~/.qz/credentials/services/<domain>.json)')
  console.error('')
  console.error('Example:')
  console.error('  bun run serve.ts invoices.org')
  console.error('  bun run serve.ts myservice.com --port 8080 --indexes 0,1,7')
  process.exit(1)
}

const PORT = Number(getFlag('--port', '3000'))
const CREDENTIAL_PATH = getFlag('--credential',
  join(homedir(), '.qz', 'credentials', 'services', `${domain}.json`)
)
const DISCLOSED_INDEXES = getFlag('--indexes', '0,1,2,5,7,10,13')
  .split(',').map(Number)

// ── BBS+ Blind Module Loading ───────────────────────────────────────

const CIPHERSUITE = 'BLS12-381-SHA-256'

let _blindModules: any = null
async function getBlindModules() {
  if (_blindModules) return _blindModules
  const blindIface = await import(
    /* @vite-ignore */ './node_modules/@digitalbazaar/bbs-signatures/lib/bbs/blind/interface.js'
  )
  const ciphersuites = await import(
    /* @vite-ignore */ './node_modules/@digitalbazaar/bbs-signatures/lib/bbs/ciphersuites.js'
  )
  _blindModules = {
    BlindProofGen: blindIface.BlindProofGen,
    resolvedCiphersuite: ciphersuites.getCiphersuite(CIPHERSUITE),
  }
  return _blindModules
}

// ── Credential Loading ──────────────────────────────────────────────

function loadCredential() {
  if (!existsSync(CREDENTIAL_PATH)) {
    console.error(`No credential found at: ${CREDENTIAL_PATH}`)
    console.error('')
    console.error('Register first:')
    console.error(`  qz-service register ${domain} --category <category>`)
    console.error(`  qz-service verify ${domain}`)
    process.exit(1)
  }
  return JSON.parse(readFileSync(CREDENTIAL_PATH, 'utf-8'))
}

// ── Proof Generation ────────────────────────────────────────────────

const CACHE_TTL_MS = 60 * 60 * 1000 // 1 hour
let cachedProofHeader: string | null = null
let cachedAt = 0

async function generateProof(cred: any): Promise<string> {
  const { BlindProofGen, resolvedCiphersuite } = await getBlindModules()

  const header = new Uint8Array(Buffer.from(cred.header, 'base64'))
  const signature = new Uint8Array(Buffer.from(cred.signature, 'base64'))
  const publicKey = new Uint8Array(Buffer.from(cred.publicKey, 'base64'))
  const messages = (cred.messages as string[]).map(
    (m: string) => new TextEncoder().encode(m),
  )
  const secretProverBlind = BigInt('0x' + cred.secretProverBlind)
  const holderSecret = new Uint8Array(Buffer.from(cred.holderSecret, 'base64'))

  // Validate indexes
  for (const i of DISCLOSED_INDEXES) {
    if (i < 0 || i >= messages.length) {
      console.error(`Index ${i} out of range (0-${messages.length - 1})`)
      process.exit(1)
    }
  }

  const proof = await BlindProofGen({
    PK: publicKey,
    signature,
    header,
    ph: new Uint8Array(),
    messages,
    disclosed_indexes: DISCLOSED_INDEXES,
    committed_messages: [holderSecret],
    disclosed_commitment_indexes: [],
    secret_prover_blind: secretProverBlind,
    signer_blind: 0n,
    ciphersuite: resolvedCiphersuite,
  })

  const proofBundle = {
    type: cred.type,
    schema: cred.schema,
    header: cred.header,
    proof: Buffer.from(proof).toString('base64'),
    publicKey: cred.publicKey,
    ciphersuite: CIPHERSUITE,
    disclosedIndexes: DISCLOSED_INDEXES,
    disclosedMessages: Object.fromEntries(
      DISCLOSED_INDEXES.map((i: number) => [i, cred.messages[i]]),
    ),
    totalMessages: cred.messageCount,
    blind: true,
  }

  return btoa(JSON.stringify(proofBundle))
}

async function getProofHeader(cred: any): Promise<string> {
  const now = Date.now()
  if (cachedProofHeader && (now - cachedAt) < CACHE_TTL_MS) {
    return cachedProofHeader
  }
  cachedProofHeader = await generateProof(cred)
  cachedAt = now
  return cachedProofHeader
}

// ── HTTP Server ─────────────────────────────────────────────────────

const cred = loadCredential()
console.log(`Loaded credential for: ${domain}`)
console.log(`  Type:      ${cred.type}`)
console.log(`  Issued:    ${cred.issuedAt}`)
console.log(`  Expires:   ${cred.expiresAt}`)
console.log(`  Blind:     ${cred.blind}`)
console.log(`  Disclosing indexes: [${DISCLOSED_INDEXES.join(', ')}]`)
console.log('')

// Eagerly generate proof
console.log('Generating ZK proof...')
const initialProof = await getProofHeader(cred)
console.log('Proof ready.')
console.log('')

// Print disclosed claims
const bundle = JSON.parse(atob(initialProof))
console.log('Disclosed claims:')
for (const [idx, msg] of Object.entries(bundle.disclosedMessages)) {
  console.log(`  [${idx}] ${msg}`)
}
console.log('')

export default {
  port: PORT,
  fetch: async () => {
    const proofHeader = await getProofHeader(cred)

    return new Response(JSON.stringify({
      service: domain,
      credential: cred.type,
      proof: 'See X-Service-Credential header',
      verify: `bun run verify.ts http://localhost:${PORT}`,
    }, null, 2), {
      headers: {
        'Content-Type': 'application/json',
        'X-Service-Credential': proofHeader,
      },
    })
  },
}

console.log(`Serving on http://localhost:${PORT}`)
console.log(`Verify with: bun run verify.ts http://localhost:${PORT}`)
