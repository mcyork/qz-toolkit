#!/usr/bin/env bun
/**
 * verify.ts — Verify a QueryZero service credential proof
 *
 * Fetches the X-Service-Credential header from a URL and cryptographically
 * verifies the BBS+ ZK proof. Prints the disclosed claims and verification result.
 *
 * Usage:
 *   bun run verify.ts <url>
 *   bun run verify.ts http://localhost:3000
 *   bun run verify.ts https://invoices.org
 *
 *   # Or verify a base64 proof directly:
 *   bun run verify.ts --proof <base64-proof>
 *   echo <base64-proof> | bun run verify.ts --stdin
 */

// ── Args ────────────────────────────────────────────────────────────

const args = process.argv.slice(2)

function getFlag(name: string): string {
  const idx = args.indexOf(name)
  if (idx !== -1 && idx + 1 < args.length) return args[idx + 1]
  return ''
}

const url = args.find(a => !a.startsWith('-'))
const proofArg = getFlag('--proof')
const useStdin = args.includes('--stdin')

if (!url && !proofArg && !useStdin) {
  console.error('Usage: bun run verify.ts <url>')
  console.error('       bun run verify.ts --proof <base64-proof>')
  console.error('       echo <proof> | bun run verify.ts --stdin')
  console.error('')
  console.error('Fetches and verifies a QueryZero service credential proof.')
  console.error('')
  console.error('Examples:')
  console.error('  bun run verify.ts http://localhost:3000')
  console.error('  bun run verify.ts https://invoices.org')
  process.exit(1)
}

// ── Get Proof ───────────────────────────────────────────────────────

let proofB64: string

if (proofArg) {
  proofB64 = proofArg
} else if (useStdin) {
  proofB64 = (await Bun.stdin.text()).trim()
} else {
  console.log(`Fetching ${url}...`)
  const res = await fetch(url!)
  const header = res.headers.get('x-service-credential')
  if (!header) {
    console.error(`No X-Service-Credential header found in response from ${url}`)
    console.error('')
    console.error('Response headers:')
    res.headers.forEach((v, k) => console.error(`  ${k}: ${v.slice(0, 80)}${v.length > 80 ? '...' : ''}`))
    process.exit(1)
  }
  proofB64 = header
  console.log(`Got proof from ${url} (${proofB64.length} bytes)`)
  console.log('')
}

// ── Parse Proof Bundle ──────────────────────────────────────────────

let bundle: any
try {
  bundle = JSON.parse(atob(proofB64))
} catch {
  console.error('Failed to decode proof. Expected base64-encoded JSON.')
  process.exit(1)
}

console.log('=== Proof Bundle ===')
console.log(`  Type:        ${bundle.type}`)
console.log(`  Schema:      ${bundle.schema}`)
console.log(`  Ciphersuite: ${bundle.ciphersuite}`)
console.log(`  Total msgs:  ${bundle.totalMessages}`)
console.log(`  Disclosed:   ${bundle.disclosedIndexes.length} of ${bundle.totalMessages}`)
console.log(`  Blind:       ${bundle.blind}`)
console.log('')

console.log('=== Disclosed Claims ===')
for (const [idx, msg] of Object.entries(bundle.disclosedMessages) as [string, string][]) {
  const [key, value] = msg.split('=', 2)
  console.log(`  [${idx.padStart(2)}] ${key} = ${value}`)
}
console.log('')

// ── Cryptographic Verification ──────────────────────────────────────

console.log('=== Verification ===')
console.log('  Loading BBS+ ciphersuite...')

const ciphersuites = await import(
  /* @vite-ignore */ './node_modules/@digitalbazaar/bbs-signatures/lib/bbs/ciphersuites.js'
)
const blindIface = await import(
  /* @vite-ignore */ './node_modules/@digitalbazaar/bbs-signatures/lib/bbs/blind/interface.js'
)
const cs = ciphersuites.getCiphersuite('BLS12-381-SHA-256')

const proof = new Uint8Array(Buffer.from(bundle.proof, 'base64'))
const header = new Uint8Array(Buffer.from(bundle.header, 'base64'))
const publicKey = new Uint8Array(Buffer.from(bundle.publicKey, 'base64'))
const messages = bundle.disclosedIndexes.map(
  (i: number) => new TextEncoder().encode(bundle.disclosedMessages[String(i)])
)

try {
  const valid = await blindIface.BlindProofVerify({
    PK: publicKey,
    proof,
    header,
    ph: new Uint8Array(),
    L: bundle.totalMessages,
    disclosed_messages: messages,
    disclosed_indexes: bundle.disclosedIndexes,
    disclosed_committed_messages: [],
    disclosed_committed_indexes: [],
    ciphersuite: cs,
  })

  if (valid) {
    console.log('  Result:      ✓ VALID')
    console.log('')
    console.log('  The proof cryptographically confirms:')
    console.log(`  • Credential was issued by the holder of the public key`)
    console.log(`  • Disclosed claims have not been tampered with`)
    console.log(`  • ${bundle.totalMessages - bundle.disclosedIndexes.length} claims remain hidden (zero-knowledge)`)
  } else {
    console.log('  Result:      ✗ INVALID')
    console.log('  The proof failed verification. It may be corrupted or forged.')
  }
} catch (err: any) {
  console.error(`  Result:      ✗ ERROR`)
  console.error(`  ${err.message}`)
}

// ── Credential Header Decode ────────────────────────────────────────

console.log('')
console.log('=== Credential Metadata ===')
try {
  const credHeader = JSON.parse(atob(bundle.header))
  console.log(`  ID:          ${credHeader.id}`)
  console.log(`  Issuer:      ${credHeader.issuer}`)
  console.log(`  Type:        ${credHeader.type}`)
  console.log(`  Issued:      ${credHeader.issuanceDate}`)
  console.log(`  Expires:     ${credHeader.expirationDate}`)
  console.log(`  Schema:      ${credHeader.schema}`)
} catch {
  console.log('  (could not decode header)')
}
