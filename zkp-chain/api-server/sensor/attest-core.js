// ============================================================
// attest-core.js — capture-device attestation (FINDINGS C6)
//
// A capture device (camera / kiosk) holds an EdDSA-BabyJubJub key that
// the RA registers on-chain. For each live capture it signs
//   Poseidon(templateDigest(live), electionId, sessionCommit)
// where sessionCommit = Poseidon(nullifier, nonce) is a hiding commitment
// supplied by the voter's client. The voting circuit verifies the
// signature and the key's registry membership in-circuit.
//
// Shared by sensor/attestor.js (the device service) and the tests.
// ============================================================

const path = require("path");
const crypto = require("crypto");
const { buildEddsa } = require("circomlibjs");

const VOTER_CLIENT = path.join(__dirname, "..", "..", "frontend", "src", "crypto", "voterClient.js");

let _eddsa, _client;
async function deps() {
  if (!_eddsa) _eddsa = await buildEddsa();
  if (!_client) _client = await import(VOTER_CLIENT);
  return { eddsa: _eddsa, F: _eddsa.babyJub.F, client: _client };
}

/**
 * @param {string} [privateKeyHex] 32-byte hex seed; random if omitted
 * @returns {{ privateKeyHex, publicKey: {ax, ay}, sign(msg: bigint) => {R8x, R8y, S} }}
 */
async function loadSigner(privateKeyHex) {
  const { eddsa, F } = await deps();
  const prv = Buffer.from(privateKeyHex || crypto.randomBytes(32).toString("hex"), "hex");
  const pub = eddsa.prv2pub(prv);
  return {
    privateKeyHex: prv.toString("hex"),
    publicKey: { ax: F.toObject(pub[0]).toString(), ay: F.toObject(pub[1]).toString() },
    sign(msg) {
      const sig = eddsa.signPoseidon(prv, F.e(BigInt(msg)));
      return { R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(), S: sig.S.toString() };
    },
  };
}

/**
 * Attest a live reading.
 *   mode           "face" | "iris"
 *   reading        raw biometric-service output (face: number[128]; iris: {irisCode, noiseMask})
 *   electionId     decimal string (public, from the on-chain ballot)
 *   sessionCommit  decimal string from voterClient.startVoteSession()
 * Returns the circuit-encoded template the device actually signed, so the
 * client proves over exactly that sample.
 */
async function attest(signer, { mode, reading, electionId, sessionCommit }) {
  const { client } = await deps();
  const template = client.toTemplate(mode, reading);
  const digest = await client.templateDigest(mode, template);
  const msg = await client.attestationMessage(digest, BigInt(electionId), BigInt(sessionCommit));
  return {
    template: template.map(String),
    sensorPublicKey: signer.publicKey,
    signature: signer.sign(msg),
    // No presentation-attack detection model is deployed in this prototype
    // (FINDINGS C25). A production device must run PAD before signing.
    pad: "not-performed",
  };
}

module.exports = { loadSigner, attest };
