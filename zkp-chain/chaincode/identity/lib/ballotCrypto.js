'use strict';

// ============================================================
// ballotCrypto.js — on-chain verification of encrypted ballots
//
// Verifier-side mirror of api-server/crypto/homomorphic.js. The hash
// encodings (Fiat–Shamir challenges, voteBinding, electionId) MUST stay
// byte-identical to the prover side or every vote will be rejected.
// ============================================================

const crypto = require('crypto');
const EC = require('elliptic').ec;
const BN = require('bn.js');

const ec = new EC('secp256k1');

function toPoint(xy) {
  if (!xy || typeof xy.x !== 'string' || typeof xy.y !== 'string') {
    throw new Error('malformed point');
  }
  const p = ec.curve.point(new BN(xy.x, 16), new BN(xy.y, 16));
  if (!p.validate()) throw new Error('point not on curve');
  return p;
}

function hashChallenge(tag, points, context) {
  const data = [tag, ...points.flatMap((p) => [p.getX().toString(16, 64), p.getY().toString(16, 64)]), context].join('|');
  const hash = crypto.createHash('sha256').update(data).digest('hex');
  return new BN(hash, 16).umod(ec.curve.n);
}

const optionContext = (ballotId, nullifier, j) => `${ballotId}|${nullifier}|opt${j}`;
const sumContext = (ballotId, nullifier) => `${ballotId}|${nullifier}|sum`;

// Disjunctive Chaum–Pedersen: ciphertext encrypts 0 or 1
function verifyValidVote(publicKey, c1, c2, proof, context) {
  const a1 = toPoint(proof.a1), b1 = toPoint(proof.b1);
  const a2 = toPoint(proof.a2), b2 = toPoint(proof.b2);
  const d1 = new BN(proof.d1, 16), d2 = new BN(proof.d2, 16);
  const r1 = new BN(proof.r1, 16), r2 = new BN(proof.r2, 16);

  const e = hashChallenge('bbzkv-sigma-or-v1', [publicKey, c1, c2, a1, b1, a2, b2], context);
  if (!e.eq(d1.add(d2).umod(ec.curve.n))) return false;

  // branch v = 0
  if (!a1.eq(ec.g.mul(r1).add(c1.mul(d1)))) return false;
  if (!b1.eq(publicKey.mul(r1).add(c2.mul(d1)))) return false;
  // branch v = 1
  if (!a2.eq(ec.g.mul(r2).add(c1.mul(d2)))) return false;
  if (!b2.eq(publicKey.mul(r2).add(c2.add(ec.g.neg()).mul(d2)))) return false;
  return true;
}

// Chaum–Pedersen: Σ ciphertexts encrypts exactly 1
function verifySumIsOne(publicKey, C1, C2, proof, context) {
  const A = toPoint(proof.A), B = toPoint(proof.B);
  const z = new BN(proof.z, 16);
  const e = hashChallenge('bbzkv-sum-one-v1', [publicKey, C1, C2, A, B], context);
  return ec.g.mul(z).eq(A.add(C1.mul(e))) &&
         publicKey.mul(z).eq(B.add(C2.add(ec.g.neg()).mul(e)));
}

/**
 * Verify a full encrypted ballot { ciphertexts: [...], sumProof }.
 * Throws with a specific reason on any failure.
 */
function verifyEncryptedBallot(publicKeyXY, numOptions, ballot, ballotId, nullifier) {
  if (!ballot || !Array.isArray(ballot.ciphertexts) || !ballot.sumProof) {
    throw new Error('Encrypted ballot missing or malformed');
  }
  if (ballot.ciphertexts.length !== numOptions) {
    throw new Error(`Encrypted ballot has ${ballot.ciphertexts.length} entries, ballot has ${numOptions} options`);
  }
  const pk = toPoint(publicKeyXY);
  let C1 = null, C2 = null;
  ballot.ciphertexts.forEach((ct, j) => {
    const c1 = toPoint(ct.c1), c2 = toPoint(ct.c2);
    if (!ct.validityProof || !verifyValidVote(pk, c1, c2, ct.validityProof, optionContext(ballotId, nullifier, j))) {
      throw new Error(`Validity proof failed for option ${j}`);
    }
    C1 = C1 ? C1.add(c1) : c1;
    C2 = C2 ? C2.add(c2) : c2;
  });
  if (!verifySumIsOne(pk, C1, C2, ballot.sumProof, sumContext(ballotId, nullifier))) {
    throw new Error('Sum proof failed — ballot does not encrypt exactly one choice');
  }
}

function computeVoteBinding(ballotId, ballot) {
  const cts = ballot.ciphertexts
    .map((c) => [c.c1.x, c.c1.y, c.c2.x, c.c2.y].join(':'))
    .join(',');
  const hex = crypto.createHash('sha256')
    .update(`bbzkv-vote-binding-v1|${ballotId}|${cts}`)
    .digest('hex');
  return BigInt('0x' + hex.slice(0, 62));
}

// Mirrors api-server/routes/vote.js: first 128 bits of SHA256(ballotId)
function electionIdFor(ballotId) {
  const hex = crypto.createHash('sha256').update(String(ballotId)).digest('hex');
  return BigInt('0x' + hex.slice(0, 32));
}

// NID binding of an attested enrollment (enroll_auth.circom): first 248
// bits of SHA256(nidHash). Mirrors voterClient.nidFieldFor.
function nidFieldFor(nidHash) {
  const hex = crypto.createHash('sha256').update(String(nidHash)).digest('hex');
  return BigInt('0x' + hex.slice(0, 62));
}

module.exports = { verifyEncryptedBallot, computeVoteBinding, electionIdFor, nidFieldFor };
