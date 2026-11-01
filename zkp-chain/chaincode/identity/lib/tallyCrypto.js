'use strict';

// ============================================================
// tallyCrypto.js — threshold ElGamal for the tally (verifier side)
//
// Key generation is Pedersen's joint-Feldman DKG among n trustees: trustee i
// publishes Feldman commitments A_ik = a_ik·G to a random degree-(t-1)
// polynomial f_i and privately sends f_i(j) to trustee j. The election key is
// h = Σ_{i∈QUAL} A_i0 and trustee j's verification key is
// h_j = Σ_{i∈QUAL} Σ_k j^k A_ik, both computable from public data, so no
// single party ever chooses or knows the decryption key.
//
// Decryption: trustee j publishes D_j = x_j·c1 with a Chaum–Pedersen proof
// that log_G h_j = log_{c1} D_j; any t valid shares give x·c1 by Lagrange
// interpolation in the exponent.
//
// Trustees authenticate dealings and complaints with a secp256k1 ECDSA key
// declared when the ballot is registered.
//
// The API server's trustee code (api-server/crypto/threshold.js) imports this
// file, so prover and verifier share one implementation of every encoding.
// ============================================================

const crypto = require('crypto');
const EC = require('elliptic').ec;
const BN = require('bn.js');

const ec = new EC('secp256k1');
const N = ec.curve.n;
const MAX_TRUSTEES = 32;

function toPoint(xy) {
  if (!xy || typeof xy.x !== 'string' || typeof xy.y !== 'string') {
    throw new Error('malformed point');
  }
  const p = ec.curve.point(new BN(xy.x, 16), new BN(xy.y, 16));
  if (!p.validate()) throw new Error('point not on curve');
  return p;
}

const ser = (P) => ({ x: P.getX().toString(16), y: P.getY().toString(16) });

function hashChallenge(tag, points, context) {
  const data = [tag, ...points.flatMap((p) => [p.getX().toString(16, 64), p.getY().toString(16, 64)]), context].join('|');
  return new BN(crypto.createHash('sha256').update(data).digest('hex'), 16).umod(N);
}

// Σ_k j^k A_k for one dealer's commitments
function commitmentAt(commitments, j) {
  const J = new BN(j);
  let pow = new BN(1);
  let acc = null;
  for (const A of commitments) {
    const term = toPoint(A).mul(pow);
    acc = acc ? acc.add(term) : term;
    pow = pow.mul(J).umod(N);
  }
  return acc;
}

/** A share f_i(j) is consistent with dealer i's commitments. */
function verifyShare(commitments, j, shareHex) {
  return ec.g.mul(new BN(shareHex, 16)).eq(commitmentAt(commitments, j));
}

/** Election public key h = Σ_{i∈QUAL} A_i0. */
function electionKey(qualDealings) {
  return qualDealings.map((d) => toPoint(d.commitments[0])).reduce((a, b) => a.add(b));
}

/** Trustee j's verification key h_j = Σ_{i∈QUAL} Σ_k j^k A_ik. */
function trusteeKey(qualDealings, j) {
  return qualDealings.map((d) => commitmentAt(d.commitments, j)).reduce((a, b) => a.add(b));
}

// ---- trustee signatures (dealings, complaints) ----
// Digest as hex; signatures travel as JSON {r, s} (hex scalars).
const signedPayload = (tag, obj) => crypto.createHash('sha256').update(`${tag}|${JSON.stringify(obj)}`).digest('hex');

function verifyTrusteeSig(pubHex, tag, obj, sig) {
  try {
    const { r, s } = typeof sig === 'string' ? JSON.parse(sig) : sig;
    return ec.keyFromPublic(pubHex, 'hex').verify(signedPayload(tag, obj), { r, s });
  } catch (e) {
    return false;
  }
}

// ---- partial decryptions ----
const partialContext = (ballotId, option, j) => `${ballotId}|${option}|trustee${j}`;

function verifyPartial(hj, c1, partial, context) {
  const D = toPoint(partial.D);
  const A = toPoint(partial.proof.A);
  const B = toPoint(partial.proof.B);
  const z = new BN(partial.proof.z, 16);
  const e = hashChallenge('bbzkv-partial-decrypt-v1', [hj, c1, D, A, B], context);
  return ec.g.mul(z).eq(A.add(hj.mul(e))) && c1.mul(z).eq(B.add(D.mul(e)));
}

/** Lagrange coefficient λ_j for interpolation at 0 over the index set S. */
function lagrange(j, S) {
  let num = new BN(1);
  let den = new BN(1);
  for (const m of S) {
    if (m === j) continue;
    num = num.mul(new BN(m)).umod(N);
    den = den.mul(new BN(m - j).umod(N)).umod(N);
  }
  return num.mul(den.invm(N)).umod(N);
}

/** x·c1 from t partials {trustee j: D_j}. */
function combinePartials(partials) {
  const S = partials.map((p) => p.trustee);
  return partials
    .map((p) => toPoint(p.D).mul(lagrange(p.trustee, S)))
    .reduce((a, b) => a.add(b));
}

const totalPoint = (total) => (total === 0 ? ec.curve.point(null, null) : ec.g.mul(new BN(total)));

/**
 * Verify one option's published total: every partial comes from a distinct
 * trustee index in 1..n and carries a valid proof, there are at least t of
 * them, and c2 - Σ λ_j D_j = total·G. Throws with the reason on failure.
 */
function verifyOptionTally(key, aggregate, option, ballotId, entry) {
  const { threshold, qualDealings, trustees } = key;
  if (!Number.isInteger(entry.total) || entry.total < 0) throw new Error(`Option ${option}: invalid total`);
  const partials = entry.partials || [];
  const seen = new Set();
  for (const p of partials) {
    if (!Number.isInteger(p.trustee) || p.trustee < 1 || p.trustee > trustees || seen.has(p.trustee)) {
      throw new Error(`Option ${option}: invalid or repeated trustee index`);
    }
    seen.add(p.trustee);
    const hj = trusteeKey(qualDealings, p.trustee);
    if (!verifyPartial(hj, aggregate.c1, p, partialContext(ballotId, option, p.trustee))) {
      throw new Error(`Option ${option}: partial decryption of trustee ${p.trustee} is invalid`);
    }
  }
  if (partials.length < threshold) {
    throw new Error(`Option ${option}: ${partials.length} partial decryptions, threshold is ${threshold}`);
  }
  const M = aggregate.c2.add(combinePartials(partials).neg());
  if (!M.eq(totalPoint(entry.total))) {
    throw new Error(`Option ${option}: published total does not match the decryption`);
  }
}

module.exports = {
  ec, BN, N, MAX_TRUSTEES, toPoint, ser, hashChallenge,
  commitmentAt, verifyShare, electionKey, trusteeKey,
  signedPayload, verifyTrusteeSig,
  partialContext, verifyPartial, lagrange, combinePartials, totalPoint, verifyOptionTally,
};
