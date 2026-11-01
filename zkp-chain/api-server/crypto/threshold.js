// ============================
// Threshold ElGamal — trustee side
// Scheme and verifier: chaincode/identity/lib/tallyCrypto.js (imported, so
// prover and verifier share every encoding). In deployment each trustee runs
// this on its own machine and keeps x_j to itself; the prototype runs the n
// trustees in one process (routes/tally.js).
// ============================

const crypto = require("crypto");
const tc = require("../../chaincode/identity/lib/tallyCrypto");

// Use tallyCrypto's own elliptic/bn.js: points and scalars from two copies of
// these libraries cannot be mixed. Callers pass points in serialized {x, y} form.
const { ec, BN, N } = tc;

function randScalar() {
  for (;;) {
    const k = new BN(crypto.randomBytes(32)).umod(N);
    if (!k.isZero()) return k;
  }
}

function evalPoly(coeffs, x) {
  const X = new BN(x);
  let acc = new BN(0);
  for (let k = coeffs.length - 1; k >= 0; k--) acc = acc.mul(X).add(coeffs[k]).umod(N);
  return acc;
}

class Trustee {
  constructor(index) {
    this.index = index;           // 1..n
    this.signKey = ec.genKeyPair();
    this.received = {};           // dealer -> share f_dealer(index)
    this.x = null;                // decryption key share, after finalize
  }

  get publicKey() {
    return this.signKey.getPublic(false, "hex");
  }

  sign(tag, obj) {
    const s = this.signKey.sign(tc.signedPayload(tag, obj));
    return JSON.stringify({ r: s.r.toString(16), s: s.s.toString(16) });
  }

  /** Random degree-(t-1) polynomial: public commitments, private shares f(1..n). */
  deal(ballotId, t, n) {
    const coeffs = Array.from({ length: t }, randScalar);
    const commitments = coeffs.map((a) => tc.ser(ec.g.mul(a)));
    const shares = {};
    for (let j = 1; j <= n; j++) shares[j] = evalPoly(coeffs, j).toString(16);
    return { commitments, shares, sig: this.sign("bbzkv-dealing-v1", { ballotId, dealer: this.index, commitments }) };
  }

  /** Check a share against the dealer's commitments; a signed complaint if it fails. */
  receive(ballotId, dealer, commitments, share) {
    if (tc.verifyShare(commitments, this.index, share)) {
      this.received[dealer] = new BN(share, 16);
      return null;
    }
    return {
      complainer: this.index, dealer, share,
      sig: this.sign("bbzkv-complaint-v1", { ballotId, complainer: this.index, dealer, share }),
    };
  }

  /** x_j = Σ_{i∈QUAL} f_i(j), once the chaincode has fixed QUAL. */
  finalize(qual) {
    this.x = qual.reduce((acc, i) => acc.add(this.received[i]), new BN(0)).umod(N);
  }

  /** D_j = x_j·c1 with a Chaum–Pedersen proof that log_G h_j = log_{c1} D_j. c1 as {x, y}. */
  partialDecrypt(ballotId, option, c1xy) {
    const c1 = tc.toPoint(c1xy);
    const hj = ec.g.mul(this.x);
    const D = c1.mul(this.x);
    const w = randScalar();
    const A = ec.g.mul(w);
    const B = c1.mul(w);
    const e = tc.hashChallenge("bbzkv-partial-decrypt-v1", [hj, c1, D, A, B],
      tc.partialContext(ballotId, option, this.index));
    return {
      trustee: this.index,
      D: tc.ser(D),
      proof: { A: tc.ser(A), B: tc.ser(B), z: w.add(e.mul(this.x)).umod(N).toString(16) },
    };
  }
}

/** Per-option ciphertext sums ({c1, c2} tallyCrypto points) over serialized ballots. */
function aggregate(encryptedBallots, numOptions) {
  const sums = Array.from({ length: numOptions }, () => null);
  for (const enc of encryptedBallots) {
    enc.ciphertexts.forEach((ct, j) => {
      const c1 = tc.toPoint(ct.c1), c2 = tc.toPoint(ct.c2);
      sums[j] = sums[j] ? { c1: sums[j].c1.add(c1), c2: sums[j].c2.add(c2) } : { c1, c2 };
    });
  }
  return sums;
}

/** Baby-step giant-step for M = T·G, T in [0, max]: O(sqrt(max)) group operations. */
function discreteLog(M, max) {
  if (M.isInfinity()) return 0;
  const key = (P) => (P.isInfinity() ? "inf" : P.getX().toString(16) + ":" + P.getY().toString(16));
  const m = Math.ceil(Math.sqrt(max + 1));
  const baby = new Map();
  let P = ec.curve.point(null, null);
  for (let j = 0; j < m; j++) {
    baby.set(key(P), j);
    P = P.add(ec.g);
  }
  const giant = ec.g.mul(new BN(m)).neg();
  let Q = M;
  for (let i = 0; i <= m; i++) {
    const j = baby.get(key(Q));
    if (j !== undefined && i * m + j <= max) return i * m + j;
    Q = Q.add(giant);
  }
  throw new Error("aggregate does not decrypt to a count in range");
}

/**
 * Decrypt every option's sum with the given trustees (any t of QUAL) and
 * return the tally to publish: { options: [{ total, partials }] }.
 */
function decryptTally(ballotId, sums, trustees, maxTotal) {
  return {
    options: sums.map((sum, j) => {
      if (!sum) return { total: 0, partials: [] };
      const partials = trustees.map((t) => t.partialDecrypt(ballotId, j, tc.ser(sum.c1)));
      const M = sum.c2.add(tc.combinePartials(partials).neg());
      return { total: discreteLog(M, maxTotal), partials };
    }),
  };
}

module.exports = { Trustee, evalPoly, randScalar, aggregate, discreteLog, decryptTally, tc };
