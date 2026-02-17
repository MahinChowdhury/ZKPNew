// ============================
// Linkable Ring Signature (LRS)
// Based on Liu-Wei-Wong scheme
// ============================

const crypto = require("crypto");
const EC = require("elliptic").ec;
const BN = require("bn.js");

const ec = new EC("secp256k1");

function keccak256(data) {
  if (data === undefined || data === null) {
    throw new Error("keccak256() received undefined data");
  }
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}

/**
 * Generate linkable ring signature
 * @param {BN} k - Signer's private key
 * @param {Array<Point>} ring - Array of public keys including signer's
 * @param {number} signerIndex - Index of signer in ring
 * @param {string} message - Message to sign (e.g., vote choice)
 * @returns {Object} signature { c0, s[], linkTag, startIndex }
 */
function sign(k, ring, signerIndex, message) {
  const n = ring.length;
  
  if (signerIndex < 0 || signerIndex >= n) {
    throw new Error("Invalid signer index");
  }

  console.log(`\n=== LRS SIGNING DEBUG ===`);
  console.log(`Ring size: ${n}, Signer index: ${signerIndex}`);
  console.log(`Message: ${message}`);

  // Verify signer's public key matches
  const expectedPk = ec.g.mul(k);
  const actualPk = ring[signerIndex];
  if (!expectedPk.eq(actualPk)) {
    console.error("ERROR: Signer's public key doesn't match k·G");
    throw new Error("Signer's public key mismatch");
  }
  
  // Link tag: I = k·H(P) - this makes the signature linkable
  // Note: H(P) is deterministic hash of the signer's public key
  const hP_signer = hashToPoint(ring[signerIndex]);
  const linkTag = hP_signer.mul(k);  // I = k·H(P)
  console.log(`Link tag: ${linkTag.getX().toString(16).slice(0, 16)}...`);
  
  // Arrays to store s values and challenges
  const s = new Array(n);
  const c = new Array(n);
  
  // Step 1: Generate random u for signer position
  const u = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
  if (u.isZero()) throw new Error("Invalid random nonce");
  console.log(`Random u: ${u.toString(16).slice(0, 16)}...`);
  
  // Step 2: Compute commitment at signer position
  const L_u = ec.g.mul(u);              // L = u·G
  const R_u = hP_signer.mul(u);         // R = u·H(P)
  
  console.log(`L_u: ${L_u.getX().toString(16).slice(0, 16)}...`);
  console.log(`R_u: ${R_u.getX().toString(16).slice(0, 16)}...`);
  
  // Step 3: Compute challenge at next position
  const startIndex = (signerIndex + 1) % n;
  c[startIndex] = hashChallenge(message, L_u, R_u, linkTag);
  
  console.log(`Starting challenge c[${startIndex}]: ${c[startIndex].toString(16).slice(0, 16)}...`);
  
  // Step 4: Generate random s and compute c for all positions from startIndex to signerIndex
  let currentIndex = startIndex;
  while (currentIndex !== signerIndex) {
    // Generate random s[i]
    s[currentIndex] = new BN(crypto.randomBytes(32)).umod(ec.curve.n);
    if (s[currentIndex].isZero()) s[currentIndex] = s[currentIndex].iaddn(1);
    
    // Compute L[i] = s[i]·G + c[i]·P[i]
    const L_i = ec.g.mul(s[currentIndex]).add(ring[currentIndex].mul(c[currentIndex]));
    
    // Compute R[i] = s[i]·H(P[i]) + c[i]·I  (where I is the link tag)
    const hP_i = hashToPoint(ring[currentIndex]);
    const R_i = hP_i.mul(s[currentIndex]).add(linkTag.mul(c[currentIndex]));
    
    // Compute next challenge
    const nextIndex = (currentIndex + 1) % n;
    c[nextIndex] = hashChallenge(message, L_i, R_i, linkTag);
    
    console.log(`Position ${currentIndex}: s=${s[currentIndex].toString(16).slice(0, 8)}... -> c[${nextIndex}]=${c[nextIndex].toString(16).slice(0, 8)}...`);
    
    currentIndex = nextIndex;
  }
  
  // Step 5: Compute s[signerIndex] to close the ring
  // We need: s[signerIndex]·G + c[signerIndex]·P[signerIndex] = L_u
  //     AND: s[signerIndex]·H(P) + c[signerIndex]·I = R_u
  // 
  // From the second equation: s[signerIndex]·H(P) + c[signerIndex]·k·H(P) = u·H(P)
  // Therefore: s[signerIndex] + c[signerIndex]·k = u
  // So: s[signerIndex] = u - c[signerIndex]·k (mod n)
  console.log(`\nClosing ring at position ${signerIndex}`);
  console.log(`c[${signerIndex}]: ${c[signerIndex].toString(16).slice(0, 16)}...`);
  s[signerIndex] = u.sub(c[signerIndex].mul(k)).umod(ec.curve.n);
  console.log(`s[${signerIndex}]: ${s[signerIndex].toString(16).slice(0, 16)}...`);
  
  // Step 6: Verify ring closes - compute what c[startIndex] should be
  const L_verify = ec.g.mul(s[signerIndex]).add(ring[signerIndex].mul(c[signerIndex]));
  const R_verify = hP_signer.mul(s[signerIndex]).add(linkTag.mul(c[signerIndex]));
  const c_computed = hashChallenge(message, L_verify, R_verify, linkTag);
  
  console.log(`Verification: computed c should equal c[${startIndex}]`);
  console.log(`c[${startIndex}]: ${c[startIndex].toString(16).slice(0, 16)}...`);
  console.log(`c_computed: ${c_computed.toString(16).slice(0, 16)}...`);
  console.log(`Match: ${c_computed.eq(c[startIndex])}`);
  
  if (!c_computed.eq(c[startIndex])) {
    console.error("\nDEBUG INFO:");
    console.error(`L_u (original): ${L_u.getX().toString(16).slice(0, 16)}...`);
    console.error(`L_verify (reconstructed): ${L_verify.getX().toString(16).slice(0, 16)}...`);
    console.error(`L match? ${L_u.eq(L_verify)}`);
    console.error(`R_u (original): ${R_u.getX().toString(16).slice(0, 16)}...`);
    console.error(`R_verify (reconstructed): ${R_verify.getX().toString(16).slice(0, 16)}...`);
    console.error(`R match? ${R_u.eq(R_verify)}`);
    
    // Additional debug
    console.error(`\nDetailed R computation check:`);
    const term1 = hP_signer.mul(s[signerIndex]);
    const term2 = linkTag.mul(c[signerIndex]);
    console.error(`s[${signerIndex}]·H(P): ${term1.getX().toString(16).slice(0, 16)}...`);
    console.error(`c[${signerIndex}]·I: ${term2.getX().toString(16).slice(0, 16)}...`);
    console.error(`Sum: ${term1.add(term2).getX().toString(16).slice(0, 16)}...`);
    console.error(`Expected u·H(P): ${R_u.getX().toString(16).slice(0, 16)}...`);
    
    throw new Error("Ring signature verification failed during signing");
  }
  
  console.log(`=== LRS SIGNING COMPLETE ===\n`);
  
  // Return signature with startIndex
  return {
    c0: c[startIndex].toString(16),  // Starting challenge
    s: s.map(si => si.toString(16)),
    linkTag: {
      x: linkTag.getX().toString(16),
      y: linkTag.getY().toString(16)
    },
    startIndex: startIndex,
    ringSize: n
  };
}

/**
 * Verify linkable ring signature
 * @param {Object} signature - { c0, s[], linkTag, startIndex }
 * @param {Array<Point>} ring - Array of public keys
 * @param {string} message - Message that was signed
 * @returns {boolean} true if signature is valid
 */
function verify(signature, ring, message) {
  try {
    const n = ring.length;
    
    console.log(`\n=== LRS VERIFICATION DEBUG ===`);
    console.log(`Ring size: ${n}`);
    console.log(`Message: ${message}`);
    
    if (signature.ringSize !== n) {
      console.error("Ring size mismatch");
      return false;
    }
    
    if (signature.s.length !== n) {
      console.error("Invalid s array length");
      return false;
    }
    
    // Reconstruct link tag
    const linkTag = ec.curve.point(
      new BN(signature.linkTag.x, 16),
      new BN(signature.linkTag.y, 16)
    );
    
    if (!linkTag.validate()) {
      console.error("Invalid link tag point");
      return false;
    }
    
    console.log(`Link tag: ${linkTag.getX().toString(16).slice(0, 16)}...`);
    
    // Get starting position
    const startIndex = signature.startIndex || 0;
    console.log(`c0 from signature: ${signature.c0.slice(0, 16)}...`);
    console.log(`Starting verification at position ${startIndex}`);
    
    // Reconstruct challenges starting from startIndex
    const c = new Array(n);
    c[startIndex] = new BN(signature.c0, 16);
    
    // Verify ring starting from startIndex, going full circle
    let currentIndex = startIndex;
    for (let count = 0; count < n; count++) {
      const s_i = new BN(signature.s[currentIndex], 16);
      const c_i = c[currentIndex];
      
      console.log(`\nPosition ${currentIndex}:`);
      console.log(`  s[${currentIndex}]: ${s_i.toString(16).slice(0, 8)}...`);
      console.log(`  c[${currentIndex}]: ${c_i.toString(16).slice(0, 8)}...`);
      
      // Compute L[i] = s[i]·G + c[i]·P[i]
      const L_i = ec.g.mul(s_i).add(ring[currentIndex].mul(c_i));
      
      // Compute R[i] = s[i]·H(P[i]) + c[i]·I (where I is link tag)
      const hP_i = hashToPoint(ring[currentIndex]);
      const R_i = hP_i.mul(s_i).add(linkTag.mul(c_i));
      
      console.log(`  L[${currentIndex}]: ${L_i.getX().toString(16).slice(0, 8)}...`);
      console.log(`  R[${currentIndex}]: ${R_i.getX().toString(16).slice(0, 8)}...`);
      
      // Compute next challenge
      const c_next = hashChallenge(message, L_i, R_i, linkTag);
      const nextIndex = (currentIndex + 1) % n;
      
      if (count === n - 1) {
        // Last iteration: verify ring closure (should return to startIndex)
        console.log(`\nRing closure check:`);
        console.log(`  Expected c[${startIndex}]: ${c[startIndex].toString(16).slice(0, 16)}...`);
        console.log(`  Computed c[${startIndex}]: ${c_next.toString(16).slice(0, 16)}...`);
        console.log(`  Match: ${c_next.eq(c[startIndex])}`);
        
        if (!c_next.eq(c[startIndex])) {
          console.error("Ring closure verification failed");
          console.log(`=== LRS VERIFICATION FAILED ===\n`);
          return false;
        }
      } else {
        c[nextIndex] = c_next;
        console.log(`  -> c[${nextIndex}]=${c_next.toString(16).slice(0, 8)}...`);
      }
      
      currentIndex = nextIndex;
    }
    
    console.log(`\n=== LRS VERIFICATION PASSED ===\n`);
    return true;
  } catch (err) {
    console.error("Verification error:", err);
    return false;
  }
}

/**
 * Hash public key to curve point (deterministic)
 * H(P) for computing R values
 */
function hashToPoint(P) {
  const px = P.getX().toString(16, 64);
  const py = P.getY().toString(16, 64);
  const hash = keccak256(px + py);
  
  // Use hash as scalar and multiply by generator
  let scalar = new BN(hash, 16).umod(ec.curve.n);
  if (scalar.isZero()) scalar = scalar.iaddn(1);
  
  return ec.g.mul(scalar);
}

/**
 * Hash challenge: H(m || L || R || I)
 * where I is the link tag
 */
function hashChallenge(message, L, R, I) {
  const lx = L.getX().toString(16, 64);
  const ly = L.getY().toString(16, 64);
  const rx = R.getX().toString(16, 64);
  const ry = R.getY().toString(16, 64);
  const ix = I.getX().toString(16, 64);
  const iy = I.getY().toString(16, 64);
  
  const combined = message + lx + ly + rx + ry + ix + iy;
  const hash = keccak256(combined);
  
  return new BN(hash, 16).umod(ec.curve.n);
}

/**
 * Check if two link tags are equal (for double-vote detection)
 */
function linkTagsEqual(tag1, tag2) {
  return tag1.x === tag2.x && tag1.y === tag2.y;
}

module.exports = {
  sign,
  verify,
  linkTagsEqual,
  hashToPoint,
  hashChallenge
};