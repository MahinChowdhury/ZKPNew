# Q1 Journal Publishability Assessment

## ZKP-Based Decentralised Voting System Using Face Biometrics

---

## Verdict: ⚠️ Publishable with Improvements (Currently Q2–Q3 Level; Q1 Achievable)

Your work has **genuine novelty** in the integration layer — no existing published system combines FaceNet-derived ECC keys + Linkable Ring Signatures + Exponential ElGamal + Hyperledger Fabric in a single architecture. The implementation is functional and well-documented. However, there are **critical gaps** that would cause Q1 reviewers to reject as-is.

---

## ✅ What's Strong (Keep These)

| Strength | Detail |
|---|---|
| **Novel integration** | No existing paper combines face-biometric key derivation + LRS + homomorphic tallying + permissioned blockchain |
| **Working prototype** | Full implementation across 3 tiers (Python model, Node.js API, Fabric chaincode) - far stronger than theoretical-only papers |
| **Benchmark suite** | [lrs_benchmark.js](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/lrs_benchmark.js) with 5 measurement categories, 30 iterations per ring size, proper statistical reporting (mean, SD, P95, P99) |
| **Comprehensive lit review** | 10+ systems analyzed with specific limitations identified per system |
| **Formal proofs** | Theorems 5.1 (revote prevention) and 5.2 (privacy of link tags) with proof sketches |
| **Security analysis** | Threat model table + formal security reductions to ECDLP/DDH |
| **Vote validity ZKP** | Disjunctive Chaum-Pedersen implementation in [homomorphic.js](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js) — addresses a gap most competitors miss |

---

## 🚨 Critical Issues (Must Fix for Q1)

### 1. The [keccak256](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/server.js#43-49) Function Is Actually SHA-256

```javascript
// server.js line 43-48, lrs.js line 12-17, vote.js line 17-22
function keccak256(data) {
  return crypto.createHash("sha256").update(String(data)).digest("hex");
}
```

> [!CAUTION]
> You name it [keccak256](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/server.js#43-49) but use `sha256`. This is **factual misrepresentation** in a cryptography paper. A reviewer will immediately flag this and question the rigor of the entire work. Either rename the function to `sha256Hash` or actually use Keccak-256 (e.g., via [keccak256](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/server.js#43-49) npm package or `ethers.js`). This is duplicated in **3 files**.

### 2. [hashToPoint](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/lrs.js#254-269) Is Not a Proper Hash-to-Curve

```javascript
// lrs.js line 258-268
function hashToPoint(P) {
  const hash = keccak256(px + py);
  let scalar = new BN(hash, 16).umod(ec.curve.n);
  return ec.g.mul(scalar);  // ← This is NOT hash-to-curve
}
```

> [!WARNING]
> The [H(P) = hash · G](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/chaincode/identity/lib/identityContract.js#214-249) construction means a party who knows [hash](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js#303-325) can compute the discrete log of [H(P)](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/chaincode/identity/lib/identityContract.js#214-249) w.r.t. `G`. This is **not** a secure hash-to-curve — it leaks the DL relationship. For LRS security (Liu-Wei-Wong), `H_p(P)` must produce a point whose DL w.r.t. `G` is unknown. Use a proper hash-to-curve algorithm (RFC 9380, or the `hash_to_field → map_to_curve` approach). This is a **potential security vulnerability** in the LRS construction that a Q1 reviewer will catch.

### 3. `voteChoice` Is Stored in Plaintext on-Chain

```javascript
// identityContract.js line 378-387
const vote = {
  voteId,
  voteChoice,        // ← PLAINTEXT candidate name!
  signature,
  encryptedVote,     // ← Also encrypted version exists
  ...
};
```

> [!CAUTION]
> You have homomorphic encryption for the vote, but you **also** store `voteChoice` as a plaintext string in the same record. This completely defeats the purpose of homomorphic tallying — anyone reading the ledger can see individual votes. For the paper, either:
> - Remove `voteChoice` from the on-chain record and rely solely on `encryptedVote`, or
> - Argue this is a deliberate design choice (e.g., plaintext for auditability) and note that in production it would be encrypted-only.

### 4. Vote Validity ZKP Is Implemented But Never Called

The [proveValidVote()](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js#183-257) and [verifyValidVote()](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js#258-302) functions exist in [homomorphic.js](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js) (lines 192–301) but are **never invoked** in the vote casting flow ([vote.js](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/routes/vote.js)). The paper's Section 5.6 describes this as a core feature, but it's not actually used.

### 5. Ballot Management Is In-Memory (Not on Blockchain)

```javascript
// ballot.js line 9
let activeBallot = null;  // In-memory storage
```

The ballot data is **not** stored on the blockchain — it's a JavaScript variable that disappears on server restart. This undermines the "decentralized" claim. A reviewer will ask: *"If the API server is the single point of ballot management, how is this decentralized?"*

### 6. Schnorr Login Verification Is Broken

```javascript
// server.js line 371-372
const sG = ec.g.mul(s);
const zkpVerified = sG.validate();  // ← This just checks if the point is on the curve
```

The legacy login verification doesn't actually verify the Schnorr proof — it only validates that `s·G` is a valid curve point (which it always is). The proper check `s·G == R + c·S` is never performed.

---

## ⚠️ Important Issues (Should Fix for Q1)

### 7. No FAR/FRR/EER Evaluation for the Biometric Pipeline

You have a cosine threshold of 0.50 but **no empirical evaluation** of:
- False Acceptance Rate (FAR) — how often an imposter is accepted
- False Rejection Rate (FRR) — how often a legitimate voter is rejected
- Equal Error Rate (EER) — the threshold where FAR = FRR

Q1 journals in security/biometrics will require this. Run your FaceNet+PCA pipeline on a standard face dataset (e.g., LFW, CALFW) and plot FAR vs FRR at different thresholds.

### 8. Benchmark Simulation Has a Flaw

In [lrs_results.json](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/lrs_results.json), the simulation section shows:
- `voters=25, ring_size=10, valid_votes=10, rejected=15`
- `voters=500, ring_size=10, valid_votes=10, rejected=490`

The ring size is fixed at 10 while attempting 500 voters. Since there are only 10 keys, only 10 unique link tags exist — 490 voters are "rejected" as double-voters. This doesn't test scalability, it tests double-vote detection. You need benchmarks where `ring_size = voters` to measure actual scalability.

### 9. Missing End-to-End Latency Benchmarks

Your benchmark covers LRS operations only. For a Q1 paper you need:
- Face detection + FaceNet inference + PCA latency
- QR decode + AES decrypt latency
- Fabric transaction submission latency (TPS)
- **Full end-to-end vote casting latency** (registration → authentication → signing → encryption → blockchain commit)

### 10. No Formal Composability Argument

Individual components (LRS, ElGamal, FaceNet) are secure in isolation. But combining them introduces potential interactions. At minimum, provide an informal argument for why the composition is secure. For Q1 venues like IEEE TIFS, you'd want a UC-framework analysis.

---

## 💡 Improvements to Boost to Q1

### Code Changes Required

| # | Change | Impact | Effort |
|---|---|---|---|
| 1 | Rename [keccak256](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/server.js#43-49) → `sha256Hash` everywhere | Eliminates credibility risk | Low |
| 2 | Implement proper hash-to-curve in [lrs.js](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/lrs.js) | Fixes potential security flaw | Medium |
| 3 | Remove `voteChoice` from on-chain vote record | Aligns implementation with privacy claims | Low |
| 4 | Wire up [proveValidVote()](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js#183-257) / [verifyValidVote()](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/homomorphic.js#258-302) in vote flow | Makes claimed feature real | Medium |
| 5 | Move ballot management to chaincode or a persistent store | Strengthens decentralization claim | Medium |
| 6 | Fix Schnorr verification or remove legacy endpoints | Removes demonstrably broken code | Low |
| 7 | Add biometric benchmark (FAR/FRR on LFW dataset) | Required for any biometric paper | Medium |
| 8 | Fix simulation benchmark (ring_size = voters) | Shows true scalability | Low |
| 9 | Add end-to-end latency benchmarks | Addresses reviewer expectations | Medium |
| 10 | Add password-to-key via PBKDF2/Argon2 instead of single SHA-256 | Eliminates a brute-force attack vector (QR credential) | Low |

### Paper Structure Additions

| Section | What to Add |
|---|---|
| **Performance Evaluation** | Tables/charts: LRS latency vs ring size ✅ (have this) + FaceNet latency + Fabric TPS + end-to-end latency |
| **Biometric Accuracy** | FAR, FRR, EER at τ=0.40, 0.45, 0.50, 0.55, 0.60 on LFW/CALFW |
| **Signature Size Comparison** | Compare your LRS sizes with MACI (zk-SNARK proof ~288B), Open Vote Network, and Panja et al. |
| **Gas/Cost Analysis** | Compare Fabric (zero gas) with Ethereum-based systems — you mention this but should quantify |
| **Composability Discussion** | 1-2 paragraphs explaining why LRS + ElGamal + FaceNet don't interfere |

---

## 🎯 Target Journals (Realistic)

| Tier | Journal | Why |
|---|---|---|
| **Best fit** | **Journal of Information Security and Applications (JISA)** — Elsevier, Q1 | Applied security, values prototypes, 4–6 month review |
| **Best fit** | **IEEE Access** — Q1 (multidisciplinary) | Higher acceptance rate, fast review, interdisciplinary audience |
| **Ambitious** | **Computers & Security** — Elsevier, Q1 | Needs stronger evaluation, but topic fits perfectly |
| **Ambitious** | **Future Generation Computer Systems** — Elsevier, Q1 | Blockchain + distributed systems focus |
| **Stretch** | **IEEE Trans. on Information Forensics and Security** — Q1 top-tier | Would need formal composability proof + FAR/FRR + comprehensive benchmarks |

---

## Summary

Your system's **concept and architecture are publishable** — the novel integration of face-biometric-derived ECC keys with LRS, ElGamal, and Fabric is a genuine contribution. The main barriers to Q1 are:

1. **The [hashToPoint](file:///c:/Mahin/TSE%20Learning/Thesis/ZKPNew/zkp-chain/api-server/crypto/lrs.js#254-269) security issue** (most critical — reviewers will reject for this)
2. **Plaintext `voteChoice` on-chain** contradicting privacy claims
3. **Missing biometric accuracy evaluation** (FAR/FRR)
4. **Missing end-to-end benchmarks**

Fix items 1–6 from the code changes table, add biometric and end-to-end evaluations, and this becomes a competitive Q1 submission for JISA or IEEE Access.
