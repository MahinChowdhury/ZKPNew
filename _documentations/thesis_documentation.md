# A Privacy-Preserving Distributed Voting System Using Zero-Knowledge Proofs and Biometric Authentication

## Detailed Technical Documentation for Thesis / Journal Paper

---

## 1. Introduction and Motivation

Electronic voting (e-voting) systems promise increased accessibility, reduced cost, and faster tallying compared to traditional paper-based voting. However, they introduce critical challenges around **voter privacy**, **ballot integrity**, and **verifiability**. A secure e-voting system must satisfy the following fundamental properties (Gritzalis, 2002; Adida, 2008):

| Property | Description |
|---|---|
| **Eligibility** | Only registered, authorized voters can cast ballots. |
| **Uniqueness** | Each voter can vote at most once. |
| **Privacy** | No one can determine how a specific voter voted. |
| **Verifiability** | Voters can verify their vote was counted; observers can verify the tally. |
| **Coercion Resistance** | A voter cannot prove to a third party how they voted. |
| **Integrity** | Votes cannot be altered, deleted, or fabricated. |

Traditional approaches sacrifice at least one of these properties. Centralized databases can be tampered with (violating integrity). PKI-based signatures link votes to identities (violating privacy). Simple password authentication is transferable (violating eligibility through proxy voting).

**This research proposes a novel architecture** that satisfies all six properties by combining:
1. **Face biometrics** for non-transferable voter authentication (Eligibility).
2. **Linkable Ring Signatures (LRS)** for anonymous yet unique vote casting (Privacy + Uniqueness).
3. **Exponential ElGamal homomorphic encryption** for private tallying (Privacy + Verifiability).
4. **Hyperledger Fabric blockchain** for immutable, auditable record-keeping (Integrity + Verifiability).

---

## 2. Related Work, Existing Systems, and Their Limitations

This section presents a comprehensive review of existing blockchain-based voting systems, zero-knowledge proof applications in e-voting, and biometric authentication approaches. For each, we identify specific limitations that our proposed system addresses.

### 2.1. Blockchain-Based Voting Systems

#### 2.1.1. Open Vote Network (McCorry, Shahandashti & Hao, 2017)
- **Approach**: First implementation of a decentralised voting protocol on Ethereum using a self-tallying mechanism based on the boardroom voting protocol.
- **Strengths**: Fully decentralised; no trusted authority needed for tallying; anyone can compute the result from the blockchain.
- **Limitations**:
  - ❌ Runs on **Ethereum public chain** — high gas costs (~$0.73 per voter at 2017 prices; much higher during congestion).
  - ❌ **No voter authentication mechanism** — assumes all participants are pre-authorized Ethereum addresses.
  - ❌ **Linear round complexity**: Requires $n$ rounds of interaction for $n$ voters (each voter must submit two transactions sequentially).
  - ❌ **No biometric binding** — Ethereum private keys are transferable; proxy voting is trivially possible.
  - ❌ **Not scalable**: Protocol complexity is $O(n^2)$ due to all-to-all ZKP verifications.

#### 2.1.2. Voatz (Specter, Koppel & Weitzner, 2020 — Security Audit)
- **Approach**: Mobile voting app used in West Virginia (2018 midterms) with a permissioned blockchain backend.
- **Strengths**: Real-world deployment; used fingerprint/face biometrics on mobile devices.
- **Limitations**:
  - ❌ **Centralised trust model** — all biometric verification and vote processing happens on Voatz servers; voters must trust the company.
  - ❌ MIT security audit found vulnerabilities to **server-side vote manipulation**, **client-side attacks**, and **network adversaries**.
  - ❌ Biometric data is processed by a **third-party service (Jumio)**, creating a privacy risk.
  - ❌ **No cryptographic anonymity** — votes are linked to identified accounts on the server side.
  - ❌ No homomorphic encryption; the server sees plaintext votes.

#### 2.1.3. Follow My Vote (2015–present)
- **Approach**: Open-source e-voting on a custom blockchain using elliptic curve cryptography.
- **Strengths**: Open-source; voter can track their ballot.
- **Limitations**:
  - ❌ **No biometric integration** — relies on traditional identity documents.
  - ❌ Uses simple digital signatures (not ring signatures) — **votes are linkable to public keys**.
  - ❌ No homomorphic tallying — votes are decrypted individually for counting.
  - ❌ No formal double-voting prevention beyond key uniqueness.

#### 2.1.4. Agora (2017–2018, Sierra Leone pilot)
- **Approach**: Permissioned blockchain observing paper ballots, providing an independent count.
- **Strengths**: Real election deployment; independent audit trail.
- **Limitations**:
  - ❌ **Not a cryptographic voting system** — merely digitises paper ballot observations.
  - ❌ No voter privacy mechanisms (all votes observed in plaintext).
  - ❌ No ZKP or biometric components.

### 2.2. ZKP-Based Voting Systems

#### 2.2.1. MACI — Minimum Anti-Collusion Infrastructure (Buterin, 2019; Barry WhiteHat, 2020)
- **Approach**: Ethereum-based protocol using zk-SNARKs to prevent bribery by allowing voters to change their vote keys without the briber knowing.
- **Strengths**: Strong anti-collusion properties; zk-SNARK proofs for correct state transitions.
- **Limitations**:
  - ❌ Requires a **trusted coordinator** who holds a secret key and can decrypt all votes (single point of trust).
  - ❌ **zk-SNARK proof generation is extremely expensive** — ~30 seconds per proof on consumer hardware, impractical for resource-constrained devices.
  - ❌ Requires a **trusted setup ceremony** (toxic waste problem).
  - ❌ **No biometric authentication** — relies on Ethereum keys.
  - ❌ Runs on Ethereum — gas costs and scalability issues persist.

#### 2.2.2. Blockchain Voting with zk-SNARKs (Syed et al., 2024 — JISIS)
- **Approach**: Hybrid on-chain/off-chain ZK-SNARK verification for voter eligibility, deployed on a blockchain.
- **Strengths**: Efficient identity verification without revealing voter data.
- **Limitations**:
  - ❌ **Trusted setup** required for zk-SNARKs.
  - ❌ No linkability property — **double-voting prevention relies on a centralised voter registry**, not a cryptographic mechanism.
  - ❌ No homomorphic tallying — individual votes are decrypted.
  - ❌ No biometric binding — relies on knowledge-based credentials.

#### 2.2.3. LRS-Based Voting on Hyperledger Fabric (Panja et al., 2022 — ResearchGate)
- **Approach**: Replaced blind signatures with linkable ring signatures in a Fabric-based e-voting scheme.
- **Strengths**: Decentralized anonymity; link tags for double-vote detection; permissioned blockchain.
- **Limitations**:
  - ❌ **No biometric authentication** — uses traditional PKI for voter registration.
  - ❌ **No homomorphic encryption** — votes are stored in plaintext on the ledger (privacy is only at the signer identity level, not the vote content level).
  - ❌ No vote validity proofs — a malicious voter could submit an arbitrary string as a vote.
  - ❌ No face/fingerprint binding, so **proxy voting remains possible** if a voter shares their private key.

#### 2.2.4. Short Linkable Ring Signature Voting (Li et al., 2023 — Northeastern University, China)
- **Approach**: Short LRS scheme for anonymous voting with automatic counting on a blockchain.
- **Strengths**: Reduced signature size compared to standard LRS.
- **Limitations**:
  - ❌ **No biometric integration** — transferable credentials.
  - ❌ No privacy-preserving tallying (votes counted in plaintext).
  - ❌ Deployed on a public blockchain with associated scalability issues.

### 2.3. Biometric-Blockchain Voting Systems

#### 2.3.1. Fingerprint + Permissioned Blockchain + ZKP (IEEE, 2023)
- **Approach**: Integrates fingerprint biometrics with a permissioned blockchain and zero-knowledge proofs.
- **Strengths**: Non-transferable authentication; blockchain immutability.
- **Limitations**:
  - ❌ Uses **fingerprint only** — requires specialised hardware (fingerprint scanners), limiting accessibility.
  - ❌ ZKP implementation details are vague — does not specify which ZKP scheme is used.
  - ❌ No homomorphic tallying described.
  - ❌ **Biometric template stored on-chain** in some implementations, creating a privacy risk.

#### 2.3.2. Facial Recognition + Smart Contracts (2024 — AWS/ResearchGate)
- **Approach**: Blockchain-based voting using facial recognition for authentication, with smart contracts for automation.
- **Strengths**: Face-based authentication; automated tally via smart contracts.
- **Limitations**:
  - ❌ **No cryptographic anonymity** — voter identity is linked to their vote via smart contract execution.
  - ❌ No ring signatures or ZKP for vote privacy.
  - ❌ No homomorphic encryption — administrator can see individual votes.
  - ❌ Face recognition used only as a gate, not integrated into the cryptographic protocol.

#### 2.3.3. Biometric E-Voting with Iris + Fingerprint (IRJET, 2025)
- **Approach**: Multi-modal biometrics (fingerprint + iris) on a blockchain.
- **Strengths**: Multi-factor biometric authentication.
- **Limitations**:
  - ❌ Requires **specialised hardware** (iris scanner + fingerprint reader).
  - ❌ **No ZKP or ring signatures** — no formal privacy guarantees.
  - ❌ No homomorphic tallying.
  - ❌ High costs for deployment at scale.

### 2.4. Summary of Limitations in Existing Work

Across the literature, we identify the following **recurring gaps**:

| Gap | Systems Affected |
|---|---|
| **No biometric authentication** — credentials are transferable | Open Vote Network, MACI, Follow My Vote, LRS-Fabric, Short LRS |
| **No privacy-preserving tallying** — server sees individual votes | Voatz, Follow My Vote, LRS-Fabric, Short LRS, Fingerprint+ZKP |
| **Centralised trust** — a single entity can manipulate votes | Voatz, MACI (coordinator), Agora |
| **No cryptographic double-vote prevention** — relies on registry checks | Voatz, zk-SNARK Voting, Follow My Vote |
| **Public blockchain costs/scalability** | Open Vote Network, MACI, Short LRS, Agora |
| **Biometric data stored on-chain** — privacy risk | Some fingerprint implementations |
| **No vote validity proofs** — ballot stuffing possible | LRS-Fabric, Follow My Vote, most biometric systems |

**Our system addresses ALL of these gaps simultaneously** — this is the core contribution.

### 2.5. Biometric Authentication in Cryptographic Systems

Biometric-based authentication provides the "something you are" factor, which is inherently non-transferable. Key challenges include:
- **Template security**: Storing raw biometric templates creates a single point of compromise.
- **Fuzzy matching**: Biometric samples are never exactly identical across sessions, requiring tolerance-based comparison.
- **Cancelability**: Unlike passwords, biometrics cannot be changed if compromised.

**Our approach**: We use **FaceNet** deep learning embeddings with **PCA dimensionality reduction** to create compact, privacy-preserving representations. The face embedding is never stored on the blockchain; instead, it is used to deterministically derive an elliptic curve private key, and the embedding is encrypted within a QR code credential held only by the voter.

---

## 3. Theoretical Foundations

### 3.1. Elliptic Curve Cryptography (ECC)

**Definition 3.1 (Elliptic Curve).** An elliptic curve $E$ over a finite field $\mathbb{F}_p$ (where $p$ is a large prime) is defined by the Weierstrass equation:

$$y^2 \equiv x^3 + ax + b \pmod{p}$$

where $4a^3 + 27b^2 \neq 0$ (non-singular condition).

**Definition 3.2 (Elliptic Curve Group).** The set of all points $(x, y)$ satisfying the curve equation, together with a special "point at infinity" $\mathcal{O}$ (serving as the identity element), forms an abelian group under the point addition operation defined by the chord-and-tangent rule.

**Curve Parameters (secp256k1)**:
| Parameter | Value |
|---|---|
| Field prime $p$ | $2^{256} - 2^{32} - 977$ |
| Curve equation | $y^2 = x^3 + 7$ (i.e., $a = 0$, $b = 7$) |
| Generator point $G$ | A fixed point on the curve |
| Order $n$ | $\approx 1.158 \times 10^{77}$ (number of points in the cyclic subgroup generated by $G$) |
| Cofactor $h$ | 1 |

**Definition 3.3 (Elliptic Curve Discrete Logarithm Problem — ECDLP).** Given two points $P$ and $Q = k \cdot P$ on an elliptic curve $E$, find the integer $k$. This problem is believed to be computationally intractable for well-chosen curves. The best known algorithm (Pollard's rho) has time complexity $O(\sqrt{n})$ where $n$ is the group order, giving approximately 128-bit security for secp256k1.

**Theorem 3.1 (Security Foundation).** All cryptographic constructions in this system — key generation, ring signatures, homomorphic encryption, and Schnorr proofs — derive their security from the hardness of the ECDLP.

---

### 3.2. Hash Functions

We use SHA-256 (referred to as `Keccak256` in the codebase for compatibility naming) as our collision-resistant hash function $H: \{0,1\}^* \rightarrow \{0,1\}^{256}$.

**Properties Required:**
1. **Pre-image resistance**: Given $h$, it is infeasible to find $m$ such that $H(m) = h$.
2. **Second pre-image resistance**: Given $m_1$, it is infeasible to find $m_2 \neq m_1$ such that $H(m_1) = H(m_2)$.
3. **Collision resistance**: It is infeasible to find any pair $(m_1, m_2)$ where $m_1 \neq m_2$ and $H(m_1) = H(m_2)$.

**Hash-to-Point Function $H_p$**: We define a deterministic mapping from public keys to curve points:

$$H_p(P) = H(P_x || P_y) \cdot G$$

where $P_x, P_y$ are the affine coordinates of $P$ encoded as 64-character hex strings. This serves as the hash-to-curve function used in LRS for computing the link tag.

---

### 3.3. Linkable Ring Signature (LRS) Theory

**Definition 3.4 (Ring Signature).** A ring signature scheme $\mathcal{RS}$ consists of three polynomial-time algorithms:
1. $\text{KeyGen}(1^\lambda) \rightarrow (sk, pk)$: Generate a key pair.
2. $\text{Sign}(sk_\pi, m, \mathcal{R}) \rightarrow \sigma$: Sign message $m$ using secret key $sk_\pi$ with respect to ring $\mathcal{R} = \{pk_1, \ldots, pk_n\}$ where $pk_\pi \in \mathcal{R}$.
3. $\text{Verify}(\sigma, m, \mathcal{R}) \rightarrow \{0, 1\}$: Verify signature $\sigma$ on message $m$ with respect to ring $\mathcal{R}$.

**Definition 3.5 (Linkable Ring Signature).** An LRS extends a ring signature with:
4. $\text{Link}(\sigma_1, \sigma_2) \rightarrow \{0, 1\}$: Determine if two signatures were produced by the same signer.

**Security Properties:**
- **Unforgeability**: An adversary who does not know any secret key in the ring cannot produce a valid signature. Formally, the advantage of any PPT adversary $\mathcal{A}$ in the forgery game is negligible in the security parameter $\lambda$.
- **Signer Ambiguity (Anonymity)**: Given a valid signature, the probability that any PPT adversary identifies the actual signer is at most $1/n$ (where $n$ is the ring size), i.e., no better than random guessing.
- **Linkability**: If two valid signatures share the same link tag $I$, they were produced by the same secret key with overwhelming probability. More precisely, $ \Pr[\text{Link}(\sigma_1, \sigma_2) = 1 \mid sk_{\sigma_1} = sk_{\sigma_2}] = 1 $ and $ \Pr[\text{Link}(\sigma_1, \sigma_2) = 1 \mid sk_{\sigma_1} \neq sk_{\sigma_2}] = \text{negl}(\lambda) $.
- **Non-slanderability**: An adversary cannot produce a signature that links to an honest user's signature without knowing that user's secret key.

---

### 3.4. Homomorphic Encryption Theory

**Definition 3.6 (Additively Homomorphic Encryption).** A public-key encryption scheme $\mathcal{E} = (\text{KeyGen}, \text{Enc}, \text{Dec})$ is additively homomorphic if there exists an efficient operation $\oplus$ on ciphertexts such that:

$$\text{Dec}_{sk}(\text{Enc}_{pk}(m_1) \oplus \text{Enc}_{pk}(m_2)) = m_1 + m_2$$

**The Exponential ElGamal Scheme over Elliptic Curves:**

Traditional ElGamal encrypts messages as group elements and is *multiplicatively* homomorphic. The *Exponential* variant encodes the message $m$ as $m \cdot G$ (a scalar multiple of the generator), converting the scheme to *additively* homomorphic at the cost of requiring a discrete log computation during decryption.

**Correctness Proof:**
Given ciphertext $\text{Enc}(v) = (r \cdot G, \; v \cdot G + r \cdot Q)$ where $Q = d \cdot G$:

$$\text{Dec}(C_1, C_2) = C_2 - d \cdot C_1 = (vG + rQ) - d(rG) = vG + r(dG) - d(rG) = vG$$

Homomorphic addition:

$$\text{Enc}(v_1) \oplus \text{Enc}(v_2) = (r_1 G + r_2 G, \; v_1 G + r_1 Q + v_2 G + r_2 Q) = ((r_1 + r_2)G, \; (v_1 + v_2)G + (r_1 + r_2)Q) = \text{Enc}(v_1 + v_2)$$

This allows the tallying authority to compute the sum of all votes $\sum v_i$ without ever decrypting individual votes.

---

### 3.5. Discrete Logarithm Recovery — Baby-Step Giant-Step Algorithm

After decryption, we obtain a point $M = v \cdot G$ and need to recover $v$. This is a bounded instance of the DLP where $v \in [0, N]$ for known bound $N$ (the maximum number of voters).

**Algorithm 3.1: Baby-Step Giant-Step (Shanks, 1971)**

**Input:** Point $M = vG$, bound $N$, generator $G$.
**Output:** Integer $v$ such that $vG = M$.

1. Set $m = \lceil \sqrt{N} \rceil$.
2. **Baby Steps**: Compute table $T = \{(jG, j) \mid j = 0, 1, \ldots, m-1\}$.
3. Compute giant step factor $\Delta = m \cdot G$.
4. Set $\gamma = M$.
5. **Giant Steps**: For $i = 0, 1, \ldots, m$:
   - If $\gamma \in T$ (lookup by x-coordinate), return $v = i \cdot m + T[\gamma]$.
   - Set $\gamma = \gamma - \Delta$.
6. If no match found, return FAILURE.

**Complexity:** Time $O(\sqrt{N})$, Space $O(\sqrt{N})$.

For a voting system with $N \leq 10{,}000$ voters, this requires at most $\sqrt{10{,}000} = 100$ curve point operations — effectively instantaneous.

---

### 3.6. Principal Component Analysis (PCA) for Embedding Reduction

**Motivation:** FaceNet produces 128-dimensional embeddings. High-dimensional embeddings increase QR code payload size and may contain noise dimensions that cause instability across sessions. PCA reduces dimensionality while preserving maximum variance.

**Algorithm 3.2: PCA Dimensionality Reduction**

**Input:** Dataset of embeddings $X \in \mathbb{R}^{n \times 128}$ (training set), target dimension $d = 64$.
**Output:** Projection matrix $W \in \mathbb{R}^{128 \times 64}$.

1. Compute mean $\mu = \frac{1}{n} \sum_{i=1}^{n} x_i$.
2. Center the data: $\hat{X} = X - \mu$.
3. Compute covariance matrix: $\Sigma = \frac{1}{n-1} \hat{X}^T \hat{X}$.
4. Compute eigendecomposition: $\Sigma = V \Lambda V^T$ where $\Lambda = \text{diag}(\lambda_1, \ldots, \lambda_{128})$ with $\lambda_1 \geq \lambda_2 \geq \cdots$.
5. Select top $d$ eigenvectors: $W = [v_1, v_2, \ldots, v_d]$.
6. **Projection**: For a new embedding $x$, compute $x' = (x - \mu) \cdot W$, then normalize: $\hat{x}' = x' / \|x'\|_2$.

**Variance Preserved**: The fraction of variance retained is $\sum_{i=1}^{d} \lambda_i / \sum_{i=1}^{128} \lambda_i$. With $d = 64$, typically $> 95\%$ of variance is preserved.

---

## 4. System Architecture

### 4.1. Three-Tier Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│   QR Code Scan  ←→  Face Camera  ←→  Vote Selection UI          │
└───────────────────────────┬──────────────────────────────────────┘
                            │ HTTPS / REST API
┌───────────────────────────▼──────────────────────────────────────┐
│                     APPLICATION LAYER                             │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ server.js   │  │ routes/      │  │ crypto/                │  │
│  │ (Express)   │  │  vote.js     │  │  lrs.js (Ring Sig)     │  │
│  │             │  │  ballot.js   │  │  homomorphic.js        │  │
│  │             │  │  tally.js    │  │  (ElGamal)             │  │
│  └──────┬──────┘  └──────────────┘  └────────────────────────┘  │
│         │                                                        │
│  ┌──────▼──────┐  ┌──────────────────────────────────────────┐  │
│  │fabric-      │  │ Python Biometric Service (FastAPI)        │  │
│  │client.js    │  │  FaceNet + MediaPipe + PCA (port 8000)   │  │
│  └──────┬──────┘  └──────────────────────────────────────────┘  │
└─────────┼────────────────────────────────────────────────────────┘
          │ gRPC / Fabric SDK
┌─────────▼────────────────────────────────────────────────────────┐
│                     BLOCKCHAIN LAYER                              │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │              Hyperledger Fabric Network                    │   │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────────────────────┐  │   │
│  │  │ Org1    │  │ Org2    │  │ Orderer                  │  │   │
│  │  │ Peer    │  │ Peer    │  │ (Raft Consensus)         │  │   │
│  │  └────┬────┘  └────┬────┘  └──────────────────────────┘  │   │
│  │       └──────┬─────┘                                      │   │
│  │      ┌───────▼───────┐                                    │   │
│  │      │identityContract│  ← Smart Contract (Chaincode)     │   │
│  │      │   .js          │     State DB: CouchDB              │   │
│  │      └────────────────┘                                    │   │
│  └───────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2. Hyperledger Fabric Configuration
- **Channel**: `mychannel` — a private communication channel between organizations.
- **Organizations**: Org1MSP and Org2MSP — two independent endorsing organizations.
- **Consensus**: Raft (Crash Fault Tolerant) ordering service.
- **Endorsement Policy**: Both organizations must endorse transactions.
- **Chaincode**: `identity` contract deployed as Node.js chaincode.
- **Certificate Authority (CA)**: Fabric CA issues X.509 certificates for network participants.

### 4.3. On-Chain Data Structures

| Key Pattern | Document Type | Contents |
|---|---|---|
| `GLOBAL_RING` | `ring` | Array of all registered public keys $\{(x_i, y_i)\}$ |
| `VOTE_COUNTER` | `counter` | Monotonically increasing vote count |
| `VOTE_{n}` | `vote` | Vote record: choice, LRS signature, ring snapshot, encrypted vote, timestamp |
| `LINK_TAG_{x}_{y}` | `linkTag` | Maps link tag coordinates to vote ID (for double-vote detection) |
| `{nidHash}` | `identity` | Legacy per-user registration record |

---

## 5. Protocol Specification

### 5.1. Phase 1 — Voter Registration Protocol

```
Voter                          API Server                    Python Service               Blockchain
  │                                │                              │                          │
  │─── NID, Password, FaceImg ───►│                              │                          │
  │                                │─── FaceImg ────────────────►│                          │
  │                                │                              │── detect_face()          │
  │                                │                              │── FaceNet.represent()    │
  │                                │                              │── PCA.transform()        │
  │                                │◄── embedding_64d ───────────│                          │
  │                                │                              │                          │
  │                                │── h_face = H(embedding)     │                          │
  │                                │── salt = random(16 bytes)    │                          │
  │                                │── k = H(h_face||salt) mod n  │                          │
  │                                │── S = k·G                    │                          │
  │                                │                              │                          │
  │                                │── register(nidHash,Sx,Sy,salt) ─────────────────────►│
  │                                │                              │        addToRing(S)      │
  │                                │                              │      emit Registered     │
  │                                │◄─────────────────────────────────── confirmation ───────│
  │                                │                              │                          │
  │                                │── QR = AES-CBC(embedding,    │                          │
  │                                │       h_face, salt, nidHash; │                          │
  │                                │       key=H(password))       │                          │
  │◄── QR Code (PNG image) ───────│                              │                          │
```

**Security Properties of Registration:**
- The private key $k$ never leaves the API server's transient memory; it is not stored anywhere.
- The blockchain stores only $(S_x, S_y)$ — the public key — which reveals nothing about the face embedding or NID.
- The QR code is AES-256-CBC encrypted with the voter's password. Without the password, the face embedding cannot be recovered.

---

### 5.2. Phase 2 — Ballot Creation Protocol

**Algorithm 5.1: Ballot Creation**

**Input:** Title $T$, description $D$, candidate options $\{O_1, O_2, \ldots, O_m\}$, start time $t_s$, end time $t_e$.

1. Validate: $m \geq 2$, all options unique, timestamps valid.
2. Create ballot object $B$:
   - $B.id = \text{``ballot\_''} || \text{timestamp}$
   - $B.status = \text{``active''}$
   - $B.options = \{(O_i, \text{votes}: 0)\}_{i=1}^{m}$
3. If a previous ballot exists, close it and archive to history.
4. Set $B$ as the active ballot.

**Algorithm 5.2: Homomorphic Encryption Setup**

1. Generate ElGamal keypair:
   - $d \xleftarrow{\$} [1, n-1]$ (random private key)
   - $Q = d \cdot G$ (public key)
2. Store $(d, Q)$ keyed by $B.id$.
3. Publish $Q$ via `GET /api/v1/tally/publickey/:ballotId`.

**Security Note:** In a production deployment, the private key $d$ should be generated via a **Distributed Key Generation (DKG)** ceremony among multiple trustees, preventing any single party from decrypting individual votes.

---

### 5.3. Phase 3 — Vote Casting Protocol

**Algorithm 5.3: Anonymous Vote Casting**

**Input:** QR code image, live face image, password, vote choice $v_c$.

**Phase 3a — Authentication:**
1. Decode QR code from image using jsQR library.
2. Decrypt QR payload: $\text{data} = \text{AES-CBC-Dec}(\text{QR}, H(\text{password}))$.
3. Extract: $\text{embedding}_{reg}, h_{face}, \text{salt}, \text{nidHash}$.
4. Capture live face and extract embedding: $\text{embedding}_{live} = \text{FaceNet}(\text{live\_image})$.
5. Compute cosine similarity:
   $$\cos(\theta) = \frac{\text{embedding}_{reg} \cdot \text{embedding}_{live}}{\|\text{embedding}_{reg}\| \cdot \|\text{embedding}_{live}\|}$$
6. **Accept** if $\cos(\theta) > \tau$ where $\tau = 0.50$ (configurable threshold).

**Phase 3b — Key Recovery:**
7. Reconstruct private key: $k = H(h_{face} || \text{salt}) \mod n$.
8. Compute public key: $S = k \cdot G$.

**Phase 3c — Ring Signature Generation:**
9. Retrieve global ring $\mathcal{R} = \{PK_1, \ldots, PK_n\}$ from blockchain.
10. Locate signer index $\pi$ such that $PK_\pi = S$.
11. Execute LRS.Sign($k$, $\mathcal{R}$, $\pi$, $v_c$) → $\sigma = (c_0, \{s_i\}, I, \text{startIndex})$.

**Phase 3d — Vote Encryption:**
12. Retrieve ballot public key $Q$.
13. Encrypt vote value (1 for chosen candidate):
    - $r \xleftarrow{\$} [1, n-1]$
    - $C_1 = r \cdot G$
    - $C_2 = 1 \cdot G + r \cdot Q$
14. Serialize: $\text{encVote} = \{C_1: (x, y), C_2: (x, y)\}$.

**Phase 3e — Submission:**
15. Verify signature locally: LRS.Verify($\sigma$, $\mathcal{R}$, $v_c$).
16. Submit to blockchain: `castVote(v_c, σ, R, encVote)`.

**On-Chain Verification (Chaincode):**
17. Extract link tag $I = (I_x, I_y)$ from $\sigma$.
18. Check: If `LINK_TAG_{I_x}_{I_y}` exists in world state → **REJECT** ("Double voting detected").
19. Increment `VOTE_COUNTER`.
20. Store vote record under `VOTE_{count}`.
21. Store `LINK_TAG_{I_x}_{I_y}` → `{voteId, timestamp}`.
22. Emit `VoteCast` event.

---

### 5.4. Phase 4 — Revote Prevention (Double-Vote Detection)

**Theorem 5.1 (Revote Prevention Correctness).** If a voter with private key $k$ casts two votes producing signatures $\sigma_1$ and $\sigma_2$, then $ I_1 = I_2 $ with probability 1.

**Proof.** The link tag is computed as:
$$I = k \cdot H_p(PK)$$

where $H_p$ is deterministic and $PK = k \cdot G$ is fixed for a given $k$. Since $k$, $PK$, and $H_p$ are all deterministic, $I$ is uniquely determined by $k$. Therefore $I_1 = k \cdot H_p(PK) = I_2$. The chaincode checks for the existence of $I$ before accepting a vote, thus preventing re-voting. $\square$

**Theorem 5.2 (Privacy of Link Tags).** Given a link tag $I$ and the ring $\mathcal{R}$, no PPT adversary can determine which member of the ring produced $I$, assuming the ECDLP is hard.

**Proof sketch.** Determining the signer from $I$ requires computing $k$ from $I = k \cdot H_p(PK)$, which is an instance of the ECDLP (since $H_p(PK)$ is a known public point). $\square$

---

### 5.5. Phase 5 — Vote Tallying Protocol

**Algorithm 5.4: Homomorphic Tally Computation**

**Input:** All encrypted votes from blockchain, ballot keypair $(d, Q)$, ballot options $\{O_1, \ldots, O_m\}$.

1. Retrieve all votes: $\{(v_{c_j}, \text{encVote}_j)\}_{j=1}^{N}$.
2. For each candidate $O_i$, initialize aggregate ciphertext $\mathcal{C}_i = \bot$.
3. For each vote $j$:
   - If $v_{c_j} = O_i$:
     - $\text{ct}_j = \text{deserialize}(\text{encVote}_j)$
     - If $\mathcal{C}_i = \bot$: $\mathcal{C}_i = \text{ct}_j$
     - Else: $\mathcal{C}_i = \text{HomAdd}(\mathcal{C}_i, \text{ct}_j)$
4. For each candidate $O_i$:
   - If $\mathcal{C}_i = \bot$: $\text{count}_i = 0$.
   - Else:
     - Decrypt: $M_i = C_{i,2} - d \cdot C_{i,1}$
     - Solve DLP: $\text{count}_i = \text{BSGS}(M_i, N)$
5. Return $\{\text{count}_i\}_{i=1}^{m}$.

**Algorithm 5.5: Tally Verification**

Any third-party auditor can verify the tally:
1. Retrieve all encrypted votes from blockchain (publicly available).
2. Recompute the homomorphic sums $\mathcal{C}_i'$ independently.
3. Compare $\mathcal{C}_i' = \mathcal{C}_i$ (the claimed aggregate ciphertexts from the decryption log).
4. If all match, the aggregation step was performed correctly.

Note: Verifying the *decryption* step requires either access to the private key $d$ or a zero-knowledge proof of correct decryption (e.g., Chaum-Pedersen protocol).

---

### 5.6. Phase 6 — Vote Validity Proof (ZK Range Proof)

To prevent ballot stuffing (encrypting values other than 0 or 1), the system includes a **Disjunctive Chaum-Pedersen** zero-knowledge proof.

**Algorithm 5.6: Prove Valid Vote (1-of-2 ZKP)**

**Goal:** Prove that a ciphertext $(C_1, C_2)$ encrypts either 0 or 1 without revealing which.

This is a $\Sigma$-protocol for the OR of two statements:
- Statement 0: $C_2 = 0 \cdot G + r \cdot Q$ (vote is 0)
- Statement 1: $C_2 = 1 \cdot G + r \cdot Q$ (vote is 1)

**If the actual vote is 0 (real proof for 0, simulated for 1):**
1. Generate random $w, d_2, r_2$.
2. Real commitment: $a_1 = w \cdot G$, $b_1 = w \cdot Q$.
3. Simulated commitment: $a_2 = r_2 \cdot G + d_2 \cdot C_1$, $b_2 = r_2 \cdot Q + d_2 \cdot (C_2 - G)$.
4. Challenge: $c = H(C_1, C_2, a_1, b_1, a_2, b_2)$.
5. Set $d_1 = c - d_2 \mod n$.
6. Response: $r_1 = w - d_1 \cdot r \mod n$.
7. Output proof: $(a_1, b_1, a_2, b_2, d_1, d_2, r_1, r_2)$.

**Verification:**
1. Recompute $c' = H(C_1, C_2, a_1, b_1, a_2, b_2)$.
2. Check $d_1 + d_2 = c' \mod n$.
3. Check: $r_1 \cdot G + d_1 \cdot C_1 = a_1$ and $r_1 \cdot Q + d_1 \cdot C_2 = b_1$.
4. Check: $r_2 \cdot G + d_2 \cdot C_1 = a_2$ and $r_2 \cdot Q + d_2 \cdot (C_2 - G) = b_2$.

**Key Property:** The proof is **zero-knowledge** — the verifier learns nothing about which of the two statements is true — and **sound** — a dishonest prover cannot produce a valid proof for an invalid vote.

---

## 6. Security Analysis

### 6.1. Threat Model

| Threat | Mitigation |
|---|---|
| **Voter impersonation** | Face biometric verification (non-transferable) + password-encrypted QR |
| **Double voting** | Link tag uniqueness check on blockchain (Theorem 5.1) |
| **Vote privacy breach** | Ring signature anonymity (signer ambiguity among $n$ members) |
| **Vote manipulation** | Blockchain immutability + endorsement by multiple organizations |
| **Tally manipulation** | Homomorphic encryption + public verification of aggregate ciphertexts |
| **Ballot stuffing** | Disjunctive Chaum-Pedersen ZKP proves each encrypted vote is in $\{0, 1\}$ |
| **Biometric data theft** | Embeddings are never stored on-chain; encrypted in QR with voter's password |
| **Coercion** | The voter cannot prove how they voted (no receipt — only voteId returned, not choice linkage) |

### 6.2. Formal Security Reductions

1. **LRS Unforgeability** reduces to the ECDLP on secp256k1.
2. **LRS Anonymity** reduces to the Decisional Diffie-Hellman (DDH) assumption on secp256k1.
3. **ElGamal Semantic Security** reduces to the DDH assumption.
4. **Vote Validity ZKP Soundness** reduces to the Discrete Log assumption (via the Fiat-Shamir heuristic in the Random Oracle Model).

### 6.3. Anonymity Set Analysis

The anonymity set equals the ring size $|\mathcal{R}|$ — the number of registered voters. A larger ring provides stronger anonymity but increases signature size linearly:
- Signature size: $O(n)$ — each signature contains $n$ response values $s_i$.
- Verification time: $O(n)$ — requires $n$ point multiplications.

For national elections with millions of voters, techniques such as **subring selection** or **ring signature compression** could be employed to manage scalability.

---

## 7. Complexity Analysis

| Operation | Time Complexity | Space Complexity |
|---|---|---|
| Key derivation (FaceNet + PCA + hash) | $O(1)$ (fixed network inference) | $O(1)$ |
| Ring signature generation | $O(n)$ point multiplications | $O(n)$ scalars |
| Ring signature verification | $O(n)$ point multiplications | $O(n)$ scalars |
| Homomorphic encryption (per vote) | $O(1)$ (2 point multiplications) | $O(1)$ |
| Homomorphic addition (per pair) | $O(1)$ (2 point additions) | $O(1)$ |
| Tally computation (N votes, m candidates) | $O(N + m\sqrt{N})$ | $O(\sqrt{N})$ |
| Double-vote check | $O(1)$ (key-value lookup) | $O(1)$ |

---

## 8. Biometric Service — Detailed Algorithm Pipeline

### 8.1. Face Detection (MediaPipe BlazeFace)

**Model**: BlazeFace SSD (Single Shot Detector) with a BlazeBlock backbone.
- **Input**: RGB image of arbitrary resolution.
- **Output**: Bounding box coordinates (relative), detection confidence score.
- **Configuration**: `model_selection=0` (short-range, within 2m), `min_detection_confidence=0.5`.
- **Post-processing**: Bounding box is expanded by a configurable margin (default 20px) to include facial context.

### 8.2. Feature Extraction (FaceNet / Inception ResNet v1)

**Architecture**: Inception ResNet v1 trained on VGGFace2 dataset ($\approx 3.3M$ images, $9{,}131$ identities).
- **Input**: Face crop resized to $160 \times 160 \times 3$.
- **Output**: 128-dimensional L2-normalized embedding vector.
- **Property**: Embeddings of the same person cluster together in Euclidean space; different persons are distant. The triplet loss training objective ensures:
  $$\|f(x_i^a) - f(x_i^p)\|_2^2 + \alpha < \|f(x_i^a) - f(x_i^n)\|_2^2$$
  where $x^a, x^p, x^n$ are anchor, positive, and negative samples, and $\alpha$ is the margin.

### 8.3. Embedding Comparison

**Cosine Similarity:**
$$\text{sim}(e_1, e_2) = \frac{e_1 \cdot e_2}{\|e_1\| \|e_2\|}$$

**Decision Rule:**
$$\text{is\_same\_person} = \begin{cases} \text{True} & \text{if } \text{sim}(e_1, e_2) > \tau \\ \text{False} & \text{otherwise} \end{cases}$$

where $\tau = 0.50$ (COSINE_THRESHOLD). Additionally, Euclidean distance is computed for diagnostic purposes:
$$d(e_1, e_2) = \|e_1 - e_2\|_2$$

---

## 9. Schnorr Identification Protocol (Legacy Authentication)

The system includes a **Schnorr ZKP** for backward-compatible login authentication.

**Algorithm 9.1: Non-Interactive Schnorr Proof (Fiat-Shamir Heuristic)**

**Prover** (knows $k$, public key $S = kG$):
1. Generate random $r \xleftarrow{\$} \mathbb{Z}_n^*$.
2. Compute commitment $R = r \cdot G$.
3. Compute challenge $c = H(R_x || R_y || S_x || S_y || \text{nidHash})$.
4. Compute response $s = r + c \cdot k \mod n$.
5. Send proof $\pi = (R, c, s)$.

**Verifier** (knows $S$):
1. Check: $s \cdot G \stackrel{?}{=} R + c \cdot S$.

**Correctness:** $s \cdot G = (r + ck)G = rG + c(kG) = R + cS$. ✓

**Soundness:** An adversary who can produce valid proofs for two different challenges $(c, s)$ and $(c', s')$ can extract $k = (s - s') / (c - c') \mod n$, reducing to ECDLP.

**Zero-Knowledge:** The simulator can produce indistinguishable transcripts by choosing $s$ randomly and computing $R = sG - cS$.

---

## 10. End-to-End Voting Flow Summary

| Step | Action | Cryptographic Operation | Security Property |
|---|---|---|---|
| 1 | Voter registers with face + NID | FaceNet → PCA → Hash → ECC Key Derivation | Biometric non-transferability |
| 2 | Public key added to global ring | Blockchain `putState(GLOBAL_RING)` | Immutable registration |
| 3 | QR credential issued | AES-256-CBC encryption of embedding + salt | Credential confidentiality |
| 4 | Admin creates ballot | In-memory ballot with options + time bounds | — |
| 5 | Encryption keypair generated | ElGamal KeyGen over secp256k1 | Tallying privacy |
| 6 | Voter authenticates | QR decrypt → Face comparison (cosine > 0.50) | Eligibility verification |
| 7 | Private key recovered | $k = H(h_{face} \| salt) \mod n$ | Deterministic, non-stored key |
| 8 | Ring signature generated | Liu-Wei-Wong LRS.Sign | Voter anonymity |
| 9 | Vote encrypted | Exponential ElGamal Enc | Individual vote privacy |
| 10 | Vote submitted to blockchain | Chaincode `castVote()` | Immutability + link tag check |
| 11 | Double-vote check | `LINK_TAG` existence lookup | Uniqueness (one-person-one-vote) |
| 12 | Homomorphic tally computed | $\bigoplus_j \text{Enc}(v_j)$ → Decrypt → BSGS | Privacy-preserving tallying |
| 13 | Tally verified | Recompute aggregate ciphertexts from public data | Public verifiability |

---

## 11. Comparative Analysis — Our System vs. Existing Work

### 11.1. Feature Comparison Matrix

| Feature | Our System | Open Vote Network | Voatz | MACI | LRS-Fabric (Panja) | Fingerprint+ZKP (IEEE) | Facial+SC (2024) |
|---|---|---|---|---|---|---|---|
| **Blockchain Type** | Permissioned (Fabric) | Public (Ethereum) | Permissioned (custom) | Public (Ethereum) | Permissioned (Fabric) | Permissioned | Public/Private |
| **Authentication** | Face Biometric + QR | Ethereum keys | Mobile biometric (Jumio) | Ethereum keys | PKI certificates | Fingerprint | Face recognition |
| **Non-Transferable Credential** | ✅ (face-derived key) | ❌ | ✅ (partial — Jumio) | ❌ | ❌ | ✅ | ✅ |
| **Voter Anonymity (ZKP)** | ✅ LRS (ring sig) | ✅ (self-tallying ZKP) | ❌ | ✅ (zk-SNARK) | ✅ LRS | ❌ (unclear) | ❌ |
| **Double-Vote Prevention** | ✅ Link Tag (crypto) | ✅ (protocol level) | ❌ (server-side check) | ✅ (key change mechanism) | ✅ Link Tag | ❌ (unclear) | ❌ (server-side) |
| **Homomorphic Tallying** | ✅ Exp. ElGamal | ❌ (self-tallying) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Vote Validity Proof** | ✅ Chaum-Pedersen | ✅ | ❌ | ✅ (zk-SNARK) | ❌ | ❌ | ❌ |
| **No Trusted Setup** | ✅ | ✅ | ❌ | ❌ (trusted setup) | ✅ | ❌ (unclear) | ❌ |
| **Biometric Data On-Chain** | ❌ (never stored) | N/A | ❌ (Jumio server) | N/A | N/A | ⚠️ (implementation-dependent) | ❌ |
| **Scalability** | $O(n)$ per vote | $O(n^2)$ total | Centralised | Gas-limited | $O(n)$ per vote | Unclear | Dependent |
| **Gas/Transaction Cost** | Zero (Fabric) | High (~$0.70+) | N/A (proprietary) | High | Zero (Fabric) | Low | Variable |
| **Open Source** | ✅ | ✅ | ❌ | ✅ | Partial | ❌ | ❌ |

### 11.2. Key Differentiators of Our System

No existing system in the literature combines **all five** of the following capabilities in a single architecture:

1. **Face Biometric → Elliptic Curve Key Derivation**: Unlike systems that use biometrics merely as an access gate (Voatz, Facial+SC), our system **mathematically binds** the face embedding to the cryptographic private key via $k = H(h_{face} \| salt) \mod n$. This makes the key non-transferable and non-forgeable.

2. **Linkable Ring Signatures for Anonymous + Unique Voting**: Unlike plain ring signatures (which allow repeated anonymous signing) or simple digital signatures (which reveal identity), LRS provides **both anonymity and uniqueness** in a single primitive.

3. **Homomorphic Tallying on a Permissioned Blockchain**: No existing LRS-based voting system on Hyperledger Fabric implements homomorphic encryption for tallying. Panja et al. (2022) store votes in plaintext. Our system ensures the tallying authority learns **only the final count**, never individual votes.

4. **Zero-Knowledge Vote Validity Proofs**: The Disjunctive Chaum-Pedersen proof ensures each encrypted vote contains exactly 0 or 1, preventing ballot stuffing — a gap absent in most LRS-based and biometric-based voting systems.

5. **No Trusted Setup or Trusted Coordinator**: Unlike zk-SNARK-based systems (MACI, Syed et al.), our system uses standard discrete-log-based proofs that require no trusted setup ceremony, eliminating the "toxic waste" risk.

---

## 12. Honest Assessment — Journal Publication Impact

### 12.1. Novelty Analysis

| Aspect | Assessment |
|---|---|
| **Core novelty** | The **integration** of face-biometric-derived ECC keys with Linkable Ring Signatures and Exponential ElGamal homomorphic encryption on Hyperledger Fabric is genuinely **not found in existing literature** as a single unified system. |
| **Individual components** | Each individual component (FaceNet, LRS, ElGamal, Hyperledger Fabric) is well-established. The novelty lies in **their combination and the specific protocol design** for how they interact. |
| **Novelty type** | This is a **systems/integration novelty** rather than a fundamental cryptographic breakthrough. This is typical and acceptable for applied cryptography and information security journals. |

### 12.2. Strengths for Publication

1. **Clear research gap**: The literature review demonstrates that no existing system simultaneously provides biometric non-transferability, ring signature anonymity, homomorphic tallying, and blockchain immutability. This is a defensible contribution.
2. **Working implementation**: Having a full prototype (chaincode + API + biometric service) significantly strengthens the paper vs. purely theoretical proposals.
3. **Interdisciplinary appeal**: The paper spans blockchain, cryptography, biometrics, and machine learning — attractive to a broad audience.
4. **Timely topic**: Blockchain voting is an active research area with growing interest post-COVID.
5. **Formal security analysis**: The inclusion of security proofs (Theorems 5.1, 5.2) and reduction arguments elevates the paper above many similar proposals.

### 12.3. Weaknesses / Challenges for Publication (Honest Assessment)

1. **No formal security proof for the full protocol**: While individual components have known security proofs, a **composability proof** (showing that combining LRS + ElGamal + biometrics together doesn't introduce new attack vectors) would significantly strengthen the paper. Consider using the **Universal Composability (UC)** framework.
2. **No large-scale performance evaluation**: Reviewers will ask for benchmarks: How long does signing take with $n = 100, 1000, 10000$ ring members? What is the end-to-end latency? TPS (transactions per second) on Fabric? You should include a **Performance Evaluation** section with measured results.
3. **Biometric key stability not empirically validated**: The paper should include experimental evidence showing that the same person's face consistently produces the same private key across different lighting, angles, and sessions (after PCA). Report **False Acceptance Rate (FAR)** and **False Rejection Rate (FRR)**.
4. **Limited comparison with related work**: The comparison should include **quantitative** numbers (signature sizes in bytes, computation time in ms) alongside the feature matrix.
5. **Ring size is $O(n)$**: This is a known limitation. Reviewers may ask why you didn't use sub-linear techniques (e.g., Triptych, Arcturus, or Raptor from Monero Research Lab). You should explicitly discuss this as a trade-off between implementation complexity and proof transparency.

### 12.4. Suggested Target Venues

| Venue | Type | Relevance | Difficulty |
|---|---|---|---|
| **IEEE Access** | Journal | Applied systems, interdisciplinary | Moderate (high acceptance rate ~30%) |
| **IEEE Transactions on Information Forensics and Security** | Journal | Cryptographic protocols, biometrics | High (top-tier, ~15% acceptance) |
| **Computers & Security (Elsevier)** | Journal | Applied security systems | Moderate |
| **Journal of Information Security and Applications (Elsevier)** | Journal | Practical security systems | Moderate |
| **Future Generation Computer Systems (Elsevier)** | Journal | Distributed systems, blockchain | Moderate |
| **Blockchain: Research and Applications (Elsevier)** | Journal | Blockchain-specific research | Moderate-Low |
| **ACSAC / ESORICS / ACM CCS** | Conference | Top security conferences | Very High |
| **CBT (International Workshop on Cryptocurrencies and Blockchain Technology)** | Workshop | Blockchain security | Moderate-Low |

> **Realistic recommendation**: For a first publication, target **IEEE Access**, **Journal of Information Security and Applications**, or **Blockchain: Research and Applications**. These venues value working implementations with clear contributions. To target higher-tier venues (IEEE TIFS, CCS), you would need to add **formal composability proofs** and **comprehensive performance benchmarking**.

### 12.5. Suggestions to Strengthen the Paper

1. **Add a Performance Evaluation section** with benchmarks:
   - Ring signature generation time vs. ring size
   - Homomorphic tally computation time vs. number of votes
   - Face embedding extraction + comparison latency
   - Hyperledger Fabric TPS under voting workload
2. **Report biometric accuracy metrics**: FAR, FRR, EER (Equal Error Rate) for your FaceNet+PCA pipeline at different thresholds.
3. **Add formal threat model diagram** (e.g., using Dolev-Yao or network adversary model).
4. **Discuss UC-composability** or at least argue informally why the composition is secure.
5. **Compare signature sizes and computation times** quantitatively with at least 3 related systems.

---

## 13. Limitations and Future Work

| # | Limitation | Impact | Mitigation / Future Work |
|---|---|---|---|
| 1 | **Ring size scalability** — Signature size grows $O(n)$ | Large elections produce large signatures (e.g., 1000 voters → ~32KB signature) | Explore sub-linear ring signatures (Triptych, Arcturus) or zk-SNARKs for constant-size proofs |
| 2 | **Single-server ElGamal key** — Private key stored in memory on one server | Single point of trust for tallying privacy | Implement $(t, n)$ threshold decryption with Shamir's Secret Sharing among multiple trustees |
| 3 | **Biometric drift** — Face changes over time (aging, surgery, facial hair) | Key derivation may produce different keys after significant time | Periodic re-enrollment; investigate fuzzy extractors or error-correcting codes for biometric keys |
| 4 | **Coercion resistance** — Voter can be forced to vote under observation | System provides receipt-freeness but not full coercion resistance | Add deniable re-voting or panic passwords that cast a decoy vote |
| 5 | **No formal composability proof** — Individual components are secure, but composition not formally verified | Potential for unforeseen interaction vulnerabilities | Conduct analysis under the Universal Composability (UC) framework |
| 6 | **In-memory ballot storage** — Ballots managed in-memory on API server | Server restart loses ballot state | Move ballot management to the blockchain or persistent database |
| 7 | **PCA model dependency** — PCA projection matrix is fixed at training time | Poor generalisation to populations not represented in training data | Retrain PCA on target population; explore adaptive embedding techniques |
| 8 | **QR code security** — AES-CBC encryption with password-derived key | Brute-forceable if password is weak | Enforce strong password policies; consider PBKDF2/Argon2 for key derivation |
| 9 | **No formal verification of chaincode** — Smart contract logic not mathematically verified | Potential for logical bugs (e.g., off-by-one in vote counting) | Apply formal verification using TLA+, Coq, or Hyperledger Fabric's formal methods tools |
