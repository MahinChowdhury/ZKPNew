# System Map — BBZKV (as actually implemented)

Snapshot taken 2026-10-30. This file describes what the **code does**, not what the paper claims.
Where the two differ, see the "Paper says / code does" table at the bottom and [FINDINGS.md](FINDINGS.md).

## Components

| Layer | Path | Role |
|---|---|---|
| Biometric service (Python, FastAPI :8000) | `model/app.py` | MediaPipe BlazeFace crop → DeepFace **Facenet-128** (`detector_backend="skip"`, no landmark alignment) → **PCA-64** (`pca_model_64d.pkl`, sklearn 1.6.1). Iris: integro-differential segmentation → Log-Gabor phase code + noise mask. Thresholds: cosine 0.50, Hamming 0.478. |
| Encodings research code | `model/sopq.py`, `model/gbsm.py` | SOPQ = regularized Fisher/LDA projection + QR orthonormalization (not used by `app.py`). GBSM = stability-ranked bit selection. |
| Accuracy eval | `model/biometric_accuracy_eval.py` | LFW / CelebA / CASIA-Iris-Thousand(/Interval) EER, ROC, fairness. Imports `app` as the pipeline. |
| API gateway (Node/Express :3000) | `api-server/server.js`, `routes/{vote,ballot,tally}.js` | **Does everything for the voter**: register, keygen, credential storage, proof generation, ElGamal encryption, Fabric submission. |
| SNARK helpers | `api-server/crypto/snark.js`, `crypto/iris-snark.js` | Scaling (σ=1e6), Poseidon, Merkle tree build, witness + proving (GPU ICICLE → rapidsnark → snarkjs fallback). |
| Homomorphic tally | `api-server/crypto/homomorphic.js`, `routes/tally.js` | Exponential ElGamal on secp256k1, disjunctive Chaum–Pedersen, BSGS. **Single key per ballot held in server memory** (`ballotKeys` Map). |
| Legacy | `api-server/crypto/lrs.js` | Linkable ring signatures — only imported by `attacks/*.js`, not by the live vote path. |
| Circuits | `api-server/circuits/face_auth.circom`, `iris_auth.circom` | Groth16/BN254, Circom 2.1.6, depth-20 Merkle. Build: `build_circuit.sh`, `build_iris_circuit.sh` (Hermez ptau + single phase-2 contribution). |
| Chaincode (Fabric) | `chaincode/identity/lib/identityContract.js` | `register`, `registerIris`, `castVote` (on-chain `snarkjs.groth16.verify`), `hasVoted`, results/queries. |
| Frontend (React/Vite) | `frontend/src/*.jsx` | Register / VoteCasting / BallotManagement / TallyResult; uploads images + password to the API. |
| Benchmarks & attacks | `api-server/benchmark/*`, `api-server/attacks/*`, `api-server/compareBenchmarks/*` | JSON results + plots used for paper figures. |
| Paper | `IEEE_Transaction_Mahin/ieee-paper.tex` (867 lines), `supplementary-material.tex` (501), `References.bib`, cover letters for TIFS and TDSC. |

## Face circuit (`face_auth.circom`, `FaceAuth(64, 20)`)

Public: `faceHash, merkleRoot, nullifier, electionId, threshold_sq_num, threshold_sq_den` (+ output `valid`, which is publicSignals[0]).
Private: `embedding[64]` (live), `registeredEmbedding[64]`, `salt`, `secretKey`, `pathElements[20]`, `pathIndices[20]`.

1. `faceHash == Poseidon2(PoseidonChunked8x8(registeredEmbedding), salt)`
2. `leaf = Poseidon2(faceHash, secretKey)`; Merkle path via circomlib `Switcher` (**no booleanity check on `pathIndices`**)
3. `nullifier == Poseidon2(secretKey, electionId)`
4. `dot² · den ≥ num · ‖a‖² · ‖b‖²` via `GreaterEqThan(128)` (**no range checks on inputs, sign of dot lost**)

Iris circuit is the same shape with 256 boolean bits, Hamming `LessThan(9)`, public `hammingThreshold`.

## Current data flow (after the C5 fix, 2026-10-30)

**Registration:**
1. Browser → `model/app.py` (direct, CORS) → template.
2. `voterClient.createCredential` generates salt and `sk` and computes `C` locally.
3. `POST /api/v1/register {nidNumber, biometricMode, commitment}` → chaincode `register` (registrar MSP only).
4. The voter downloads `voter-credential-<mode>.json` (PBKDF2-600k + AES-GCM).

**Vote:**
1. Browser opens the credential with the password and gets a live template from `model/app.py`.
2. It fetches the public data: `GET /ballot/:id/chain` (pk, numOptions, electionId) and `GET /commitments`.
3. `voterClient.prepareVote` computes the nullifier, then `encryptBallot` (Σ-OR + sum proof), then `voteBinding`, then snarkjs `fullProve` (WASM/zkey from `GET /circuits/*`).
4. `POST /api/v1/vote {proof, publicSignals, nullifier, encryptedBallot, ballotId, biometricMode}` → relay → `castVote`. The chaincode checks:
   - Groth16 proof (public signals `[valid, root, nullifier, electionId, voteBinding]`)
   - Merkle root, and `electionId` against the on-chain ballot
   - `voteBinding`, every Σ-OR proof and the sum proof
   - nullifier unused

**Tally:** `POST /tally/setup/:id` publishes the pk on-chain (write-once). `compute` re-verifies every ballot proof, aggregates, decrypts with the single trustee key (C15 still open) and runs BSGS.

The two sections below describe the **original** flow audited on 2026-10-30, kept for the paper's before/after discussion.

## Data flow — registration (`POST /api/v1/register`) — ORIGINAL

Browser sends NID, password, and image → server computes `nidHash = SHA256(NID)` and a random salt → Python service returns the embedding → **server** generates `sk` (`crypto.randomBytes`), `faceHash`, and `C = H(faceHash, sk)` → `C` goes on-chain under `nidHash` → **server** stores `{faceHash, sk, C}` in `credential-store.js`, encrypted under the password → the voter receives a QR code holding `AES(pwd, {nidHash, salt, faceEmbedding})`.

## Data flow — vote (`POST /api/v1/vote`) — ORIGINAL

Browser sends the QR code, password, live image, **plaintext `voteChoice`**, and ballotId → server decrypts the QR and loads `sk` → live embedding → Groth16 proof, threshold **16/100 (τ=0.4)** hard-coded in `snark.js` → server encrypts the one-hot vote under the ballot pk and builds the Σ-OR proofs → `castVote`. Chaincode then:
- verifies Groth16
- checks `valid==1` and that `nullifier` matches its public signal
- rebuilds the Merkle root from all commitments and compares it
- checks only that `electionId` is non-zero
- checks the nullifier is unused, then stores `{proof, publicSignals, encryptedVote}`

The chaincode does **not** check the thresholds, the electionId↔ballotId binding, the Σ-OR proofs, or that `encryptedVote` exists.

## Tally

`POST /tally/setup/:id` generates an ElGamal keypair in server memory and logs a key prefix. `compute` verifies the Σ-OR proofs (tally time only), aggregates, decrypts with the single key, and runs BSGS. Duress, FODF, threshold DKG, and decryption proofs are **not implemented**.

## Paper says / code does

| Paper claim | Code reality |
|---|---|
| Keys and credentials generated and encrypted client-side | Server generates `sk` and stores the credential bundle |
| Voter encrypts ballot | Server receives the plaintext choice, encrypts it, and logs it (`vote.js:97`) |
| τ = 0.50 (25/100) | Proof uses 16/100 (τ = 0.40); the log line still says 0.5 |
| SOPQ-64 deployed | `app.py` uses PCA-64 |
| Chaincode atomically validates all proofs | Σ-OR proofs not checked on-chain; ciphertext optional and unbound |
| t-of-n threshold DKG for TA | Single in-memory key |
| Deniable duress / FODF | Not implemented |
| Iris + Face | Iris EER ≈ chance; soundness scoped to face only |
