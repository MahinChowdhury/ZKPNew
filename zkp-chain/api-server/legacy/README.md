# legacy/ — retired pre-revision code

Nothing here runs against the current protocol, and none of it backs a
number in the paper. It is kept for history only; relative imports inside
these files point at their old locations and are not maintained.

Why it was retired: before the 2026-10 revision the API server generated
the voter's key, received the plaintext choice and built the proof itself,
with a QR credential, a 64-D chunk-hashed template and no capture
attestation. The current client proves in the browser
(`frontend/src/crypto/voterClient.js`) over a packed 128-D template with an
attested live sample, so these scripts no longer match the circuits.

| Retired | Use instead |
|---|---|
| `test_snark.js`, `dump_proof.js` | `node test_snark.mjs [--dump]` |
| `test_qr_*.js`, `test_circom_input.js`, `test_poseidon_chunk.js`, `test_circomlibjs_limit.js`, `test_fe_negative.js` | one-off experiments for the old QR flow and chunked hash; no replacement needed |
| `benchmark/zksnark_benchmark.js`, `e2e_benchmark.js`, `e2e_scalability_benchmark.js`, their plots and results | `benchmark/bench_client.mjs` (client, chaincode, scaling, tally) |
| `benchmark/concurrent_load_test.js` | `benchmark/bench_fabric.mjs` (live network, concurrent castVote) |
| `benchmark/run_all_benchmarks_and_plots.js`, `compareBenchmarks/` | `IEEE_Transaction_Mahin/build.sh` (numbers from result JSONs via `make_numbers.py`) |
| `attacks/0*_*.js`, `run_all_attacks.js`, `benchmark/attack_benchmark.js` (ring-signature era, FINDINGS C16) | `attacks/soundness/run_soundness_attacks.js` |
| `credential-store.js` (server-held credentials) | sealed credential file, `voterClient.sealCredential` |
| `crypto/lrs.js` (linkable ring signatures) | nullifiers in the face/iris circuits |
| server-side provers in `crypto/snark.js` / `crypto/iris-snark.js` (removed; last copy in the revision backup) | `voterClient.prepareVote` |
