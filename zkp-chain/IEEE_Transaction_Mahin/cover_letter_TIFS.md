# Cover Letter for Submission to IEEE Transactions on Information Forensics and Security (T-IFS)

**Date:** [SUBMISSION DATE]  
**To:** Editor-in-Chief, *IEEE Transactions on Information Forensics and Security*  
**From:**  
Mahin R. Chowdhury (Corresponding Author)  
Department of Computer Science and Engineering  
Khulna University of Engineering & Technology (KUET)  
Khulna-9203, Bangladesh  
Email: `mahin@kuet.ac.bd`

---

### Subject: Resubmission under IEEE SPS Policy 6.16 — Manuscript [PRIOR MANUSCRIPT ID]

**Title:** *Constraint-Aware Zero-Knowledge Face Eligibility Against Lookalike Attackers: Sound Circuits and Attested Capture for Decentralized Voting*  
**Authors:** Mahin R. Chowdhury, K. M. Azharul Hasan, and Arpita Das

Dear Editor-in-Chief and Editorial Board,

We submit the manuscript **"Constraint-Aware Zero-Knowledge Face Eligibility Against Lookalike Attackers: Sound Circuits and Attested Capture for Decentralized Voting"** for consideration as a Regular Paper in *IEEE Transactions on Information Forensics and Security*.

The paper addresses a gap between biometric template protection and zero-knowledge proofs. A zk-SNARK can show that a live face sample matches an enrolled template without revealing either. In practice, however, such a circuit is only as sound as its weakest constraint, and the live sample is a free witness that the prover chooses. We present a face-eligibility circuit that is sound against adversarial witnesses, bind every live sample in-circuit to a registered capture device, and deploy the circuit in a decentralized voting system on Hyperledger Fabric.

### Disclosure under SPS Policy 6.16

An earlier version of this work was submitted to [PRIOR JOURNAL] as manuscript [PRIOR MANUSCRIPT ID] on [PRIOR SUBMISSION DATE]. We treat this submission as our one permitted resubmission. Following the reviewers' feedback, we re-audited the implementation and rewrote the paper. The main changes are:

- **Circuit and protocol soundness.** The audit found weaknesses that the earlier version did not report: unconstrained Merkle direction bits, a prover-chosen threshold, an election identifier not bound to the ballot, a public per-voter biometric hash, unranged embedding coordinates, and ciphertexts not bound to the proof. Each is now fixed, and each fix is backed by an attack test against the deployed chaincode.
- **Security model.** We replaced the earlier composability claim with game-based theorems for eligibility, one vote per credential, ballot integrity, ballot privacy and verifiability. We now state explicitly that we do not claim UC security. The deniable-duress mechanism, which was not implemented, has been removed.
- **Trust architecture.** Key generation, proving and ballot encryption now run on the voter's own device. A single tally key has been replaced by a t-of-n Pedersen DKG whose key the chaincode derives, and the chaincode verifies the threshold tally itself.
- **Biometric evaluation.** The deployed encoding is now ArcFace with a 128-D PCA projection. Its operating point is selected on validation identities only, against a stated lookalike attacker, and every EER is reported with a bootstrap confidence interval. Our earlier proposed encodings (the SOPQ face projection and the GBSM iris bit selection) did not beat simple baselines under this evaluation, and we report them as negative results.

### Contributions

1. **Constraint-aware face encoding.** Per-coordinate range checks, which soundness requires, dominate the comparator, so circuit cost is set by the template dimension rather than by the choice of metric. Because a face is public, once an attacker holds a stolen credential we set the threshold against a lookalike found by screening photos offline, not only a random impostor. A PCA sweep of 512-D ArcFace embeddings against measured circuit cost, with the operating point chosen on validation identities against an attacker who screens 100 candidates, selects 128-D at τ = 0.35. On test data this gives 0.22% EER on LFW (4.02% on CelebA), 0.60% FRR, and 0.85% success for that attacker, in 32,668 constraints, which fit a 2^15 proving domain. The usual zero-effort rule would have selected a point that the same attacker beats 9% of the time.
2. **Attested, sound eligibility circuit.** The live sample is bound in-circuit to a registered capture device by an EdDSA signature over the sample, the election and a hiding commitment to the nullifier, so the device does not learn which ballot it enabled.
3. **Security tied to the implementation.** Every premise of the game-based theorems is a concrete constraint or chaincode check. An attack suite makes each premise executable: each of 13 attacks succeeds when its check is removed (12 executed against the chaincode without the checks; the 13th, decryption under a single tally key, holds by construction), and all 26 attacks are rejected by the full system.
4. **Evaluation.** LFW and CelebA accuracy with confidence intervals and paired tests, cross-age and cross-pose rejection rates on CALFW and CPLFW, a gender-fairness measurement, a template-inversion analysis, voter-side proving in 1.7 s with the WASM prover the browser client uses, chaincode verification in 49 ms independent of electorate size, and a 40-voter election on a live two-organization Fabric network.

### Scope and stated limitations

We have tried to keep every claim within what we measured:

- **Iris.** Iris is implemented with the same circuits but is excluded from the soundness claim, because classical segmentation keeps its accuracy near chance.
- **Liveness.** Sensor attestation proves which registered device captured a sample, not that the sample is live. Presentation attack detection is a stated requirement on the capture device and is not evaluated.
- **Age and pose.** The threshold that contains lookalikes rejects 9.6% of genuine voters across an age gap (CALFW) and 13.8% across pose (CPLFW), so a deployment needs periodic re-enrollment and frontal capture.
- **Enrollment.** Enrollment is supervised by the registration authority rather than attested.
- **Coercion.** Receipt-freeness and coercion resistance are out of scope, and we give a short impossibility argument for JCJ-style deniability under observed biometric capture.

### Compliance with T-IFS format and page limits

- **Main manuscript:** 12 pages in the IEEEtran 10pt two-column journal format, including figures, tables and references, within the 13-page limit.
- **Supplementary material:** 6 pages. It contains the full security proofs, circuit signal tables, per-sub-circuit constraint counts, the iris negative result and the face-model comparison.
- **Subject areas:** Biometrics, zero-knowledge proofs, biometric template protection, arithmetic circuits, privacy-preserving authentication, electronic voting.

This manuscript is original work and is not under consideration for publication elsewhere. All authors have reviewed and approved it for submission to *IEEE Transactions on Information Forensics and Security*.

Thank you for your time and consideration.

Sincerely,

**Mahin R. Chowdhury** (Corresponding Author)  
Department of Computer Science and Engineering  
Khulna University of Engineering & Technology (KUET), Bangladesh  
Email: `mahin@kuet.ac.bd`
