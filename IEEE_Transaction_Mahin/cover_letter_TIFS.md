# Cover Letter for Submission to IEEE Transactions on Information Forensics and Security (T-IFS)

**Date:** September 12, 2026  
**To:** Editor-in-Chief, *IEEE Transactions on Information Forensics and Security*  
**From:**  
Mahin R. Chowdhury (Corresponding Author)  
Department of Computer Science and Engineering  
Khulna University of Engineering & Technology (KUET)  
Khulna-9203, Bangladesh  
Email: `mahin@kuet.ac.bd`

---

### Subject: Resubmission under IEEE SPS Policy 6.16 — Manuscript TIFS-XXXXX

**Title:** *Constraint-Efficient Biometric Matching in Zero-Knowledge Circuits: A Comparative Study of Face and Iris Verification for Privacy-Preserving Authentication*  
**Authors:** Mahin R. Chowdhury, K. M. Azharul Hasan, and Arpita Das  

Dear Editor-in-Chief and Editorial Board,

We submit our manuscript entitled **"Constraint-Efficient Biometric Matching in Zero-Knowledge Circuits: A Comparative Study of Face and Iris Verification for Privacy-Preserving Authentication"** for consideration as a Regular Paper in the *IEEE Transactions on Information Forensics and Security* (T-IFS).

In accordance with **IEEE Signal Processing Society (SPS) Policy 6.16** regarding the resubmission of manuscripts, we explicitly disclose that an earlier iteration of this project was previously submitted to an IEEE journal under an application-focused electronic voting framing. Based on critical editorial and reviewer feedback emphasizing that the core scientific bottleneck lies in the arithmetic complexity of biometric template matching within zero-knowledge circuits, this manuscript has undergone an extensive, multi-month research overhaul and complete architectural refactoring. We treat this submission as our one permitted resubmission under SPS Policy 6.16.

---

### Key Technical Contributions & Substantial New Content

The current manuscript fundamentally pivots from a distributed system description to an in-depth biometric signal processing, feature quantization, and arithmetic circuit co-design study. Specifically, this revision introduces:

1. **Novel Circuit-Optimized Biometric Encodings (SOPQ and GBSM):**
   - *Face (Continuous Modality):* We develop **Spherical Orthogonal Projection and Quantization (SOPQ)**, which replaces standard unsupervised PCA with angular margin-maximizing orthogonal projection and hyper-spherical unit-norm regularization prior to fixed-point integerization ($\sigma=10^6$). SOPQ achieves an Equal Error Rate (EER) of **1.14%** (compared to 1.85% under standard PCA), recovering **78.0%** of the accuracy lost to downsampling without adding a single non-linear R1CS gate (6,484 constraints).
   - *Iris (Binary Modality):* We develop **Gabor Bit-Salience Masking (GBSM)**, which samples multi-scale 2-D Log-Gabor phase stability scores across reference populations to discard eyelid/eyelash noise. GBSM reduces downsampled 256-bit iris EER from 0.098% to **0.038%** (recovering **69.8%** of lost accuracy) within identical 5,976 linear XOR constraints.

2. **Cross-Dataset Generalization & Complete Multi-Threshold ROC Sweeps:**
   - Rather than reporting single-point operating metrics on developmental sets, we conduct extensive multi-threshold sweeps across four independent public benchmarks: **LFW** and **CelebA** for face biometrics, and **CASIA-Iris-Thousand** and **CASIA-Iris-Interval** for iris biometrics.
   - We demonstrate robust generalization under unconstrained pose, lighting, and pupil dilation, with operational False Acceptance Rates strictly bounded below **0.050%** ($\mathsf{FAR}_{\delta,\mathsf{face}} = 0.050\%$, $\mathsf{FAR}_{\delta,\mathsf{iris}} = 0.047\%$).

3. **Demographic Parity & Fairness Analysis:**
   - We evaluate performance across demographic subgroups (gender and ethnicity metadata in LFW and CelebA across 50,000 genuine/impostor pairs), demonstrating a minimal demographic parity gap ($\Delta\text{EER} \le 0.10\%$) and confirming that finite-field quantization does not induce algorithmic bias.

4. **Presentation Attack Detection (PAD) & Replay Defense:**
   - We evaluate presentation attack vulnerability against printed photo, digital replay, and patterned contact lens attacks. We analyze active challenge-response sensing (APCER $<0.15\%$ at BPCER $=1.0\%$) and prove that in-circuit ephemeral salt binding ($h_i = \mathcal{H}_{\text{chunked}}(\mathbf{b}_i, s_i)$) mathematically precludes credential replay on public ledgers under Poseidon preimage resistance.

5. **Applied Decentralized Deployment Case Study:**
   - We demonstrate real-world applicability by deploying our circuits within an end-to-end decentralized voting architecture on Hyperledger Fabric with composable security guarantees ($(\delta, \mathsf{FAR}_\delta)$-approximate Universal Composability). We demonstrate that embedding Groth16 pairing checks directly in smart contracts eliminates gateway relayer trust with only 31.5~ms overhead, achieving sub-second client proving (170.9--196.3~ms).

---

### Compliance with T-IFS Format and Page Limits

- **Main Manuscript (`ieee-paper.tex`):** Strictly complies with the T-IFS hard limit of **$\le 13$ pages** in standard 10pt IEEEtran double-column journal format (including all figures, tables, and references).
- **Supplementary Material (`supplementary-material.tex`):** Strictly complies with the recommended **$\le 6$ pages** (calibrated to $\approx 5.5$ pages), containing only simulator constructions, formal hybrid reduction proofs, and extended wire signal diagrams.
- **EDICS / Subject Categories:** Biometrics, Zero-Knowledge Proofs, Template Protection, Feature Quantization, Arithmetic Circuits, Privacy-Preserving Authentication, Presentation Attack Detection.

This manuscript represents original work that is not currently under consideration for publication elsewhere. All authors have reviewed and approved the manuscript for submission to *IEEE Transactions on Information Forensics and Security*.

Thank you very much for your time, consideration, and coordination of the peer-review process.

Sincerely,

**Mahin R. Chowdhury** (Corresponding Author)  
Department of Computer Science and Engineering  
Khulna University of Engineering & Technology (KUET), Bangladesh  
Email: `mahin@kuet.ac.bd`
