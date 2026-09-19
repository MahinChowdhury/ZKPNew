# Submission Cover Letter

**To:**  
Editor-in-Chief  
*IEEE Transactions on Dependable and Secure Computing (TDSC)*  

**Date:** September 12, 2026  

**Subject:** Submission of Original Research Manuscript — *Composable Security for Biometric-Bound Zero-Knowledge Voting: A Decentralized Architecture with Face and Iris Case Studies*

**Authors:**  
- **Mahin R. Chowdhury** (Student Member, IEEE) — Department of Computer Science and Engineering, Khulna University of Engineering & Technology, Bangladesh (`mahin@cse.kuet.ac.bd`)
- **K. M. Azharul Hasan** (Member, IEEE) — Department of Computer Science and Engineering, Khulna University of Engineering & Technology, Bangladesh (`azharul@cse.kuet.ac.bd`)
- **Arpita Das** (Student Member, IEEE) — Department of Computer Science and Engineering, Khulna University of Engineering & Technology, Bangladesh (`arpita@cse.kuet.ac.bd`)

---

Dear Editor-in-Chief and Editorial Board,

We are pleased to submit our original research manuscript entitled **"Composable Security for Biometric-Bound Zero-Knowledge Voting: A Decentralized Architecture with Face and Iris Case Studies"** for consideration as a Regular Paper in the *IEEE Transactions on Dependable and Secure Computing (TDSC)*.

### 1. Scope and Alignment with IEEE TDSC
The design of dependable, coercion-resistant, and verifiable electronic voting systems remains an open challenge at the intersection of cryptography, distributed consensus, and identity security. While decentralized state machines eliminate single points of electoral failure, existing blockchain voting protocols rely either on centralized credential authorities (re-introducing administrative single points of failure) or anonymous identity tokens that fail to enforce the fundamental democratic principle of "one-person-one-vote" against Sybil impersonation. 

Our manuscript directly addresses the core mission of IEEE TDSC by introducing **BBZKV**, a decentralized, end-to-end verifiable (E2EV) e-voting architecture that cryptographically binds biometric identity to zero-knowledge voting protocols while maintaining provable anonymity, universal verifiability, and modular composability.

### 2. Primary Scientific Contributions
Specifically, this manuscript contributes:
1. **The $(\delta, \mathsf{FAR}_\delta)$-Approximate Universal Composability (UC) Electoral Framework:** We bridge the foundational tension between physical biometric tolerance ($\mathsf{FAR}_\delta > 0$) and cryptographic simulation ($\mathsf{negl}(\lambda)$). By proving that classical UC fails catastrophically under biometric inputs due to non-negligible environmental distinguishing advantage $\Omega(\mathsf{FAR}_\delta)$, we formulate a rigorous approximate UC model across three composed sub-functionalities ($\mathcal{F}_{\mathsf{reg}}$, $\mathcal{F}_{\mathsf{vote}}$, $\mathcal{F}_{\mathsf{tally}}$), establishing provable security bounded by physical false acceptance ($\leq 0.050\%$).
2. **Characterization of the Biometric Coercion Frontier & Deniable Duress Protocol:** We resolve the fundamental open dilemma between physical biometric non-transferability and voter coercion. We formally prove that observed biometric capture fundamentally precludes classical JCJ/Civitas-style deniability modulo physical false acceptances ($\leq \mathsf{FAR}_\delta$, Proposition~V.10), and design a constructive Deniable Duress Nullifier protocol that guarantees computational receipt-freeness under remote coercion through zero-knowledge tally neutralization.
3. **Deterministic, Tight Cryptographic Reductions:** We establish concrete and asymptotic tightness for all cryptographic terms in our simulation bound. In particular, we prove a tight $1$-to-$1$ reduction for Merkle-tree binding ($\mathbf{Adv}^{\mathsf{CR}}_{\mathsf{Pos}}(\lambda)$) via deterministic $\mathcal{O}(L)$ path collision inspection, eliminating factor-$L$ reduction loss.
4. **Rigorous Circuit-Level Modality Comparative Analysis:** We engineer, synthesize, and benchmark complete electoral arithmetic circuits for 256-bit iris templates versus 64-dimensional facial embeddings. We identify that iris matching reduces sub-circuit constraints by 13.3% (8,224 vs. 9,484 R1CS) and accelerates witness generation by $1.66\times$ (55.9 vs. 92.7\,ms) due to linear Hamming distance arithmetic, whereas facial embeddings preserve commodity accessibility.
5. **Comprehensive System Scalability Across Five Orders of Magnitude:** Rather than evaluating on a toy testbed, we demonstrate system scalability across $N \in \{10, 10^2, 10^3, 10^4, 10^5\}$ enrolled voters under a fixed depth-20 Sparse Merkle Tree ($2^{20} \approx 1.04 \times 10^6$ leaf capacity, accommodating $2^{19} = 524{,}288$ physical voters under dual-leaf enrollment), empirically verifying $\mathcal{O}(1)$ proving ($\approx 450$--$510$\,ms) and verification ($\approx 34$--$37$\,ms) invariance. Under high-concurrency stress testing with 1,000 simultaneous client requests, the ingestion pipeline sustains 297.66 TPS with mean response latency of $1{,}689.9 \pm 962.4$\,ms. Offline Baby-Step Giant-Step homomorphic tallying scales to $N=10^6$ ballots in under 0.5\,s for 5 candidates.
6. **On-Chain Trust-Boundary Hardening and Trade-Off Analysis:** We analyze the architectural risks of gateway-delegated proof verification, showing that direct peer invocation can bypass unhardened contracts (100% exploit success rate), and demonstrate that in-situ Groth16 pairing verification in smart contracts eliminates relayer trust with only $29.2$--$29.4$\,ms pairing overhead.

---

### 3. Prior Review History and Substantive Revisions Disclosure
In accordance with IEEE author guidelines and our commitment to academic transparency, we disclose that an earlier, preliminary iteration of this work was reviewed at the *IEEE Transactions on Information Forensics and Security (T-IFS)*. 

Rather than executing cosmetic revisions, our research group spent several months performing a thorough, top-to-bottom theoretical overhaul and expansive empirical extension to resolve the core concerns raised during that review cycle. Specifically:
- **Formal Coercion Resistance Impossibility & Protocol Formulation:** We resolved the open challenge of biometric coercion by formalizing the impossibility of JCJ deniability under observed physical capture and formulating an achievable Deniable Duress Protocol for remote coercion.
- **Overhaul of Theoretical Soundness & UC Model:** We formulated a complete $(\delta, \mathsf{FAR}_\delta)$-approximate Universal Composability proof with an explicit 4-hybrid simulator, proving composability across registration, voting, and tallying sub-functionalities.
- **Tightening of Cryptographic Bounds:** We replaced the probabilistic guessing reduction in the Merkle-binding lemma with a deterministic $\mathcal{O}(L)$ path collision extraction proof, removing factor-$L$ ($=20$) slack and ensuring that every cryptographic component is asymptotically tight.
- **Scaling from $N=10$ to $N=100{,}000$ and Concurrency Stress Testing:** We extended the experimental evaluation with full empirical sweeps across five orders of magnitude ($N=10$ to $N=10^5$), 1,000 concurrent client stress tests (297.66 TPS), candidate sweeps up to $m=50$, and BSGS tallying up to $N=10^6$.
- **Hardening and Exploit Demonstration:** We added a concrete attack experiment evaluating the on-chain vs. off-chain verification trade-off and verified in-situ pairing defenses in smart contracts.
- **Strict Formatting and Length Compliance:** The manuscript strictly satisfies the double-column format within the **13-page limit** (main paper) and **6-page limit** (supplementary proofs and reproducible artifacts).

---

### 4. Declarations and Conflict of Interest
- **Originality:** This manuscript represents original work that has not been published elsewhere and is not currently under consideration for publication by any other journal or conference.
- **Author Approval:** All authors have read and approved the final manuscript for submission to *IEEE Transactions on Dependable and Secure Computing*.
- **Data & Artifact Availability:** Full cryptographic circuits, Hyperledger Fabric chaincode, API gateway implementations, and benchmark analysis scripts have been made available for reproducible peer review.
- **Conflicts of Interest:** The authors declare no competing financial or personal interests.

We thank you and the editorial team in advance for your time, consideration, and management of the peer-review process.

Sincerely,

**Mahin R. Chowdhury** (Corresponding Author)  
Department of Computer Science and Engineering  
Khulna University of Engineering & Technology (KUET)  
Khulna-9203, Bangladesh  
Email: `mahin@cse.kuet.ac.bd`
