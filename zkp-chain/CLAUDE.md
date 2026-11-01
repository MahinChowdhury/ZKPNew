# zkp-chain

Biometric (face/iris) ZK-SNARK e-voting prototype on Hyperledger Fabric, plus the IEEE journal paper describing it (`IEEE_Transaction_Mahin/`).

## Active work: paper revision for IEEE TIFS

Read these before doing anything on the paper or the protocol:
- `docs/revision/REVISION_PLAN.md` — phased plan, checkboxes, decision log (update it as work lands)
- `docs/revision/FINDINGS.md` — every known issue with an ID (C*, B*) and status
- `docs/revision/SYSTEM_MAP.md` — what the code actually does vs. what the paper claims

Rules for this repo:
- **The paper is `IEEE_Transaction_Mahin/ieee-paper.tex` (+ `supplementary-material.tex`). The compiled main paper must stay at 13 pages or fewer (IEEE TIFS limit).** Check the page count after every paper edit with `bash IEEE_Transaction_Mahin/build.sh` (compiles into `build/`, fails if over 13 pages); anything added must be paid for by a cut or a move to the supplement in the same change.
- Circuits are compiled with `circom --O2`; the attack suite (`api-server/attacks/soundness/`) must stay at 0 vulnerable after any protocol change.
- Any circuit change (`api-server/circuits/*.circom`) requires a recompile, a new zkey, and copying the new verification keys into `chaincode/identity/lib/`.
- Every soundness fix needs an attack test that fails before the fix and is rejected after it.
- Numbers in the paper must come from a generated file, never typed by hand (Phase 5 of the plan).
