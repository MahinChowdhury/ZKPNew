// ============================================================
// run_soundness_attacks.js — protocol soundness attack suite
//
// Each attack targets one issue in docs/revision/FINDINGS.md and is
// scored against the CURRENT circuits + REAL chaincode:
//   VULNERABLE — the attack transaction was accepted by castVote
//   PROTECTED  — rejected by witness generation (unsatisfiable
//                constraints) or by a chaincode check
//   OPEN       — VULNERABLE, but a known design gap awaiting a decision
// Attacks with `expect` are harness controls (must behave as stated).
//
// Usage (from api-server/):
//   bash attacks/soundness/build_test_artifacts.sh    # once per circuit change
//   node attacks/soundness/run_soundness_attacks.js
// Exit code = number of VULNERABLE results (0 = all protected).
// Pre-fix results are kept in results/soundness_results_before_fix.json.
// ============================================================

const fs = require("fs");
const path = require("path");
const h = require("./harness");
const homomorphic = require("../../crypto/homomorphic");
const threshold = require("../../crypto/threshold");
const { loadSigner } = require("../../sensor/attest-core");

const BALLOT_A = "ballot-soundness-A";
const BALLOT_B = "ballot-soundness-B";
const NUM_OPTIONS = 2;

// ------------------------------------------------------------
// World: an RA-registered population and two on-chain ballots
// ------------------------------------------------------------
async function setupWorld() {
  const contract = h.loadContract();
  const { ctx, state } = h.makeLedger();
  // One authorised capture device, registered by the RA (face enrollment needs its signature)
  const signer = await loadSigner();
  await h.quiet(() => contract.registerSensor(ctx, signer.publicKey.ax, signer.publicKey.ay));
  const sensorTree = await h.buildTree([await h.H(signer.publicKey.ax, signer.publicKey.ay)], h.SENSOR_LEVELS);
  const sensor = { signer, tree: sensorTree, index: 0 };

  const face = [], iris = [];
  for (let i = 0; i < 4; i++) {
    const v = await h.makeFaceVoter();
    await h.registerFace(contract, ctx, `nid-face-${i}`, v, sensor);
    face.push(v);
  }
  for (let i = 0; i < 4; i++) {
    const v = await h.makeIrisVoter();
    await h.quiet(() => contract.registerIris(ctx, `nid-iris-${i}`, v.commitment.toString()));
    iris.push(v);
  }
  // 2-of-3 trustee key per ballot, generated through the chaincode
  const ballots = {};
  for (const b of [BALLOT_A, BALLOT_B]) ballots[b] = await h.setupBallot(contract, ctx, b, NUM_OPTIONS);
  // Each ballot has its own election key, derived on-chain from the dealings
  const keyOf = (b) => homomorphic.deserializeCiphertext({ c1: ballots[b].record.publicKey, c2: ballots[b].record.publicKey }).c1;
  const keypair = { publicKey: keyOf(BALLOT_A), keyOf };
  const faceTree = await h.buildTree(face.map((v) => v.commitment));
  const irisTree = await h.buildTree(iris.map((v) => v.commitment));


  return { contract, ctx, state, face, iris, faceTree, irisTree, keypair, ballots, sensor };
}

const treeOf = (w, v) => (v.kind === "face" ? w.faceTree : w.irisTree);

function flipBits(bits, n) {
  const out = [...bits];
  for (let i = 0; i < n; i++) out[i] ^= 1;
  return out;
}

const genuineLive = (v) => (v.kind === "face" ? h.noisyCopy(v.template) : flipBits(v.template, 20));

// ------------------------------------------------------------
// Packing alias (A24): PackedCoordHash packs 12 offset coordinates per
// field element in 20-bit slots. Moving 2^20·c out of slot j and c into
// slot j+1 leaves the packed element unchanged, so with c chosen from the
// attacker's face the "registered" template points at the attacker while
// hashing to the victim's digest. Only the coordinate range checks stop it.
// ------------------------------------------------------------
let _alias;
function packingAlias(w) {
  if (_alias) return _alias;
  const victim = w.face[3];
  const attacker = h.randomUnitEmbedding();
  const T = victim.template, n = T.length, MU = 1n << 40n, SLOT = 1n << 20n;
  const div = (a, b) => (a >= 0n ? (a + b / 2n) / b : -((-a + b / 2n) / b));
  const alias = new Array(n);
  for (let e = 0; e * 12 < n; e++) {
    const slots = Math.min(12, n - e * 12);
    let carry = 0n;
    for (let j = 0; j < slots; j++) {
      const i = e * 12 + j;
      const c = j === slots - 1 ? 0n : -div(MU * attacker[i], SLOT);   // last slot of an element cannot carry out
      alias[i] = T[i] - SLOT * c + carry;
      carry = c;
    }
  }
  return (_alias = { victim, attacker, alias });
}

// floor(1000 · cos^2(a, b)) in exact integer arithmetic
function cosineSquaredMilli(a, b) {
  const dot = a.reduce((s, x, i) => s + x * b[i], 0n);
  const na = a.reduce((s, x) => s + x * x, 0n), nb = b.reduce((s, x) => s + x * x, 0n);
  return (1000n * dot * dot) / (na * nb);
}

/**
 * Build and prove a vote the way a (possibly malicious) client would.
 *   opts.live, opts.electionId, opts.path, opts.extra — witness choices
 *   opts.sensor — overrides for the capture attestation (default: the honest device signing `live`)
 *   opts.makeBallot(nullifier) — custom encrypted ballot (default: honest, choice 0)
 * Returns the tx arguments; nothing is submitted.
 */
async function buildVote(w, v, ballotId, opts = {}) {
  const electionId = opts.electionId ?? h.electionIdFor(ballotId);
  const nullifier = h.fieldStr(await h.nullifierOf(v, electionId));
  const enc = opts.makeBallot
    ? opts.makeBallot(nullifier)
    : homomorphic.encryptBallot(w.keypair.keyOf(ballotId), NUM_OPTIONS, opts.choice ?? 0, ballotId, nullifier);
  const vote = await h.proveVote(v, {
    live: opts.live ?? genuineLive(v),
    registered: opts.registered,
    electionId,
    root: treeOf(w, v).root,
    path: opts.path ?? (await h.merklePath(treeOf(w, v), opts.index)),
    voteBinding: homomorphic.computeVoteBinding(ballotId, enc),
    sensor: { ...w.sensor, ...(opts.sensor || {}) },
    extra: opts.extra,
  });
  return { ...vote, enc, ballotId, kind: v.kind };
}

async function submit(w, tx, enc = tx.enc) {
  const res = await h.quiet(() => w.contract.castVote(
    w.ctx,
    JSON.stringify(tx.proof),
    JSON.stringify(tx.publicSignals),
    tx.nullifier,
    enc === null ? "" : JSON.stringify(enc),
    tx.ballotId,
    tx.kind,
  ));
  return JSON.parse(res);
}

function storedVotes(w) {
  return [...w.state.entries()]
    .filter(([k]) => k.startsWith("VOTE_"))
    .map(([, v]) => JSON.parse(v.toString()));
}

// ------------------------------------------------------------
// Merkle forgery: with pathIndices unconstrained, solve the top
// Switcher so an arbitrary leaf hashes to the real root.
//   outL = L + s(R-L) = x,  outR = R - s(R-L) = y
//   => R = x + y - L,  s = (x - L) / (R - L)
// ------------------------------------------------------------
async function forgedPath(tree, leaf) {
  const pathElements = [], pathIndices = [];
  let cur = leaf;
  for (let lvl = 0; lvl < h.LEVELS - 1; lvl++) {
    pathElements.push(tree.z[lvl]);
    pathIndices.push(0n);
    cur = await h.H(cur, tree.z[lvl]);
  }
  const x = tree.node(h.LEVELS - 1, 0), y = tree.node(h.LEVELS - 1, 1);
  const R = h.mod(x + y - cur);
  const s = h.mod((x - cur) * h.modInv(R - cur));
  pathElements.push(R);
  pathIndices.push(s);
  return { pathElements, pathIndices };
}

// ------------------------------------------------------------
// Attacks
// ------------------------------------------------------------
const attacks = [
  {
    id: "BASELINE-face", finding: "-", expect: "ACCEPTED",
    title: "Honest registered face voter casts one vote",
    run: async (w) => submit(w, await buildVote(w, w.face[0], BALLOT_A, { index: 0 })),
  },
  {
    id: "BASELINE-iris", finding: "-", expect: "ACCEPTED",
    title: "Honest registered iris voter casts one vote",
    run: async (w) => submit(w, await buildVote(w, w.iris[0], BALLOT_A, { index: 0 })),
  },
  {
    id: "A1-face", finding: "C1",
    title: "Unregistered attacker forges Merkle membership (face)",
    run: async (w) => {
      const atk = await h.makeFaceVoter(); // never registered
      return submit(w, await buildVote(w, atk, BALLOT_A, {
        live: atk.template, path: await forgedPath(w.faceTree, atk.commitment),
      }));
    },
  },
  {
    id: "A1-iris", finding: "C1",
    title: "Unregistered attacker forges Merkle membership (iris)",
    run: async (w) => {
      const atk = await h.makeIrisVoter();
      return submit(w, await buildVote(w, atk, BALLOT_A, {
        live: atk.template, path: await forgedPath(w.irisTree, atk.commitment),
      }));
    },
  },
  {
    id: "A2-face", finding: "C2",
    title: "Impostor face (random embedding) tries threshold_sq_num = 0",
    run: async (w) => submit(w, await buildVote(w, w.face[1], BALLOT_A, {
      index: 1, live: h.randomUnitEmbedding(), extra: { threshold_sq_num: "0", threshold_sq_den: "100" },
    })),
  },
  {
    id: "A2-iris", finding: "C2",
    title: "Impostor iris (random bits) tries hammingThreshold = 257",
    run: async (w) => submit(w, await buildVote(w, w.iris[1], BALLOT_A, {
      index: 1, live: h.randomBits(), extra: { hammingThreshold: "257" },
    })),
  },
  {
    id: "A2-control", finding: "C2", expect: "REJECTED",
    title: "Control: impostor face with no threshold tampering is rejected",
    run: async (w) => submit(w, await buildVote(w, w.face[1], BALLOT_A, {
      index: 1, live: h.randomUnitEmbedding(),
    })),
  },
  {
    id: "A3", finding: "C3",
    title: "Voter who already voted on ballot A votes again on A with a fresh electionId",
    run: async (w) => {
      const v = w.face[0]; // voted in BASELINE-face
      const r = await submit(w, await buildVote(w, v, BALLOT_A, {
        index: 0, electionId: h.electionIdFor(BALLOT_A) + 1n,
      }));
      r.detail = "second vote by the same credential stored on ballot A";
      return r;
    },
  },
  {
    id: "A4", finding: "C4",
    title: "Votes are linkable across elections (and to NID by the server) via public biometric hash",
    run: async (w) => {
      const v = w.face[2];
      await submit(w, await buildVote(w, v, BALLOT_A, { index: 2 }));
      await submit(w, await buildVote(w, v, BALLOT_B, { index: 2 }));
      const mine = storedVotes(w).filter((x) => x.publicSignals.includes(h.fieldStr(v.bioHash)));
      if (mine.length < 2) {
        throw new Error(`biometric hash appears in ${mine.length} stored votes (needs 2 to link)`);
      }
      return { detail: `${mine.length} on-chain votes carry the same faceHash` };
    },
  },
  {
    id: "A5", finding: "C9",
    title: "Negated template (cos = -1) passes the squared-cosine check",
    run: async (w) => submit(w, await buildVote(w, w.face[3], BALLOT_A, {
      index: 3, live: w.face[3].template.map((x) => -x),
    })),
  },
  {
    id: "A5b", finding: "C9",
    title: "Out-of-range live embedding (template x 2^10, cos = 1) accepted",
    run: async (w) => submit(w, await buildVote(w, w.face[3], BALLOT_B, {
      index: 3, live: w.face[3].template.map((x) => x * 1024n),
    })),
  },
  {
    id: "A24-base", finding: "-", expect: "ACCEPTED",
    title: "Control: a carry-aliased template has the victim's digest and matches the attacker's face",
    run: async (w) => {
      const { victim, attacker, alias } = packingAlias(w);
      if ((await h.faceDigestOf(alias)) !== (await h.faceDigestOf(victim.template))) throw new Error("digests differ");
      const cos = cosineSquaredMilli(attacker, alias);
      if (cos * 10000n < 1225n * 1000n) throw new Error(`cos^2 = ${cos}/1000 below threshold`);
      return { detail: `same digest; cos^2(attacker, alias) = ${Number(cos) / 1000} (needs 0.1225); only the range checks stop it` };
    },
  },
  {
    id: "A24", finding: "packing",
    title: "Stolen credential + attacker's own attested face: open the commitment with a carry-aliased template",
    run: async (w) => {
      const { victim, attacker, alias } = packingAlias(w);
      return submit(w, await buildVote(w, victim, BALLOT_B, { index: 3, live: attacker, registered: alias }));
    },
  },
  {
    id: "A6", finding: "C6",
    title: "Credential holder votes with no live capture: live := registered, self-signed with an unregistered key",
    run: async (w) => {
      const rogue = await loadSigner();
      return submit(w, await buildVote(w, w.iris[2], BALLOT_A, {
        index: 2, live: w.iris[2].template, sensor: { signer: rogue },
      }));
    },
  },
  {
    id: "A13", finding: "C6",
    title: "Credential holder uses the real device on THEIR OWN face, then proves with the victim's template",
    run: async (w) => submit(w, await buildVote(w, w.face[3], BALLOT_A, {
      index: 3, live: w.face[3].template, sensor: { signedTemplate: h.randomUnitEmbedding() },
    })),
  },
  {
    id: "A14", finding: "C6",
    title: "Replay a genuine attestation captured for a different election",
    run: async (w) => submit(w, await buildVote(w, w.iris[2], BALLOT_A, {
      index: 2, sensor: { signElectionId: h.electionIdFor(BALLOT_B) },
    })),
  },
  {
    id: "A15", finding: "C6",
    title: "Replay a genuine attestation bound to another vote session (different nullifier)",
    run: async (w) => submit(w, await buildVote(w, w.iris[2], BALLOT_A, {
      index: 2, sensor: { signNullifier: h.mod(12345n) },
    })),
  },
  {
    id: "A16", finding: "C6",
    title: "Rogue key signs, witness claims the registered device's public key",
    run: async (w) => {
      const rogue = await loadSigner();
      return submit(w, await buildVote(w, w.iris[2], BALLOT_A, {
        index: 2, sensor: { signer: rogue, claimKey: w.sensor.signer.publicKey },
      }));
    },
  },
  {
    id: "A7", finding: "C8",
    title: "Front-runner swaps the ciphertext under an intercepted (proof, nullifier)",
    run: async (w) => {
      const tx = await buildVote(w, w.iris[3], BALLOT_A, { index: 3, choice: 0 });
      const forged = homomorphic.encryptBallot(w.keypair.publicKey, NUM_OPTIONS, 1, BALLOT_A, tx.nullifier);
      let r;
      try {
        r = await submit(w, tx, forged);
      } finally {
        // whatever happened to the attacker, the honest voter must still get in
        try { await submit(w, tx); } catch (e) { if (r) r.detail = `honest voter then rejected: "${e.message}"`; }
      }
      return r;
    },
  },
  {
    id: "A8", finding: "C8",
    title: "Vote accepted with no ciphertext at all",
    run: async (w) => submit(w, await buildVote(w, w.face[1], BALLOT_B, { index: 1 }), null),
  },
  {
    id: "A9", finding: "C8",
    title: "Ciphertext encrypting 5 with a forged Σ-OR proof",
    run: async (w) => submit(w, await buildVote(w, w.iris[1], BALLOT_B, {
      index: 1,
      makeBallot: (nullifier) => {
        const pk = w.keypair.keyOf(BALLOT_B);
        const enc = homomorphic.encryptBallot(pk, NUM_OPTIONS, 0, BALLOT_B, nullifier);
        const c = homomorphic.encrypt(pk, 5);
        const s = homomorphic.serializeCiphertext(c);
        s.validityProof = homomorphic.proveValidVote(pk, c, 1, c.r,
          homomorphic.optionContext(BALLOT_B, nullifier, 0)); // claims v=1
        enc.ciphertexts[0] = s;
        return enc;
      },
    })),
  },
  {
    id: "A11", finding: "C20",
    title: "Overvote: every option encrypts 1, each with a valid Σ-OR proof",
    run: async (w) => submit(w, await buildVote(w, w.iris[2], BALLOT_B, {
      index: 2,
      makeBallot: (nullifier) => {
        const pk = w.keypair.keyOf(BALLOT_B);
        const raw = [], ciphertexts = [];
        for (let j = 0; j < NUM_OPTIONS; j++) {
          const c = homomorphic.encrypt(pk, 1);
          raw.push(c);
          const s = homomorphic.serializeCiphertext(c);
          s.validityProof = homomorphic.proveValidVote(pk, c, 1, c.r, homomorphic.optionContext(BALLOT_B, nullifier, j));
          ciphertexts.push(s);
        }
        const sumProof = homomorphic.proveSumIsOne(pk, raw, raw.map((c) => c.r), homomorphic.sumContext(BALLOT_B, nullifier));
        return { ciphertexts, sumProof };
      },
    })),
  },
  {
    id: "A12", finding: "C19",
    title: "Ballot copying: attacker re-submits another voter's ciphertexts + proofs under own credential",
    run: async (w) => {
      const victim = storedVotes(w).find((x) => x.ballotId === BALLOT_A);
      return submit(w, await buildVote(w, w.face[1], BALLOT_A, {
        index: 1, makeBallot: () => victim.encryptedVote,
      }));
    },
  },
  {
    id: "A25", finding: "C26",
    title: "Credential transfer at enrollment: B enrolls a commitment to A's face under B's NID, then A votes as B",
    run: async (w) => {
      const a = await h.makeFaceVoter();                      // A: the person who will actually vote
      const nidB = `nid-transfer-${Date.now()}`;               // B's identity, checked by the RA
      // Best enrollment evidence the colluders can get: A's face attested at A's own enrollment
      const extra = h.enrollmentProof ? await h.enrollmentProof(a, `nid-of-A-${Date.now()}`, w.sensor) : [];
      await h.quiet(() => w.contract.register(w.ctx, nidB, a.commitment.toString(), ...extra));
      const all = JSON.parse(await h.quiet(() => w.contract.getCommitments(w.ctx))).map((c) => BigInt(c.value ?? c));
      const tree = await h.buildTree(all);
      w.faceTree = tree;   // the on-chain root moved; later attacks must prove against it
      const index = all.findIndex((c) => c === BigInt(a.commitment));
      const electionId = h.electionIdFor(BALLOT_B);
      const nullifier = h.fieldStr(await h.nullifierOf(a, electionId));
      const enc = homomorphic.encryptBallot(w.keypair.keyOf(BALLOT_B), NUM_OPTIONS, 0, BALLOT_B, nullifier);
      const vote = await h.proveVote(a, {
        live: h.noisyCopy(a.template), electionId, root: tree.root, path: await h.merklePath(tree, index),
        voteBinding: homomorphic.computeVoteBinding(BALLOT_B, enc), sensor: w.sensor,
      });
      return submit(w, { ...vote, enc, ballotId: BALLOT_B, kind: "face" });
    },
  },
  {
    id: "A26", finding: "C26",
    title: "Enroll A's face under B's NID with a vote-time kiosk signature (election slot instead of the enrollment domain)",
    run: async (w) => {
      const a = await h.makeFaceVoter();
      const nidB = `nid-votecapture-${Date.now()}`;
      const extra = await h.enrollmentProof(a, nidB, w.sensor, { domain: h.electionIdFor(BALLOT_B) });
      return JSON.parse(await h.quiet(() => w.contract.register(w.ctx, nidB, a.commitment.toString(), ...extra)));
    },
  },
  {
    id: "A27", finding: "C26",
    title: "RA registers a face commitment with no enrollment proof (pre-fix register call)",
    run: async (w) => {
      const a = await h.makeFaceVoter();
      return JSON.parse(await h.quiet(() => w.contract.register(w.ctx, `nid-noproof-${Date.now()}`, a.commitment.toString())));
    },
  },
  {
    id: "A25-control", finding: "-", expect: "ACCEPTED",
    title: "Control: an honest attested enrollment is accepted",
    run: async (w) => {
      const v = await h.makeFaceVoter();
      const r = await h.registerFace(w.contract, w.ctx, `nid-honest-${Date.now()}`, v, w.sensor);
      const all = JSON.parse(await h.quiet(() => w.contract.getCommitments(w.ctx))).map((c) => BigInt(c.value ?? c));
      w.faceTree = await h.buildTree(all);   // the on-chain root moved
      return { detail: r };
    },
  },
  {
    id: "A10", finding: "C18",
    title: "Non-RA Fabric identity registers a phantom voter, which then votes",
    run: async (w) => {
      const { ctx: rogueCtx } = h.makeLedger("RogueMSP");
      rogueCtx.stub = w.ctx.stub; // same ledger, different client identity
      const phantom = await h.makeFaceVoter();
      // Even with a valid kiosk-attested enrollment proof, only the RA's MSP may enrol
      await h.registerFace(w.contract, rogueCtx, "nid-phantom", phantom, w.sensor);
      const all = JSON.parse(await h.quiet(() => w.contract.getCommitments(w.ctx)));
      w.faceTree = await h.buildTree(all);
      return submit(w, await buildVote(w, phantom, BALLOT_B, {
        index: all.indexOf(phantom.commitment.toString()),
      }));
    },
  },

  // ---------------- Tally: t-of-n trustees, verified on-chain ----------------
  {
    id: "A17", finding: "C15",
    title: "A single key holder (one trustee) decrypts an individual ballot",
    run: async (w) => {
      // With one TA key this succeeds; with a 2-of-3 key, one share is useless
      const vote = storedVotes(w).find((x) => x.ballotId === BALLOT_A);
      const t1 = w.ballots[BALLOT_A].trustees[0];
      const opened = vote.encryptedVote.ciphertexts.map((ct) => {
        const c1 = threshold.tc.toPoint(ct.c1), c2 = threshold.tc.toPoint(ct.c2);
        const M = c2.add(c1.mul(t1.x).neg());
        return M.isInfinity() ? 0 : M.eq(threshold.tc.ec.g) ? 1 : null;
      });
      if (opened.some((v) => v === null)) throw new Error("one trustee's share does not open the ballot");
      return { detail: `decrypted ballot as [${opened}]` };
    },
  },
  {
    id: "A18", finding: "C15",
    title: "Tally published while voting is still open (early results)",
    run: async (w) => publish(w, BALLOT_A, honestTally(w, BALLOT_A)),
  },
  {
    id: "A22", finding: "C15",
    title: "Vote cast after the ballot is closed",
    run: async (w) => {
      await h.quiet(() => w.contract.closeBallot(w.ctx, BALLOT_A));
      return submit(w, await buildVote(w, w.face[2], BALLOT_A, { index: 2 }));
    },
  },
  {
    id: "A19", finding: "C15",
    title: "Inflated total published with genuine partial decryptions",
    run: async (w) => {
      const tally = honestTally(w, BALLOT_A);
      tally.options[0].total += 1;
      return publish(w, BALLOT_A, tally);
    },
  },
  {
    id: "A20", finding: "C15",
    title: "Correct totals backed by a single trustee's partial decryption (below t = 2)",
    run: async (w) => {
      // One trustee cannot decrypt, so take the right totals from elsewhere
      // and submit them with only that trustee's (valid) partials
      const tally = honestTally(w, BALLOT_A);
      tally.options.forEach((o) => { o.partials = o.partials.slice(0, 1); });
      return publish(w, BALLOT_A, tally);
    },
  },
  {
    id: "A21", finding: "C15",
    title: "Partial decryption made with a forged key share",
    run: async (w) => {
      const tally = honestTally(w, BALLOT_A);
      const forger = new threshold.Trustee(2);
      forger.x = threshold.randScalar();
      const sums = threshold.aggregate(storedVotes(w).filter((v) => v.ballotId === BALLOT_A).map((v) => v.encryptedVote), NUM_OPTIONS);
      tally.options[0].partials[1] = forger.partialDecrypt(BALLOT_A, 0, threshold.tc.ser(sums[0].c1));
      return publish(w, BALLOT_A, tally);
    },
  },
  {
    id: "BASELINE-tally", finding: "-", expect: "ACCEPTED",
    title: "Honest 2-of-3 tally of the closed ballot is accepted and matches the votes cast",
    run: async (w) => {
      const r = await publish(w, BALLOT_A, honestTally(w, BALLOT_A));
      const n = storedVotes(w).filter((v) => v.ballotId === BALLOT_A).length;
      if (r.numVotes !== n || r.totals.reduce((a, b) => a + b, 0) !== n) throw new Error(`totals ${r.totals} != ${n} votes`);
      return { detail: `totals [${r.totals}] over ${n} ballots` };
    },
  },
  {
    id: "A23", finding: "C15",
    title: "Trustee corrupts key generation by sending an inconsistent share",
    run: async (w) => {
      // Dealer 3 sends trustee 1 a wrong share; trustee 1's complaint must disqualify it
      const b = await h.setupBallot(w.contract, w.ctx, "ballot-soundness-C", NUM_OPTIONS, {
        corrupt: (dealer, receiver, share) => (dealer === 3 && receiver === 1 ? "1" + share : null),
      });
      if (!b.qual.includes(3)) throw new Error(`dealer 3 disqualified by complaint; QUAL = [${b.qual}]`);
      return { detail: `QUAL = [${b.qual}] still contains the corrupt dealer` };
    },
  },
  {
    id: "A23-control", finding: "-", expect: "REJECTED",
    title: "Control: a false complaint against an honest dealer is rejected",
    run: async (w) => {
      // During key generation, trustee 2 complains about dealer 1 while
      // revealing the honest share it received
      const id = "ballot-soundness-D";
      const ts = [1, 2, 3].map((i) => new threshold.Trustee(i));
      await h.quiet(() => w.contract.registerBallot(w.ctx, id, String(NUM_OPTIONS),
        JSON.stringify(ts.map((t) => t.publicKey)), "2"));
      const d1 = ts[0].deal(id, 2, 3);
      await h.quiet(() => w.contract.submitDealing(w.ctx, id, "1", JSON.stringify(d1.commitments), d1.sig));
      const share = d1.shares[2];
      const sig = ts[1].sign("bbzkv-complaint-v1", { ballotId: id, complainer: 2, dealer: 1, share });
      return JSON.parse(await h.quiet(() => w.contract.complain(w.ctx, id, "2", "1", share, sig)));
    },
  },
];

// Decrypt BALLOT's sums with its first `t` trustees (default: the threshold)
function honestTally(w, ballotId, t) {
  const b = w.ballots[ballotId];
  const votes = storedVotes(w).filter((v) => v.ballotId === ballotId);
  const sums = threshold.aggregate(votes.map((v) => v.encryptedVote), NUM_OPTIONS);
  const active = b.trustees.slice(0, t ?? b.record.threshold);
  return threshold.decryptTally(ballotId, sums, active, votes.length);
}

async function publish(w, ballotId, tally) {
  return JSON.parse(await h.quiet(() => w.contract.publishTally(w.ctx, ballotId, JSON.stringify(tally))));
}

// ------------------------------------------------------------
async function main() {
  const w = await setupWorld();
  const results = [];
  for (const a of attacks) {
    let accepted, detail;
    try {
      const r = await a.run(w);
      accepted = true;
      detail = r?.detail || (r?.voteId ? `stored as ${r.voteId}` : "");
    } catch (e) {
      accepted = false;
      detail = e.message.split("\n")[0].slice(0, 160);
    }
    let outcome;
    if (a.expect) outcome = accepted === (a.expect === "ACCEPTED") ? "OK" : "HARNESS-FAIL";
    else if (!accepted) outcome = "PROTECTED";
    else outcome = a.knownOpen ? "OPEN" : "VULNERABLE";
    if (outcome === "OPEN") detail = `${detail} (${a.knownOpen})`;
    results.push({ id: a.id, finding: a.finding, title: a.title, outcome, detail });
    console.log(`${outcome.padEnd(12)} ${a.id.padEnd(13)} [${a.finding}] ${a.title}\n${" ".repeat(13)}${detail}`);
  }

  const outDir = path.join(__dirname, "results");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "soundness_results.json"),
    JSON.stringify({ date: new Date().toISOString(), results }, null, 2));

  const count = (o) => results.filter((r) => r.outcome === o).length;
  console.log(`\n${count("VULNERABLE")} vulnerable, ${count("OPEN")} known-open, ` +
    `${count("PROTECTED")} protected, ${count("HARNESS-FAIL")} harness failures, ${results.length} total`);
  process.exit(count("HARNESS-FAIL") ? 100 : count("VULNERABLE"));
}

main().catch((e) => { console.error(e); process.exit(101); });
