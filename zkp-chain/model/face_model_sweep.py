"""
face_model_sweep.py — PCA output-dimension and threshold sweep for a cached face model.

Uses only the embeddings cached by `run_face_eval.sh <model>`, with the same
LFW split and genuine/impostor pairs (same SEED), so it needs no GPU. Per PCA
output dimension d (PCA fitted on the LFW training split, as deployed):

  * EER with a pair-bootstrap 95% CI on the 6,000/6,000 pairs of Table 3,
    plus raw and mean-centred full-dimension baselines;
  * TAR at FAR = 1% and 0.1% on a larger impostor set (default 200,000 random
    cross-identity test pairs, so 0.1% is 200 false accepts);
  * circuit-exact FAR/FRR per threshold tau: coordinates round(5e5 * v) as in
    the circuit, which accepts iff dot >= 0 and dot^2 * tau_den >= tau_num * |a|^2 |b|^2
    (FaceAuth(d, 20, tau_num, tau_den, 10) with tau = t/100 -> tau_num = t^2,
    tau_den = 10^4). The grid is scored with the cosine of the integer vectors
    (the same predicate for tau > 0); the chosen operating points are then
    re-checked with exact integer arithmetic;
  * the full face-circuit constraint count where measure_subcircuits.sh has
    measured d (full(d) = full(d0) + 2 (H(d) - H(d0)) + (C(d) - C(d0)), d0 = compiled dim);
plus the embedding spectrum and, when cached, the CelebA cross-dataset EER per d.

Usage (from model/):
  venv312/bin/python face_model_sweep.py --cache face_embeddings --label facenet
  venv312/bin/python face_model_sweep.py --cache face_embeddings_insightface_buffalo_l --label insightface
Output: ../api-server/benchmark/face_sweep_<label>.json
"""

import argparse
import json
import os
import random
import sys
import types

import numpy as np
from sklearn.decomposition import PCA

sys.modules.setdefault("app", types.ModuleType("app"))   # embeddings come from the cache
import biometric_accuracy_eval as ev                      # noqa: E402

D = "../Datasets"   # must match run_face_eval.sh: cache keys are these relative paths
LFW = f"{D}/lfw_kaggle/lfw-deepfunneled/lfw-deepfunneled"
CELEBA_IMG, CELEBA_ID = f"{D}/img_align_celeba", f"{D}/identity_CelebA.txt"
COST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "api-server", "results", "subcircuit_constraints.json")
SIGMA = 500_000                   # sigma, matches FACE_SCALE and the circuit range check |a_k| < 2^19
FAR_TARGETS = (1e-2, 1e-3)
TAU_GRID = range(10, 81)          # tau = t/100
TAU_REPORT = range(20, 65, 5)     # rows written per d


def unit_rows(X):
    return X / np.linalg.norm(X, axis=1, keepdims=True)


def pair_index(pairs, idx):
    return np.array([(idx[a], idx[b]) for a, b in pairs if a in idx and b in idx],
                    dtype=np.int64).reshape(-1, 2)


def scores(Z, ij):
    return np.einsum("ij,ij->i", Z[ij[:, 0]], Z[ij[:, 1]])


def integer_terms(Z, ij):
    """dot, |a|^2, |b|^2 of the circuit's integer coordinates (exact in int64:
    |a_k| <= 5e5 and d <= 512, so every sum is below 2^63)."""
    Q = np.rint(SIGMA * Z).astype(np.int64)
    a, b = Q[ij[:, 0]], Q[ij[:, 1]]
    return (np.einsum("ij,ij->i", a, b), np.einsum("ij,ij->i", a, a), np.einsum("ij,ij->i", b, b))


def circuit_accepts_exact(terms, t):
    dot, na, nb = terms
    return np.array([int(x) >= 0 and int(x) * int(x) * 10_000 >= t * t * int(y) * int(z)
                     for x, y, z in zip(dot, na, nb)])


def tar_at_far(g, imp, far):
    thr = np.quantile(imp, 1.0 - far, method="higher")
    return float(np.mean(g > thr)), float(thr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True, help="cache name under .eval_cache, e.g. face_embeddings")
    ap.add_argument("--label", required=True, help="model label for the output file")
    ap.add_argument("--dims", default="16,32,48,64,96,128,160,192,256",
                    type=lambda s: [int(x) for x in s.split(",")])
    ap.add_argument("--impostors", type=int, default=200_000)
    ap.add_argument("--bootstrap", type=int, default=1000)
    ap.add_argument("--no-celeba", action="store_true")
    args = ap.parse_args()

    cache = ev.open_cache(args.cache, ev.DEFAULT_CACHE_DIR, False)

    def cached(paths):
        return {p: np.asarray(cache[p], dtype=np.float64) for p in paths if p in cache}

    ids = ev.scan_identity_folders(LFW)
    train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
    train = cached([p for v in train_ids.values() for p in v])
    test = cached([p for v in test_ids.values() for p in v])
    assert train and test, f"no cached embeddings in '{args.cache}' — run run_face_eval.sh first"
    X = np.array(list(train.values()))
    raw_dim = X.shape[1]
    dims = [d for d in args.dims if d % 8 == 0 and d <= raw_dim]

    paths = list(test)
    idx = {p: k for k, p in enumerate(paths)}
    T = np.array([test[p] for p in paths])
    g_pairs, i_pairs = ev.make_pairs(test_ids, max_pairs=6000)
    g_ij, i_ij = pair_index(g_pairs, idx), pair_index(i_pairs, idx)

    # Larger impostor set for low-FAR operating points
    who = {p: k for k, v in test_ids.items() for p in v}
    owner = np.array([who[p] for p in paths])
    rng = np.random.default_rng(ev.SEED)
    big = rng.integers(0, len(paths), size=(int(args.impostors * 1.2), 2))
    big = big[owner[big[:, 0]] != owner[big[:, 1]]][:args.impostors]

    full_pca = PCA(random_state=ev.SEED).fit(X)
    cum = np.cumsum(full_pca.explained_variance_ratio_)
    res = {"label": args.label, "cache": args.cache, "raw_dim": raw_dim,
           "train_images": len(train), "test_images": len(test),
           "n_genuine": len(g_ij), "n_impostor": len(i_ij), "n_impostor_large": len(big),
           "spectrum": {"components_99": int(np.searchsorted(cum, 0.99) + 1),
                        "components_999": int(np.searchsorted(cum, 0.999) + 1),
                        "cum_variance": {str(d): round(float(cum[d - 1]), 5) for d in dims}}}

    cost = json.load(open(COST)) if os.path.exists(COST) else {}

    def full_cost(d):
        H = lambda x: cost.get(f"PackedCoordHash({x})")
        C = lambda x: cost.get(f"SquaredCosineSimilarity({x})")
        base = cost.get("face_auth (dim)", 64)   # dimension of the compiled face circuit
        if None in (H(d), C(d), H(base), C(base), cost.get("face_auth (full)")):
            return None
        return cost["face_auth (full)"] + 2 * (H(d) - H(base)) + C(d) - C(base)

    encodings = {"raw": unit_rows(T), "centred": unit_rows(T - X.mean(axis=0))}
    pcas = {}
    for d in dims:
        pcas[d] = PCA(n_components=d, random_state=ev.SEED).fit(X)
        encodings[f"pca{d}"] = unit_rows(pcas[d].transform(T))

    print(f"[{args.label}] raw {raw_dim}-D, {len(test)} test images; bootstrap {args.bootstrap}...")
    ci, diffs = ev.bootstrap_eer({k: (scores(Z, g_ij), scores(Z, i_ij)) for k, Z in encodings.items()},
                                 n_boot=args.bootstrap)
    res["eer"] = ci
    res["paired_diff"] = diffs   # every pair of encodings, same resampled pairs

    per_dim = {}
    for name, Z in encodings.items():
        g, imp = scores(Z, g_ij), scores(Z, big)
        row = {"tar_at_far": {str(f): round(tar_at_far(g, imp, f)[0], 5) for f in FAR_TARGETS}}
        if name.startswith("pca"):
            d = int(name[3:])
            row["full_circuit_constraints"] = full_cost(d)
            tg, ti = integer_terms(Z, g_ij), integer_terms(Z, big)
            cos_g = tg[0] / np.sqrt(tg[1].astype(float) * tg[2])
            cos_i = ti[0] / np.sqrt(ti[1].astype(float) * ti[2])
            grid = {t: (float(np.mean(cos_i >= t / 100)), float(np.mean(cos_g < t / 100))) for t in TAU_GRID}
            row["circuit_tau"] = {f"{t / 100:.2f}": {"far": round(grid[t][0], 5), "frr": round(grid[t][1], 5)}
                                  for t in TAU_REPORT}
            ops = {}
            for f in FAR_TARGETS:
                ok = [t for t in TAU_GRID if grid[t][0] <= f]
                if not ok:
                    continue
                t = min(ok)   # lowest threshold meeting the FAR target = lowest FRR
                acc_g, acc_i = circuit_accepts_exact(tg, t), circuit_accepts_exact(ti, t)
                ops[str(f)] = {"tau": t / 100, "tau_num": t * t, "tau_den": 10_000,
                               "far": round(float(acc_i.mean()), 5), "frr": round(float(1 - acc_g.mean()), 5)}
            row["circuit_operating_points"] = ops
        per_dim[name] = row
        op = row.get("circuit_operating_points", {}).get("0.001", {})
        print(f"  {name:>8}: EER {100 * ci[name]['eer']:5.2f}% {ci[name]['ci95']}  "
              f"TAR@0.1% {100 * row['tar_at_far']['0.001']:5.2f}%"
              + (f"  circuit tau={op['tau']:.2f} FAR {100 * op['far']:.3f}% FRR {100 * op['frr']:.2f}%" if op else "")
              + (f"  [{row['full_circuit_constraints']:,} constraints]" if row.get("full_circuit_constraints") else ""))
    res["per_encoding"] = per_dim

    if not args.no_celeba:
        celeba_ids = ev.scan_celeba_flat(CELEBA_IMG, CELEBA_ID)
        keep = random.Random(ev.SEED).sample(list(celeba_ids.keys()), 2000)
        celeba_ids = {k: celeba_ids[k] for k in keep}
        cel = cached([p for v in celeba_ids.values() for p in v])
        total = sum(len(v) for v in celeba_ids.values())
        if len(cel) < 0.5 * total:
            res["celeba"] = {"status": f"only {len(cel)}/{total} CelebA images cached — skipped"}
        else:
            cp = list(cel)
            cidx = {p: k for k, p in enumerate(cp)}
            C = np.array([cel[p] for p in cp])
            cg, cimp = ev.make_pairs(celeba_ids, max_pairs=6000)
            cg_ij, ci_ij = pair_index(cg, cidx), pair_index(cimp, cidx)
            cenc = {"raw": unit_rows(C)} | {f"pca{d}": unit_rows(pcas[d].transform(C)) for d in dims}
            res["celeba"] = {"embedded": [len(cel), total]} | {
                k: round(ev.eer_np(scores(Z, cg_ij), scores(Z, ci_ij)), 5) for k, Z in cenc.items()}
            print("  CelebA EER: " + ", ".join(f"{k} {100 * v:.2f}%" for k, v in res["celeba"].items() if k != "embedded"))

    cache.close()
    out = os.path.join(ev.RESULTS_DIR, f"face_sweep_{args.label}.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"→ {out}")


if __name__ == "__main__":
    main()
