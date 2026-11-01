"""
select_operating_point.py — choose the face dimension d and circuit threshold tau
WITHOUT looking at the test pairs, then report test performance at that point.

Protocol (same LFW split and SEED as every other face script):
  * the 60% training identities are split again into A (75%) and B (25%);
  * for each d, PCA is fitted on A and tau is set on validation pairs from B:
    the lowest tau (0.01 grid) whose circuit FAR over random impostor pairs is
    <= FAR_TARGET; the validation FRR at that tau is recorded;
  * d* = smallest d whose validation FRR <= FRR_TARGET (the paper's rule);
  * PCA is refitted on all training identities and, for every d at its
    validation tau, test FAR (200,000 impostor pairs) and FRR (the 6,000
    genuine pairs of Table 3) are measured with exact integer arithmetic,
    exactly as the circuit decides.

Usage (from model/):
  venv312/bin/python select_operating_point.py --cache face_embeddings_insightface_buffalo_l --label insightface
  venv312/bin/python select_operating_point.py --cache face_embeddings --label facenet
Output: ../api-server/benchmark/operating_point_<label>.json
"""

import argparse
import json
import os
import random

import numpy as np
from sklearn.decomposition import PCA

import face_model_sweep as fs   # stubs `app`, shares the split, pairs and circuit predicate
ev = fs.ev

FAR_TARGET, FRR_TARGET = 1e-3, 1e-2


def impostor_index(paths, owner_of, n, seed):
    owner = np.array([owner_of[p] for p in paths])
    rng = np.random.default_rng(seed)
    ij = rng.integers(0, len(paths), size=(int(n * 1.2), 2))
    return ij[owner[ij[:, 0]] != owner[ij[:, 1]]][:n]


def cosines(Z, ij):
    dot, na, nb = fs.integer_terms(Z, ij)
    return dot / np.sqrt(na.astype(float) * nb)


def lowest_tau(cos_imp, far_target):
    ok = [t for t in fs.TAU_GRID if np.mean(cos_imp >= t / 100) <= far_target]
    return min(ok) if ok else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--dims", default="32,48,64,80,96,112,128,160,192,256",
                    type=lambda s: [int(x) for x in s.split(",")])
    ap.add_argument("--impostors", type=int, default=200_000)
    args = ap.parse_args()

    cache = ev.open_cache(args.cache, ev.DEFAULT_CACHE_DIR, False)
    cached = lambda ps: {p: np.asarray(cache[p], dtype=np.float64) for p in ps if p in cache}

    ids = ev.scan_identity_folders(fs.LFW)
    train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
    # Second split of the training identities: A fits PCA, B selects (d, tau)
    keys = sorted(train_ids)
    random.Random(ev.SEED + 1).shuffle(keys)
    cut = int(0.75 * len(keys))
    a_ids = {k: train_ids[k] for k in keys[:cut]}
    b_ids = {k: train_ids[k] for k in keys[cut:]}

    A = cached([p for v in a_ids.values() for p in v])
    B = cached([p for v in b_ids.values() for p in v])
    train = cached([p for v in train_ids.values() for p in v])
    test = cached([p for v in test_ids.values() for p in v])
    XA, Xtr = np.array(list(A.values())), np.array(list(train.values()))
    raw_dim = Xtr.shape[1]
    dims = [d for d in args.dims if d <= raw_dim]

    owner = {p: k for k, v in ids.items() for p in v}
    b_paths, t_paths = list(B), list(test)
    b_idx, t_idx = {p: k for k, p in enumerate(b_paths)}, {p: k for k, p in enumerate(t_paths)}
    B_mat, T_mat = np.array([B[p] for p in b_paths]), np.array([test[p] for p in t_paths])

    b_gen, _ = ev.make_pairs({k: [p for p in v if p in B] for k, v in b_ids.items()}, max_pairs=6000)
    b_g = fs.pair_index(b_gen, b_idx)
    b_i = impostor_index(b_paths, owner, args.impostors, ev.SEED + 2)
    t_gen, _ = ev.make_pairs(test_ids, max_pairs=6000)            # Table 3's genuine pairs
    t_g = fs.pair_index(t_gen, t_idx)
    t_i = impostor_index(t_paths, owner, args.impostors, ev.SEED)   # same draw as face_model_sweep

    res = {"label": args.label, "cache": args.cache, "far_target": FAR_TARGET, "frr_target": FRR_TARGET,
           "validation": {"fit_identities": len(a_ids), "select_identities": len(b_ids),
                          "genuine_pairs": len(b_g), "impostor_pairs": len(b_i)},
           "test": {"genuine_pairs": len(t_g), "impostor_pairs": len(t_i)}, "per_dim": {}}

    for d in dims:
        pa = PCA(n_components=d, random_state=ev.SEED).fit(XA)
        Zb = fs.unit_rows(pa.transform(B_mat))
        tau = lowest_tau(cosines(Zb, b_i), FAR_TARGET)
        row = {"tau": None if tau is None else tau / 100}
        if tau is not None:
            row["val_frr"] = round(float(np.mean(cosines(Zb, b_g) < tau / 100)), 5)
            pt = PCA(n_components=d, random_state=ev.SEED).fit(Xtr)    # refit on all training identities
            Zt = fs.unit_rows(pt.transform(T_mat))
            acc_g = fs.circuit_accepts_exact(fs.integer_terms(Zt, t_g), tau)
            acc_i = fs.circuit_accepts_exact(fs.integer_terms(Zt, t_i), tau)
            row |= {"tau_num": tau * tau, "tau_den": 10_000,
                    "test_far": round(float(acc_i.mean()), 5), "test_frr": round(float(1 - acc_g.mean()), 5),
                    "test_false_accepts": int(acc_i.sum())}
        res["per_dim"][str(d)] = row
        print(f"  d={d:>3}: tau={row['tau']}  val FRR {100 * row.get('val_frr', float('nan')):.2f}%  "
              f"test FAR {100 * row.get('test_far', float('nan')):.3f}%  FRR {100 * row.get('test_frr', float('nan')):.2f}%")

    chosen = next((d for d in dims if res["per_dim"][str(d)].get("val_frr", 1) <= FRR_TARGET), None)
    res["selected_dim"] = chosen
    print(f"→ selected d = {chosen}" + (f", tau = {res['per_dim'][str(chosen)]['tau']}" if chosen else ""))
    cache.close()
    out = os.path.join(ev.RESULTS_DIR, f"operating_point_{args.label}.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"→ {out}")


if __name__ == "__main__":
    main()
