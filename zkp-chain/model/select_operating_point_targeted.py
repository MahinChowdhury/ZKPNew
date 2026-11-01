"""
select_operating_point_targeted.py — choose the face dimension d and circuit threshold tau
against a stated lookalike attacker, WITHOUT looking at the test pairs.

Rule (stated before any test number is seen):
  * attacker: screens K_ATTACK = 100 recruits offline and presents the best one once;
  * for each d, PCA is fitted on validation-fit identities A, and tau_d is the lowest
    tau (0.01 grid) whose lookalike success on the validation-select identities B is
    <= SUCCESS_TARGET (1%);
  * d* = smallest d whose validation FRR at tau_d is <= FRR_TARGET (1%).
The A/B split, genuine pairs and impostor draws are those of select_operating_point.py.
At the selected point (PCA refitted on all training identities), the test set reports:
zero-effort FAR over 200,000 impostor pairs, FRR on Table 3's 6,000 genuine pairs, and
lookalike success for K = 1, 10, 100, 1000 (protocol of targeted_impostor.py).

Usage (from model/):
  venv312/bin/python select_operating_point_targeted.py
Output: ../api-server/benchmark/operating_point_targeted.json (operating_point_targeted_<label>.json for --label)
"""

import argparse
import json
import os
import random

import numpy as np
from sklearn.decomposition import PCA

import face_model_sweep as fs
import select_operating_point as sop
import targeted_impostor as ti
ev = fs.ev

K_ATTACK, SUCCESS_TARGET, FRR_TARGET = 100, 1e-2, 1e-2
TAUS = range(30, 61)


def lookalike_rates(Z, taus, k, trials, seed):
    """Lookalike success at each tau (in hundredths), one image per identity in Z,
    with the same random pools for every tau."""
    n = len(Z)
    Q = np.rint(fs.SIGMA * Z).astype(np.float64)
    dot = Q @ Q.T
    nn = np.einsum("ij,ij->i", Q, Q)
    cos = dot / np.sqrt(np.outer(nn, nn))
    np.fill_diagonal(cos, -np.inf)
    rng = np.random.default_rng(seed)
    best = []                                   # (target, best recruit) for every trial
    for t in range(n):
        pool = np.delete(np.arange(n), t)
        for _ in range(trials if k < len(pool) else 1):
            cand = pool if k >= len(pool) else rng.choice(pool, size=k, replace=False)
            best.append((t, cand[np.argmax(cos[t, cand])]))
    best = np.array(best)
    i, j = best[:, 0], best[:, 1]
    # exact integer decision (object dtype: dot^2 * 1e4 exceeds float64's exact range)
    d = dot[i, j].astype(np.int64).astype(object)
    rhs = nn[i].astype(np.int64).astype(object) * nn[j].astype(np.int64).astype(object)
    lhs = d * d * 10_000
    nonneg = dot[i, j] >= 0
    return {t: float(np.mean(nonneg & (lhs >= t * t * rhs))) for t in taus}


def test_point(Xtr, T_mat, T_first, t_g, t_i, d, tau, trials):
    """Test-set report at (d, tau), PCA refitted on all training identities."""
    pt = PCA(n_components=d, random_state=ev.SEED).fit(Xtr)
    Zt = fs.unit_rows(pt.transform(T_mat))
    acc_i = fs.circuit_accepts_exact(fs.integer_terms(Zt, t_i), tau)
    frr = 1 - float(fs.circuit_accepts_exact(fs.integer_terms(Zt, t_g), tau).mean())
    Zf = fs.unit_rows(pt.transform(T_first))
    look = {str(k): round(lookalike_rates(Zf, [tau], k, trials, ev.SEED)[tau], 5) for k in (1, 10, 100, 1000)}
    return {"test_far": round(float(acc_i.mean()), 6), "test_false_accepts": int(acc_i.sum()),
            "test_impostor_pairs": len(t_i), "test_frr": round(frr, 5), "test_lookalike_success": look}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="face_embeddings_insightface_buffalo_l")
    ap.add_argument("--label", default="insightface")
    ap.add_argument("--dims", default="64,80,96,112,128,160",
                    type=lambda s: [int(x) for x in s.split(",")])
    ap.add_argument("--trials", type=int, default=20)
    args = ap.parse_args()

    cache = ev.open_cache(args.cache, ev.DEFAULT_CACHE_DIR, False)
    cached = lambda ps: {p: np.asarray(cache[p], dtype=np.float64) for p in ps if p in cache}

    ids = ev.scan_identity_folders(fs.LFW)
    train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
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

    owner = {p: k for k, v in ids.items() for p in v}
    b_paths, t_paths = list(B), list(test)
    b_idx, t_idx = {p: k for k, p in enumerate(b_paths)}, {p: k for k, p in enumerate(t_paths)}
    B_mat, T_mat = np.array([B[p] for p in b_paths]), np.array([test[p] for p in t_paths])
    b_gen, _ = ev.make_pairs({k: [p for p in v if p in B] for k, v in b_ids.items()}, max_pairs=6000)
    b_g = fs.pair_index(b_gen, b_idx)
    t_gen, _ = ev.make_pairs(test_ids, max_pairs=6000)
    t_g = fs.pair_index(t_gen, t_idx)
    t_i = sop.impostor_index(t_paths, owner, 200_000, ev.SEED)
    _, B_first = ti.first_images(b_ids, B)
    _, T_first = ti.first_images(test_ids, test)

    res = {"rule": {"attacker_recruits_K": K_ATTACK, "lookalike_success_target": SUCCESS_TARGET,
                    "frr_target": FRR_TARGET, "trials_per_target": args.trials},
           "validation": {"fit_identities": len(a_ids), "select_identities": len(B_first),
                          "genuine_pairs": len(b_g)},
           "per_dim": {}}
    for d in args.dims:
        pa = PCA(n_components=d, random_state=ev.SEED).fit(XA)
        rates = lookalike_rates(fs.unit_rows(pa.transform(B_first)), TAUS, K_ATTACK, args.trials, ev.SEED + 3)
        ok = [t for t in TAUS if rates[t] <= SUCCESS_TARGET]
        tau = min(ok) if ok else None
        row = {"tau": None if tau is None else tau / 100,
               "val_lookalike_success": None if tau is None else round(rates[tau], 5)}
        if tau is not None:
            Zb = fs.unit_rows(pa.transform(B_mat))
            row["val_frr"] = round(1 - float(fs.circuit_accepts_exact(fs.integer_terms(Zb, b_g), tau).mean()), 5)
            row |= test_point(Xtr, T_mat, T_first, t_g, t_i, d, tau, args.trials)   # reported, never used to select
        res["per_dim"][str(d)] = row
        print(f"  d={d:>3}: tau={row['tau']}  val lookalike {row['val_lookalike_success']}  val FRR {row.get('val_frr')}")

    chosen = next((d for d in args.dims if res["per_dim"][str(d)].get("val_frr", 1) <= FRR_TARGET), None)
    res["selected_dim"] = chosen
    if chosen is not None:
        row = res["per_dim"][str(chosen)]
        res["selected"] = {"dim": chosen, "tau": row["tau"], "tau_num": round(100 * row["tau"]) ** 2,
                           "tau_den": 10_000} | {k: row[k] for k in row if k.startswith("test_")}
        print("→ selected", json.dumps(res["selected"]))
    cache.close()
    out = os.path.join(ev.RESULTS_DIR, "operating_point_targeted" + ("" if args.label == "insightface" else f"_{args.label}") + ".json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"→ {out}")


if __name__ == "__main__":
    main()
