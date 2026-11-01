"""
targeted_impostor.py — lookalike (targeted) impostor attack on the deployed face circuit.

The FAR in Theorem 1 is a zero-effort rate: a random impostor against a random
template. A face is public, so a real attacker first collects photos of the
target, screens a pool of K people they can recruit with a face recognizer,
and sends the most similar one to an honest capture device. This script
measures how often that single presentation passes the circuit.

Protocol (same LFW split and SEED as every other face script):
  * PCA-96 fitted on the training identities (the deployed encoding);
  * each test identity is a target; its enrolled template is its first image;
  * each recruit contributes one image (its first);
  * the attacker screens with the deployed ArcFace embedding itself (strongest
    case), so the best recruit is the one with the highest cosine;
  * acceptance is the circuit's predicate, dot >= 0 and dot^2*1e4 >= tau_num*|a|^2*|b|^2 (tau_num = tau^2),
    on sigma = 5e5 integer coordinates;
  * a short sweep of stricter thresholds on LFW reports the FRR each costs
    (Table 3's genuine pairs) beside the lookalike success it leaves;
  * for each pool size K, R random pools per target; reported: the fraction of
    (target, pool) trials whose best recruit is accepted. K = 1 is the
    zero-effort FAR of one presentation.
Repeated on the 2,000 CelebA identities (LFW-fitted PCA), with pools drawn from
all identities and from same-gender identities only.

Usage (from model/):
  venv312/bin/python targeted_impostor.py                      # deployed PCA-128, tau 0.35
  venv312/bin/python targeted_impostor.py --dim 96 --tau 33      # previous PCA-96 point
Output: ../api-server/benchmark/targeted_impostor_d<dim>_t<tau>.json
"""

import argparse
import json
import os
import random

import numpy as np
from sklearn.decomposition import PCA

import face_model_sweep as fs   # stubs `app`, shares the split and the circuit predicate
ev = fs.ev

TAU_DEN = 10_000
CELEBA_ATTR = f"{fs.D}/list_attr_celeba.txt"


def accept_matrix(Z, tau_num):
    """Circuit decision for every (template, presentation) pair of rows of Z."""
    Q = np.rint(fs.SIGMA * Z).astype(np.float64)       # exact integers, |q| <= 5e5
    dot = Q @ Q.T                                        # |dot| < 96e12 < 2^53: exact
    n = np.einsum("ij,ij->i", Q, Q)
    lhs, rhs = dot * dot * TAU_DEN, tau_num * np.outer(n, n)
    acc = (dot >= 0) & (lhs >= rhs)
    near = np.abs(lhs - rhs) <= 1e-9 * rhs               # float rounding could flip these
    for i, j in zip(*np.nonzero(near)):                  # re-decide them in exact integers
        qi, qj = Q[i].astype(np.int64), Q[j].astype(np.int64)
        d, a, b = int(qi @ qj), int(qi @ qi), int(qj @ qj)
        acc[i, j] = d >= 0 and d * d * TAU_DEN >= tau_num * a * b
    cos = dot / np.sqrt(np.outer(n, n))
    return cos, acc, int(near.sum())


def attack(cos, acc, pools_of, ks, trials, rng):
    """pools_of[t] = indices the attacker may recruit for target t."""
    out = {}
    for k in ks:
        hits = total = 0
        for t, pool in enumerate(pools_of):
            if len(pool) < k:
                continue
            reps = 1 if k == len(pool) else trials
            for _ in range(reps):
                cand = pool if k == len(pool) else rng.choice(pool, size=k, replace=False)
                best = cand[np.argmax(cos[t, cand])]
                hits += bool(acc[t, best])
                total += 1
        out[str(k)] = {"trials": total, "accepted": hits,
                       "success_rate": round(hits / total, 5) if total else None}
    return out


def first_images(ids, emb):
    names, rows = [], []
    for k in sorted(ids):
        p = next((p for p in ids[k] if p in emb), None)
        if p is not None:
            names.append(k)
            rows.append(emb[p])
    return names, np.array(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="face_embeddings_insightface_buffalo_l")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--dim", type=int, default=128)
    ap.add_argument("--tau", type=int, default=35, help="threshold in hundredths (deployed: 35)")
    ap.add_argument("--ks", default="1,10,100,1000", type=lambda s: [int(x) for x in s.split(",")])
    args = ap.parse_args()
    rng = np.random.default_rng(ev.SEED)

    cache = ev.open_cache(args.cache, ev.DEFAULT_CACHE_DIR, False)
    cached = lambda ps: {p: np.asarray(cache[p], dtype=np.float64) for p in ps if p in cache}

    ids = ev.scan_identity_folders(fs.LFW)
    train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
    train = cached([p for v in train_ids.values() for p in v])
    test = cached([p for v in test_ids.values() for p in v])
    D, T = args.dim, args.tau
    pca = PCA(n_components=D, random_state=ev.SEED).fit(np.array(list(train.values())))
    enc = lambda X: fs.unit_rows(pca.transform(X))

    res = {"encoding": f"PCA-{D}", "tau": T / 100, "trials_per_target": args.trials,
           "attacker_screening_model": "deployed ArcFace embedding (strongest case)"}

    _, L = first_images(test_ids, test)
    cos, acc, near = accept_matrix(enc(L), T * T)
    n = len(L)
    np.fill_diagonal(acc, False)
    pools = [np.delete(np.arange(n), t) for t in range(n)]
    res["lfw"] = {"identities": n, "near_ties_rechecked": near,
                  "zero_effort_pair_far": round(float(acc.sum() / (n * (n - 1))), 6),
                  "by_pool_size": attack(cos, acc, pools, args.ks + [n - 1], args.trials, rng)}
    print("LFW", json.dumps(res["lfw"]["by_pool_size"]))

    # Stricter thresholds: lookalike success vs the FRR they cost (a trade-off curve, not a selection)
    paths = list(test)
    idx = {p: k for k, p in enumerate(paths)}
    g_pairs, _ = ev.make_pairs(test_ids, max_pairs=6000)          # Table 3's genuine pairs
    g_ij = fs.pair_index(g_pairs, idx)
    Zt = enc(np.array([test[p] for p in paths]))
    res["lfw"]["tau_sweep"] = {}
    for t in (33, 36, 40, 45):
        frr = 1 - float(fs.circuit_accepts_exact(fs.integer_terms(Zt, g_ij), t).mean())
        cos_t, acc_t, _ = accept_matrix(enc(L), t * t)
        np.fill_diagonal(acc_t, False)
        far = float(acc_t.sum() / (n * (n - 1)))
        res["lfw"]["tau_sweep"][f"{t / 100:.2f}"] = {
            "test_frr": round(frr, 5), "zero_effort_pair_far": round(far, 6),
            "by_pool_size": attack(cos_t, acc_t, pools, [10, 100, 1000], args.trials, rng)}
        print(f"  tau={t / 100:.2f}: FRR {100 * frr:.2f}%  FAR {100 * far:.4f}%  ",
              {k: v["success_rate"] for k, v in res["lfw"]["tau_sweep"][f"{t / 100:.2f}"]["by_pool_size"].items()})

    celeba_ids = ev.scan_celeba_flat(fs.CELEBA_IMG, fs.CELEBA_ID)
    keep = random.Random(ev.SEED).sample(list(celeba_ids.keys()), 2000)
    celeba_ids = {k: celeba_ids[k] for k in keep}
    cel = cached([p for v in celeba_ids.values() for p in v])
    names, C = first_images(celeba_ids, cel)
    cos, acc, near = accept_matrix(enc(C), T * T)
    n = len(C)
    np.fill_diagonal(acc, False)
    gender_of_file = ev.load_celeba_gender_labels(CELEBA_ATTR)
    g = np.array([ev.identity_gender(celeba_ids[k], gender_of_file) for k in names])
    all_pools = [np.delete(np.arange(n), t) for t in range(n)]
    same = [np.array([j for j in np.nonzero(g == g[t])[0] if j != t]) for t in range(n)]
    res["celeba"] = {"identities": n, "near_ties_rechecked": near,
                     "zero_effort_pair_far": round(float(acc.sum() / (n * (n - 1))), 6),
                     "by_pool_size": attack(cos, acc, all_pools, args.ks + [n - 1], args.trials, rng),
                     "same_gender_by_pool_size": attack(cos, acc, same, args.ks, args.trials, rng)}
    print("CelebA", json.dumps(res["celeba"]["by_pool_size"]))
    print("CelebA same-gender", json.dumps(res["celeba"]["same_gender_by_pool_size"]))
    cache.close()

    out = os.path.join(ev.RESULTS_DIR, f"targeted_impostor_d{D}_t{T}.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"→ {out}")


if __name__ == "__main__":
    main()
