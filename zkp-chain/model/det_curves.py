"""
det_curves.py — DET curves (FNMR vs FMR) for the paper's DET figure.

Same LFW split, 6,000 genuine test pairs and 200,000 cross-identity impostor
pairs as face_model_sweep.py (same SEED), from the cached embeddings, so it
needs no GPU. Encodings: ArcFace (InsightFace buffalo_l) raw 512-D, PCA-64 and
PCA-128 (deployed); FaceNet PCA-64 (baseline). PCA is fitted on all training
identities, as deployed.

Usage (from model/):  venv312/bin/python det_curves.py
Output: api-server/benchmark/det_curves.json
"""

import json
import os

import numpy as np
from sklearn.decomposition import PCA

import face_model_sweep as fs
from face_model_sweep import ev

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api-server", "benchmark", "det_curves.json")
CURVES = (("insightface", "face_embeddings_insightface_buffalo_l", ("raw", 64, 128)),
          ("facenet", "face_embeddings", (64,)))
N_IMPOSTORS = 200_000
FMR_GRID = np.logspace(-5, 0, 101)


def det(g, imp):
    """FNMR at the threshold giving each FMR on the grid (accept if score > threshold)."""
    imp_sorted = np.sort(imp)[::-1]
    out = []
    for fmr in FMR_GRID:
        k = int(np.floor(fmr * len(imp)))           # impostors allowed above the threshold
        thr = imp_sorted[k] if k < len(imp) else -np.inf
        out.append([float(np.mean(imp > thr)), float(np.mean(g <= thr))])
    return out


def main():
    ids = ev.scan_identity_folders(fs.LFW)
    train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
    res = {"protocol": {"genuine_pairs": None, "impostor_pairs": N_IMPOSTORS, "seed": ev.SEED,
                        "pca_fit": "all LFW training identities (60%)"}, "curves": {}}
    for label, cache_name, encodings in CURVES:
        cache = ev.open_cache(cache_name, ev.DEFAULT_CACHE_DIR, False)
        cached = lambda paths: {p: np.asarray(cache[p], dtype=np.float64) for p in paths if p in cache}
        train = cached([p for v in train_ids.values() for p in v])
        test = cached([p for v in test_ids.values() for p in v])
        cache.close()
        X = np.array(list(train.values()))
        paths = list(test)
        idx = {p: k for k, p in enumerate(paths)}
        T = np.array([test[p] for p in paths])
        g_pairs, _ = ev.make_pairs(test_ids, max_pairs=6000)
        g_ij = fs.pair_index(g_pairs, idx)
        who = {p: k for k, v in test_ids.items() for p in v}
        owner = np.array([who[p] for p in paths])
        rng = np.random.default_rng(ev.SEED)                 # identical to face_model_sweep.py
        big = rng.integers(0, len(paths), size=(int(N_IMPOSTORS * 1.2), 2))
        big = big[owner[big[:, 0]] != owner[big[:, 1]]][:N_IMPOSTORS]
        res["protocol"]["genuine_pairs"] = len(g_ij)
        for enc in encodings:
            if enc == "raw":
                Z, name = fs.unit_rows(T), f"{label}_raw{T.shape[1]}"
            else:
                Z = fs.unit_rows(PCA(n_components=enc, random_state=ev.SEED).fit(X).transform(T))
                name = f"{label}_pca{enc}"
            g, imp = fs.scores(Z, g_ij), fs.scores(Z, big)
            res["curves"][name] = det(g, imp)
            print(f"{name}: {len(g)} genuine, {len(imp)} impostor")
    with open(OUT, "w") as f:
        json.dump(res, f, indent=1)
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
