"""
cross_lfw_eval.py — the deployed face encoding on CALFW (cross-age) and CPLFW (cross-pose).

Both use the standard 6,000-pair protocols (3,000 genuine, 3,000 impostor; CALFW
impostors are matched by gender and race). The images come from the Hugging Face
mirrors marcelohaps/calfw (raw 250x250 LFW-style images, so our SCRFD detection and
alignment run as on LFW) and marcelohaps/cplfw (224x224 pre-aligned crops, the only
version mirrored).

Both datasets reuse LFW identities, some of which are in the LFW training split that
fits the PCA and selects tau. Every number is therefore reported twice: over all
pairs, and over 'unseen' pairs whose two identities are both outside that split.

Deployed encoding: InsightFace buffalo_l -> PCA-128 (fitted on the LFW training
identities, as everywhere else) -> circuit decision at tau = 0.35 on sigma = 5e5
integers, exactly as FaceAuth(128, 20, 1225, 10000, 10) decides.

Usage (from model/):
  source gpu_env.sh && venv312/bin/python cross_lfw_eval.py --embed   # GPU, once (~10-15 min)
  venv312/bin/python cross_lfw_eval.py                                 # evaluation (seconds)
Output: ../api-server/benchmark/cross_lfw_eval.json
"""

import argparse
import csv
import json
import os
import re
import sys

import numpy as np
from sklearn.decomposition import PCA

EMBED = "--embed" in sys.argv
if EMBED:
    import biometric_accuracy_eval as ev   # imports the real app.py pipeline
import face_model_sweep as fs              # stubs `app` unless the real one is already loaded
ev = fs.ev

CACHE = "face_embeddings_insightface_buffalo_l"
DIM, TAU = 128, 35
SETS = {
    "calfw": {"root": f"{fs.D}/calfw", "images": "raw", "a": "image_a_raw_path", "b": "image_b_raw_path"},
    "cplfw": {"root": f"{fs.D}/cplfw", "images": "train", "a": "image_a_path", "b": "image_b_path"},
}


def identity(fname):
    """'Carl_Reiner_0003.jpg' (CALFW) or 'Carl_Reiner_3.jpg' (CPLFW) -> 'Carl_Reiner'."""
    return re.sub(r"_\d+\.jpg$", "", os.path.basename(fname))


def load_pairs(cfg):
    out = []
    with open(os.path.join(cfg["root"], "pairs.csv"), newline="") as f:
        for r in csv.DictReader(f):
            a = os.path.join(cfg["root"], cfg["images"], r[cfg["a"]])
            b = os.path.join(cfg["root"], cfg["images"], r[cfg["b"]])
            out.append((a, b, r["is_same"] == "1", identity(r["image_a"]), identity(r["image_b"])))
    return out


def scores_and_decisions(pairs, Z_of):
    """Cosine scores and exact circuit decisions for (genuine, impostor) pairs."""
    keep = [p for p in pairs if p[0] in Z_of and p[1] in Z_of]
    paths = sorted({x for p in keep for x in p[:2]})
    idx = {x: k for k, x in enumerate(paths)}
    Z = np.array([Z_of[x] for x in paths])
    ij = np.array([(idx[p[0]], idx[p[1]]) for p in keep], dtype=np.int64).reshape(-1, 2)
    same = np.array([p[2] for p in keep])
    cos = fs.scores(Z, ij)
    acc = fs.circuit_accepts_exact(fs.integer_terms(Z, ij), TAU)
    return cos[same], cos[~same], acc[same], acc[~same]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--embed", action="store_true", help="embed the images on the GPU into the shared cache")
    args = ap.parse_args()

    cache = ev.open_cache(CACHE, ev.DEFAULT_CACHE_DIR, False)
    pairs = {name: load_pairs(cfg) for name, cfg in SETS.items()}

    if args.embed:
        ev.pipeline.init_models(insightface=True, facenet=False, insightface_pack="buffalo_l")
        for name, ps in pairs.items():
            paths = sorted({x for p in ps for x in p[:2]})
            print(f"{name}: embedding {len(paths)} images")
            ev.embed_all_faces(paths, cache=cache, embedder=ev.insightface_embedder())
        cache.close()
        print("done — now run without --embed")
        return

    ids = ev.scan_identity_folders(fs.LFW)
    train_ids, _ = ev.split_identities(ids, train_frac=0.6)
    train = {p: np.asarray(cache[p], dtype=np.float64) for v in train_ids.values() for p in v if p in cache}
    pca = PCA(n_components=DIM, random_state=ev.SEED).fit(np.array(list(train.values())))

    res = {"encoding": f"PCA-{DIM} (LFW training identities)", "tau": TAU / 100, "sets": {}}
    for name, ps in pairs.items():
        paths = sorted({x for p in ps for x in p[:2]})
        raw = {x: np.asarray(cache[x], dtype=np.float64) for x in paths if x in cache}
        names = list(raw)
        X = np.array([raw[x] for x in names])
        Z_raw = dict(zip(names, fs.unit_rows(X)))
        Z_pca = dict(zip(names, fs.unit_rows(pca.transform(X))))
        entry = {"images": len(paths), "embedded": len(raw)}
        subsets = {"all": ps, "unseen": [p for p in ps if p[3] not in train_ids and p[4] not in train_ids]}
        for sub, sp in subsets.items():
            g_raw, i_raw, _, _ = scores_and_decisions(sp, Z_raw)
            g, i, acc_g, acc_i = scores_and_decisions(sp, Z_pca)
            boot, diff = ev.bootstrap_eer({"raw": (g_raw, i_raw), "pca": (g, i)})
            entry[sub] = {"genuine_pairs": len(g), "impostor_pairs": len(i),
                          "eer_raw": boot["raw"], "eer_pca": boot["pca"], "raw_minus_pca": diff["raw-pca"],
                          "circuit_frr": round(1 - float(acc_g.mean()), 5),
                          "circuit_far": round(float(acc_i.mean()), 5),
                          "circuit_false_accepts": int(acc_i.sum())}
            print(f"{name:>6} {sub:>6}: {len(g)}+{len(i)} pairs  EER raw {100 * boot['raw']['eer']:.2f}%  "
                  f"PCA-{DIM} {100 * boot['pca']['eer']:.2f}% {boot['pca']['ci95']}  "
                  f"circuit FRR {100 * entry[sub]['circuit_frr']:.2f}%  FAR {100 * entry[sub]['circuit_far']:.3f}%")
        res["sets"][name] = entry
    cache.close()
    out = os.path.join(ev.RESULTS_DIR, "cross_lfw_eval.json")
    with open(out, "w") as f:
        json.dump(res, f, indent=2)
    print(f"→ {out}")


if __name__ == "__main__":
    main()
