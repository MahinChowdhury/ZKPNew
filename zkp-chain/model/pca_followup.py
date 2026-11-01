"""
pca_followup.py — results for a PCA-d encoding of a cached face model, and
optionally the deployed PCA file.

Deployed (author decision 2026-10-31, selected on validation identities by
select_operating_point.py): InsightFace
buffalo_l -> PCA-96, cos >= 0.33 (tau_num/tau_den = 1089/10000). The FaceNet
PCA-64 at 25/100 is the pre-revision baseline (default label 'facenet').

Uses only the embeddings cached by `run_face_eval.sh <model>`, with the
identical LFW split, pairs and CelebA identity sample (same SEED), so it runs
in seconds and needs no GPU. Reports LFW EER (bootstrap CI), the circuit's own
FAR/FRR at tau_num/tau_den, the PCA dimension sweep, template inversion, and
CelebA cross-dataset and gender-fairness EER, all on the PCA-d encoding.

Outputs
  ../api-server/benchmark/biometric_accuracy_pca.json          (label facenet)
  ../api-server/benchmark/biometric_accuracy_pca_<label>.json  (other labels)
  pca_model_<d>d.pkl   with --deploy (loaded by app.py)

Usage (from model/):
  venv312/bin/python pca_followup.py                                   # FaceNet baseline
  venv312/bin/python pca_followup.py --cache face_embeddings_insightface_buffalo_l \
      --label insightface --dim 96 --tau-num 1089 --tau-den 10000 --deploy
"""

import argparse
import json
import os
import pickle
import random
import sys
import types

import numpy as np
from sklearn.decomposition import PCA

sys.modules.setdefault("app", types.ModuleType("app"))   # embeddings come from the cache
import biometric_accuracy_eval as ev                      # noqa: E402

D = "../Datasets"   # must match run_face_eval.sh: cache keys are these relative paths
LFW = f"{D}/lfw_kaggle/lfw-deepfunneled/lfw-deepfunneled"
CELEBA_IMG, CELEBA_ID, CELEBA_ATTR = f"{D}/img_align_celeba", f"{D}/identity_CelebA.txt", f"{D}/list_attr_celeba.txt"
DIMS = [16, 32, 48, 64, 80, 96, 112, 128]


def unit(v):
    return v / np.linalg.norm(v)


def scores(pairs, emb):
    return ev.cosine_scores(pairs, emb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default="face_embeddings")
    ap.add_argument("--label", default="facenet")
    ap.add_argument("--dim", type=int, default=64)
    ap.add_argument("--tau-num", type=int, default=25)
    ap.add_argument("--tau-den", type=int, default=100)
    ap.add_argument("--sigma", type=int, default=500_000, help="fixed-point scale (deployed circuit: 5e5)")
    ap.add_argument("--deploy", action="store_true", help=f"write pca_model_<dim>d.pkl for app.py")
    args = ap.parse_args()
    out_path = os.path.join(ev.RESULTS_DIR, "biometric_accuracy_pca.json" if args.label == "facenet"
                            else f"biometric_accuracy_pca_{args.label}.json")

    cache = ev.open_cache(args.cache, ev.DEFAULT_CACHE_DIR, False)

    def cached(paths):
        out = {}
        for p in paths:
            if p in cache:
                out[p] = np.asarray(cache[p])
        return out

    # ---------------- LFW: same split and pairs as the evaluation run ----------------
    ids = ev.scan_identity_folders(LFW)
    train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
    train = cached([p for v in train_ids.values() for p in v])
    test = cached([p for v in test_ids.values() for p in v])
    assert train and test, f"no cached embeddings in '{args.cache}' — run `bash model/run_face_eval.sh` first"
    X = np.array(list(train.values()))
    g_pairs, i_pairs = ev.make_pairs(test_ids, max_pairs=6000)

    pca = PCA(n_components=args.dim, random_state=ev.SEED).fit(X)
    enc = {p: unit(pca.transform(v.reshape(1, -1))[0]) for p, v in test.items()}
    g, i = scores(g_pairs, enc), scores(i_pairs, enc)

    res = {"encoding": f"PCA-{args.dim} of {args.label} ({X.shape[1]}-D), fitted on the LFW training split",
           "cache": args.cache, "dim": args.dim,
           "train_images": len(train), "test_images": len(test),
           "n_genuine": len(g), "n_impostor": len(i)}
    ci, _ = ev.bootstrap_eer({"pca": (g, i)}, n_boot=1000)
    res["lfw"] = ci["pca"]

    acc_g = ev.quantized_rates(g_pairs, enc, args.tau_num, args.tau_den, sigma=args.sigma)
    acc_i = ev.quantized_rates(i_pairs, enc, args.tau_num, args.tau_den, sigma=args.sigma)
    res["circuit_op"] = {"far": round(sum(acc_i) / len(acc_i), 5),
                         "frr": round(1 - sum(acc_g) / len(acc_g), 5),
                         "tau": round((args.tau_num / args.tau_den) ** 0.5, 4),
                         "tau_num": args.tau_num, "tau_den": args.tau_den, "sigma": args.sigma}

    # Dimension sweep (Fig. encoding_pareto)
    sweep = {}
    for d in [d for d in DIMS if d <= X.shape[1]]:
        p_d = PCA(n_components=d, random_state=ev.SEED).fit(X)
        e_d = {p: unit(p_d.transform(v.reshape(1, -1))[0]) for p, v in test.items()}
        sweep[d] = round(ev.eer_np(scores(g_pairs, e_d), scores(i_pairs, e_d)), 5)
    res["pca_dim_sweep"] = sweep

    # Template inversion: attacker holds a leaked normalized template and the
    # public projection (components, mean). Rescale by the typical training
    # norm, invert, and compare with the true full-dimension embedding.
    z_norm = float(np.mean(np.linalg.norm(pca.transform(X), axis=1)))
    recon = {p: unit(pca.inverse_transform((z_norm * enc[p]).reshape(1, -1))[0]) for p in enc}
    res["inversion"] = {
        "mean_cosine_to_true": round(float(np.mean([np.dot(recon[p], unit(test[p])) for p in recon])), 4),
        # impersonation: reconstructed probe vs raw gallery of other images
        "impersonation_eer": round(ev.eer_np(
            [float(np.dot(recon[a], unit(test[b]))) for a, b in g_pairs if a in recon and b in test],
            [float(np.dot(recon[a], unit(test[b]))) for a, b in i_pairs if a in recon and b in test]), 5),
        # reference: the same raw-vs-raw pairs, i.e. a genuine sample
        "raw_eer": round(ev.eer_np(
            [float(np.dot(unit(test[a]), unit(test[b]))) for a, b in g_pairs if a in test and b in test],
            [float(np.dot(unit(test[a]), unit(test[b]))) for a, b in i_pairs if a in test and b in test]), 5),
    }

    # ---------------- CelebA: same 2,000-identity sample, LFW-trained PCA ----------------
    celeba_ids = ev.scan_celeba_flat(CELEBA_IMG, CELEBA_ID)
    keep = random.Random(ev.SEED).sample(list(celeba_ids.keys()), 2000)
    celeba_ids = {k: celeba_ids[k] for k in keep}
    cel = cached([p for v in celeba_ids.values() for p in v])
    cel_enc = {p: unit(pca.transform(v.reshape(1, -1))[0]) for p, v in cel.items()}
    cg, ci_ = ev.make_pairs(celeba_ids, max_pairs=6000)
    cel_ci, _ = ev.bootstrap_eer({"pca": (scores(cg, cel_enc), scores(ci_, cel_enc))}, n_boot=1000)
    res["celeba"] = cel_ci["pca"] | {"embedded": [len(cel), sum(len(v) for v in celeba_ids.values())]}

    gender = ev.load_celeba_gender_labels(CELEBA_ATTR)
    fair = {}
    for label, code in (("male", "M"), ("female", "F")):
        subset = {k: v for k, v in celeba_ids.items() if ev.identity_gender(v, gender) == code}
        sg, si = ev.make_pairs(subset, max_pairs=6000)
        f_ci, _ = ev.bootstrap_eer({"pca": (scores(sg, cel_enc), scores(si, cel_enc))}, n_boot=1000)
        fair[label] = f_ci["pca"] | {"n_identities": len(subset)}
    res["fairness"] = fair

    cache.close()

    if args.deploy:
        # app.py loads this file and L2-normalizes after transform
        with open(f"pca_model_{args.dim}d.pkl", "wb") as f:
            pickle.dump(pca, f)

    with open(out_path, "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))
    print(f"→ {out_path}" + (f"\n→ pca_model_{args.dim}d.pkl (deployed)" if args.deploy else ""))


if __name__ == "__main__":
    main()
