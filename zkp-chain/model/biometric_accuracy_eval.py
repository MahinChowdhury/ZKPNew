#!/usr/bin/env python3
"""
===================================================================
 Biometric Accuracy Evaluation — Real Dataset Harness
===================================================================
Computes FAR/FRR/EER for the face (raw-128D / PCA-64D / SOPQ-64D) and iris
(full IrisCode / uniform-stride-256 / GBSM-256) pipelines by running actual
images through the same detection + FaceNet + Log-Gabor code in app.py.

This intentionally does NOT fall back to synthetic/simulated distributions.
If a dataset path is missing or a split can't be scored, the script raises
instead of guessing — a prior version of this file used
`random.gauss(mu, sigma, ...)` with hand-picked parameters to *simulate*
plausible-looking LFW/CASIA statistics, and those simulated numbers ended up
quoted in the paper as if they were measured. Do not reintroduce that.

Expected dataset layout:
  --lfw-root DIR         DIR/<identity_name>/<image>.jpg   (LFW-deepfunneled style)
  --celeba-root DIR      same ImageFolder style, used only for cross-dataset face eval
  --casia-thousand-root DIR   DIR/<subject_id>/<L_or_R>/<image>.jpg (or .bmp)
  --casia-interval-root DIR   same style, used only for cross-dataset iris eval

Run from this directory (so relative model paths in app.py resolve), e.g.:
  python biometric_accuracy_eval.py \
      --lfw-root /data/lfw-deepfunneled \
      --celeba-root /data/celeba_by_identity \
      --casia-thousand-root /data/CASIA-Iris-Thousand \
      --casia-interval-root /data/CASIA-Iris-Interval

Demographic-parity and presentation-attack numbers are only computed if you
pass --face-attributes-csv / --pad-spoof-dir; otherwise those sections are
marked SKIPPED in the output rather than fabricated.
"""

import argparse
import json
import os
import random
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as pipeline  # noqa: E402  (reuses the live server's real pipeline)
import sopq as sopq_mod  # noqa: E402
import gbsm as gbsm_mod  # noqa: E402

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "api-server", "benchmark")
IMG_EXTS = (".jpg", ".jpeg", ".png", ".bmp")
SEED = 42


# ------------------------------------------------------------------
# Dataset scanning
# ------------------------------------------------------------------
def scan_identity_folders(root):
    """root/<identity>/<image> -> {identity: [filepaths]}"""
    identities = defaultdict(list)
    for identity in sorted(os.listdir(root)):
        idir = os.path.join(root, identity)
        if not os.path.isdir(idir):
            continue
        for fname in sorted(os.listdir(idir)):
            if fname.lower().endswith(IMG_EXTS):
                identities[identity].append(os.path.join(idir, fname))
    if not identities:
        raise FileNotFoundError(f"No identity subfolders with images found under {root}")
    return identities


def scan_iris_subject_folders(root):
    """root/<subject_id>/<L_or_R>/<image> -> {"subject_eye": [filepaths]}"""
    subjects = defaultdict(list)
    for subject in sorted(os.listdir(root)):
        sdir = os.path.join(root, subject)
        if not os.path.isdir(sdir):
            continue
        for eye in sorted(os.listdir(sdir)):
            edir = os.path.join(sdir, eye)
            if not os.path.isdir(edir):
                continue
            key = f"{subject}_{eye}"
            for fname in sorted(os.listdir(edir)):
                if fname.lower().endswith(IMG_EXTS):
                    subjects[key].append(os.path.join(edir, fname))
    if not subjects:
        raise FileNotFoundError(
            f"No <subject>/<L|R>/<image> structure found under {root}"
        )
    return subjects


def split_identities(identities: dict, train_frac=0.6, seed=SEED):
    keys = list(identities.keys())
    rng = random.Random(seed)
    rng.shuffle(keys)
    cut = int(len(keys) * train_frac)
    train_keys, test_keys = keys[:cut], keys[cut:]
    return {k: identities[k] for k in train_keys}, {k: identities[k] for k in test_keys}


# ------------------------------------------------------------------
# Pair generation
# ------------------------------------------------------------------
def make_pairs(identities: dict, max_pairs=6000, seed=SEED, max_per_identity=50):
    """Returns (genuine_pairs, impostor_pairs) as lists of (path_a, path_b).

    Identities with many images (e.g. LFW's most-photographed people) are
    capped per-identity before shuffling, so one identity with hundreds of
    images can't dominate the pool or blow up combinatorially.
    """
    rng = random.Random(seed)
    genuine = []

    multi = {k: v for k, v in identities.items() if len(v) >= 2}
    for imgs in multi.values():
        if len(imgs) <= 10:
            combos = [(imgs[i], imgs[j]) for i in range(len(imgs)) for j in range(i + 1, len(imgs))]
        else:
            combos = [tuple(rng.sample(imgs, 2)) for _ in range(max_per_identity)]
        genuine.extend(combos)
    rng.shuffle(genuine)
    genuine = genuine[:max_pairs]

    keys = list(identities.keys())
    if len(keys) < 2:
        raise ValueError("Need >=2 identities to build impostor pairs")
    attempts = 0
    target = len(genuine) if genuine else max_pairs
    while len(impostor) < target and attempts < target * 20:
        attempts += 1
        a, b = rng.sample(keys, 2)
        impostor.append((rng.choice(identities[a]), rng.choice(identities[b])))

    if not genuine:
        raise ValueError("No identity in this dataset has >=2 images — cannot form genuine pairs")
    return genuine, impostor


# ------------------------------------------------------------------
# EER / FAR / FRR (unchanged math, now fed real scores)
# ------------------------------------------------------------------
def eval_cosine(genuine, impostor, steps=500, t_min=0.0, t_max=1.0):
    best_diff, best_eer, best_th = 999.0, 0.0, 0.5
    n_g, n_i = len(genuine), len(impostor)
    for s in range(steps + 1):
        t = t_min + (t_max - t_min) * (s / steps)
        far = sum(1 for x in impostor if x >= t) / n_i
        frr = sum(1 for x in genuine if x < t) / n_g
        diff = abs(far - frr)
        if diff < best_diff:
            best_diff, best_eer, best_th = diff, (far + frr) / 2.0, t
    return best_eer, best_th


def eval_hamming(genuine, impostor, steps=500, t_min=0.0, t_max=0.6):
    best_diff, best_eer, best_th = 999.0, 0.0, 0.4
    n_g, n_i = len(genuine), len(impostor)
    for s in range(steps + 1):
        t = t_min + (t_max - t_min) * (s / steps)
        far = sum(1 for x in impostor if x <= t) / n_i
        frr = sum(1 for x in genuine if x > t) / n_g
        diff = abs(far - frr)
        if diff < best_diff:
            best_diff, best_eer, best_th = diff, (far + frr) / 2.0, t
    return best_eer, best_th


def get_rates_cosine(genuine, impostor, t):
    return (sum(1 for x in impostor if x >= t) / len(impostor),
            sum(1 for x in genuine if x < t) / len(genuine))


def get_rates_hamming(genuine, impostor, t):
    return (sum(1 for x in impostor if x <= t) / len(impostor),
            sum(1 for x in genuine if x > t) / len(genuine))


# ------------------------------------------------------------------
# Face evaluation
# ------------------------------------------------------------------
def embed_all_faces(paths):
    """path -> (raw128, conf). Skips images with no detected face."""
    out = {}
    for i, p in enumerate(paths):
        try:
            with open(p, "rb") as f:
                raw128, conf = pipeline.get_raw_embedding_from_bytes(f.read())
            out[p] = raw128
        except Exception as e:
            print(f"  ⚠ skip {p}: {e}")
        if (i + 1) % 200 == 0:
            print(f"  ...embedded {i + 1}/{len(paths)}")
    return out


def cosine_scores(pairs, embeddings):
    scores = []
    for a, b in pairs:
        if a in embeddings and b in embeddings:
            scores.append(float(np.dot(embeddings[a], embeddings[b])))
    return scores


def run_face_eval(args):
    print("=" * 85)
    print("FACE — loading dataset and computing FaceNet embeddings (this hits the real pipeline)")
    identities = scan_identity_folders(args.lfw_root)
    train_ids, test_ids = split_identities(identities, train_frac=args.train_frac)

    train_paths = [p for imgs in train_ids.values() for p in imgs]
    test_paths = [p for imgs in test_ids.values() for p in imgs]
    print(f"  {len(identities)} identities total -> {len(train_ids)} train / {len(test_ids)} test")

    print("Embedding train split (for fitting SOPQ)...")
    train_emb = embed_all_faces(train_paths)
    print("Embedding test split (for measuring EER)...")
    test_emb = embed_all_faces(test_paths)

    # Fit SOPQ strictly on train identities
    train_labels_flat, train_vecs = [], []
    for ident, paths in train_ids.items():
        for p in paths:
            if p in train_emb:
                train_vecs.append(train_emb[p])
                train_labels_flat.append(ident)
    W = sopq_mod.fit_sopq(np.array(train_vecs), np.array(train_labels_flat), out_dim=64)

    def to_pca64(v):
        reduced = pipeline.pca_model.transform(v.reshape(1, -1))[0]
        return reduced / np.linalg.norm(reduced)

    pca64 = {p: to_pca64(v) for p, v in test_emb.items()}
    sopq64 = {p: sopq_mod.apply_sopq(W, v) for p, v in test_emb.items()}

    genuine_pairs, impostor_pairs = make_pairs(test_ids, max_pairs=args.max_pairs)
    print(f"  {len(genuine_pairs)} genuine / {len(impostor_pairs)} impostor face pairs")

    g128, i128 = cosine_scores(genuine_pairs, test_emb), cosine_scores(impostor_pairs, test_emb)
    g_pca, i_pca = cosine_scores(genuine_pairs, pca64), cosine_scores(impostor_pairs, pca64)
    g_sopq, i_sopq = cosine_scores(genuine_pairs, sopq64), cosine_scores(impostor_pairs, sopq64)

    eer128, th128 = eval_cosine(g128, i128)
    eer_pca, th_pca = eval_cosine(g_pca, i_pca)
    eer_sopq, th_sopq = eval_cosine(g_sopq, i_sopq)
    far_pca_op, frr_pca_op = get_rates_cosine(g_pca, i_pca, 0.50)
    far_sopq_op, frr_sopq_op = get_rates_cosine(g_sopq, i_sopq, 0.50)

    denom = (eer_pca - eer128)
    recovery = ((eer_pca - eer_sopq) / denom * 100) if abs(denom) > 1e-9 else float("nan")

    result = {
        "raw_128d": {"eer": round(eer128, 5), "th": round(th128, 3),
                     "n_genuine": len(g128), "n_impostor": len(i128)},
        "pca_64d": {"eer": round(eer_pca, 5), "th": round(th_pca, 3),
                    "far_op": round(far_pca_op, 5), "frr_op": round(frr_pca_op, 5)},
        "sopq_64d": {"eer": round(eer_sopq, 5), "th": round(th_sopq, 3),
                     "far_op": round(far_sopq_op, 5), "frr_op": round(frr_sopq_op, 5)},
        "recovery_pct": round(recovery, 1) if recovery == recovery else None,
        "source": "measured",
    }

    if args.celeba_root:
        print("Cross-dataset (CelebA): applying LFW-trained SOPQ without retraining...")
        celeba_ids = scan_identity_folders(args.celeba_root)
        celeba_emb = embed_all_faces([p for imgs in celeba_ids.values() for p in imgs])
        celeba_sopq = {p: sopq_mod.apply_sopq(W, v) for p, v in celeba_emb.items()}
        g_pairs, i_pairs = make_pairs(celeba_ids, max_pairs=args.max_pairs)
        eer_celeba, th_celeba = eval_cosine(
            cosine_scores(g_pairs, celeba_sopq), cosine_scores(i_pairs, celeba_sopq)
        )
        result["celeba_64d_sopq"] = {"eer": round(eer_celeba, 5), "th": round(th_celeba, 3),
                                      "source": "measured"}
    else:
        result["celeba_64d_sopq"] = {"status": "SKIPPED — pass --celeba-root to measure this"}

    result["demographic_fairness"] = (
        {"status": "SKIPPED — pass --face-attributes-csv to measure this"}
        if not args.face_attributes_csv else {"status": "NOT_IMPLEMENTED_YET"}
    )
    result["pad_resilience"] = (
        {"status": "SKIPPED — pass --pad-spoof-dir to measure this"}
        if not args.pad_spoof_dir else {"status": "NOT_IMPLEMENTED_YET"}
    )
    return result, W


# ------------------------------------------------------------------
# Iris evaluation
# ------------------------------------------------------------------
def extract_all_iris(paths):
    out = {}
    for i, p in enumerate(paths):
        try:
            with open(p, "rb") as f:
                code, mask, quality = pipeline.get_iris_code_from_bytes(f.read())
            out[p] = (code, mask)
        except Exception as e:
            print(f"  ⚠ skip {p}: {e}")
        if (i + 1) % 200 == 0:
            print(f"  ...extracted {i + 1}/{len(paths)}")
    return out


def masked_hamming(code_a, mask_a, code_b, mask_b):
    joint = mask_a & mask_b
    n_valid = int(joint.sum())
    if n_valid < 1:
        return 1.0
    return float((code_a ^ code_b)[joint == 1].sum()) / n_valid


def roll_flat(flat, width, shift):
    grid = flat.reshape(-1, width)
    return np.roll(grid, shift, axis=1).ravel()


def best_rotation_hd(code_a, mask_a, code_b, mask_b, width, n_shifts=8):
    best_hd, best_shift = 1.0, 0
    for shift in range(-n_shifts, n_shifts + 1):
        rb = roll_flat(code_b, width, shift)
        rm = roll_flat(mask_b, width, shift)
        hd = masked_hamming(code_a, mask_a, rb, rm)
        if hd < best_hd:
            best_hd, best_shift = hd, shift
    return best_hd, best_shift


def run_iris_eval(args):
    print("=" * 85)
    print("IRIS — loading dataset and extracting IrisCodes (this hits the real pipeline)")
    subjects = scan_iris_subject_folders(args.casia_thousand_root)
    train_subj, test_subj = split_identities(subjects, train_frac=args.train_frac)

    train_paths = [p for imgs in train_subj.values() for p in imgs]
    test_paths = [p for imgs in test_subj.values() for p in imgs]
    print(f"  {len(subjects)} subject-eyes total -> {len(train_subj)} train / {len(test_subj)} test")

    print("Extracting train split (for fitting GBSM salience)...")
    train_codes = extract_all_iris(train_paths)
    print("Extracting test split (for measuring EER)...")
    test_codes = extract_all_iris(test_paths)

    code_len = next(iter(train_codes.values()))[0].shape[0]

    train_labels, codes_arr, masks_arr = [], [], []
    for ident, paths in train_subj.items():
        for p in paths:
            if p in train_codes:
                c, m = train_codes[p]
                codes_arr.append(c)
                masks_arr.append(m)
                train_labels.append(ident)
    salience = gbsm_mod.compute_bit_salience(np.array(codes_arr), np.array(masks_arr),
                                              np.array(train_labels))
    gbsm_idx = gbsm_mod.select_top_bits(salience, d=256)
    stride_idx = gbsm_mod.stride_baseline(code_len, d=256)

    genuine_pairs, impostor_pairs = make_pairs(test_subj, max_pairs=args.max_pairs)
    print(f"  {len(genuine_pairs)} genuine / {len(impostor_pairs)} impostor iris pairs")

    def score_pairs(pairs):
        full, stride, gbsm = [], [], []
        for a, b in pairs:
            if a not in test_codes or b not in test_codes:
                continue
            ca, ma = test_codes[a]
            cb, mb = test_codes[b]
            hd_full, shift = best_rotation_hd(ca, ma, cb, mb, pipeline.NORM_WIDTH)
            cb_r = roll_flat(cb, pipeline.NORM_WIDTH, shift)
            mb_r = roll_flat(mb, pipeline.NORM_WIDTH, shift)
            full.append(hd_full)
            stride.append(masked_hamming(ca[stride_idx], ma[stride_idx], cb_r[stride_idx], mb_r[stride_idx]))
            gbsm.append(masked_hamming(ca[gbsm_idx], ma[gbsm_idx], cb_r[gbsm_idx], mb_r[gbsm_idx]))
        return full, stride, gbsm

    g_full, g_stride, g_gbsm = score_pairs(genuine_pairs)
    i_full, i_stride, i_gbsm = score_pairs(impostor_pairs)

    eer_full, th_full = eval_hamming(g_full, i_full)
    eer_stride, th_stride = eval_hamming(g_stride, i_stride)
    eer_gbsm, th_gbsm = eval_hamming(g_gbsm, i_gbsm)
    far_stride_op, frr_stride_op = get_rates_hamming(g_stride, i_stride, 0.478)
    far_gbsm_op, frr_gbsm_op = get_rates_hamming(g_gbsm, i_gbsm, 0.478)

    denom = (eer_stride - eer_full)
    recovery = ((eer_stride - eer_gbsm) / denom * 100) if abs(denom) > 1e-9 else float("nan")

    result = {
        "code_length": int(code_len),
        "full": {"eer": round(eer_full, 5), "th": round(th_full, 3),
                 "n_genuine": len(g_full), "n_impostor": len(i_full)},
        "strided_256": {"eer": round(eer_stride, 5), "th": round(th_stride, 3),
                         "far_op": round(far_stride_op, 5), "frr_op": round(frr_stride_op, 5)},
        "gbsm_256": {"eer": round(eer_gbsm, 5), "th": round(th_gbsm, 3),
                     "far_op": round(far_gbsm_op, 5), "frr_op": round(frr_gbsm_op, 5)},
        "recovery_pct": round(recovery, 1) if recovery == recovery else None,
        "source": "measured",
    }

    if args.casia_interval_root:
        print("Cross-dataset (CASIA-Interval): applying Thousand-trained GBSM mask without refitting...")
        interval_subj = scan_iris_subject_folders(args.casia_interval_root)
        interval_codes = extract_all_iris([p for imgs in interval_subj.values() for p in imgs])
        g_pairs, i_pairs = make_pairs(interval_subj, max_pairs=args.max_pairs)

        def score_gbsm_only(pairs):
            # Rotation search must run on the FULL rectangular code (the roll
            # is a circular shift along the theta axis of the (filter, row,
            # col) grid); the GBSM-selected 256 bits are scattered indices
            # into that grid and can't be reshaped/rolled on their own.
            scores = []
            for a, b in pairs:
                if a not in interval_codes or b not in interval_codes:
                    continue
                ca, ma = interval_codes[a]
                cb, mb = interval_codes[b]
                _, shift = best_rotation_hd(ca, ma, cb, mb, pipeline.NORM_WIDTH, n_shifts=4)
                cb_r = roll_flat(cb, pipeline.NORM_WIDTH, shift)
                mb_r = roll_flat(mb, pipeline.NORM_WIDTH, shift)
                scores.append(masked_hamming(ca[gbsm_idx], ma[gbsm_idx], cb_r[gbsm_idx], mb_r[gbsm_idx]))
            return scores

        eer_interval, th_interval = eval_hamming(score_gbsm_only(g_pairs), score_gbsm_only(i_pairs))
        result["interval_256_gbsm"] = {"eer": round(eer_interval, 5), "th": round(th_interval, 3),
                                        "source": "measured"}
    else:
        result["interval_256_gbsm"] = {"status": "SKIPPED — pass --casia-interval-root to measure this"}

    result["pad_resilience"] = (
        {"status": "SKIPPED — pass --pad-spoof-dir to measure this"}
        if not args.pad_spoof_dir else {"status": "NOT_IMPLEMENTED_YET"}
    )
    return result


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lfw-root", help="root/<identity>/<image> face dataset")
    ap.add_argument("--celeba-root", help="same layout, cross-dataset face eval only")
    ap.add_argument("--casia-thousand-root", help="root/<subject>/<L|R>/<image> iris dataset")
    ap.add_argument("--casia-interval-root", help="same layout, cross-dataset iris eval only")
    ap.add_argument("--face-attributes-csv", help="optional filename->gender/ethnicity metadata")
    ap.add_argument("--pad-spoof-dir", help="optional spoof/replay image set for PAD metrics")
    ap.add_argument("--train-frac", type=float, default=0.6)
    ap.add_argument("--max-pairs", type=int, default=6000)
    ap.add_argument("--out", default=os.path.join(RESULTS_DIR, "biometric_accuracy_results.json"))
    args = ap.parse_args()

    if not args.lfw_root and not args.casia_thousand_root:
        ap.error("Provide at least --lfw-root or --casia-thousand-root — there is no synthetic "
                  "fallback in this script anymore.")

    print("Initializing real pipeline models (FaceNet / MediaPipe / Log-Gabor bank)...")
    pipeline.init_models()

    results = {}
    if args.lfw_root:
        results["face"], _ = run_face_eval(args)
    if args.casia_thousand_root:
        results["iris"] = run_iris_eval(args)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print("=" * 85)
    print(f"Wrote real, measured results to {args.out}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
