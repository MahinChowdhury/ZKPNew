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
  --celeba-root DIR      either the same per-identity ImageFolder style, OR the flat
                         img_align_celeba/ directory CelebA actually ships as — pair the
                         latter with --celeba-identity-file pointing at identity_CelebA.txt
  --casia-thousand-root DIR   DIR/<subject_id>/<L_or_R>/<image>.jpg (or .bmp)
  --casia-interval-root DIR   same style, used only for cross-dataset iris eval

Run from this directory (so relative model paths in app.py resolve), e.g.:
  python biometric_accuracy_eval.py \
      --lfw-root /data/lfw-deepfunneled \
      --celeba-root /data/CelebA/img_align_celeba/img_align_celeba \
      --celeba-identity-file /data/CelebA/identity_CelebA.txt \
      --celeba-max-identities 2000 \
      --casia-thousand-root /data/CASIA-Iris-Thousand \
      --casia-interval-root /data/CASIA-Iris-Interval

Demographic-parity and presentation-attack numbers are only computed if you
pass --face-attributes-csv / --pad-spoof-dir; otherwise those sections are
marked SKIPPED in the output rather than fabricated.

Resumability & memory: every embedding/iris-code is cached to disk under
--cache-dir (default ./eval_cache) as it's computed. A rerun with the same
--cache-dir skips anything already done instead of recomputing it — so a
crash partway through only costs work done since the cache was last written,
not the whole run. For iris specifically, the cache isn't just a resumability
nicety: a full CASIA-Iris-Thousand run needs ~20,000 code+mask pairs
(~384KB each, ~7.7GB total) which will exhaust a memory-constrained VM if
held in a plain in-memory dict, so pair-scoring reads codes from the disk
cache on demand instead. Pass --no-cache to disable and go back to
plain-dict behavior (not recommended for a full iris run).

Pause/resume: press Ctrl+C at any point (or `kill` the process — SIGTERM is
handled the same way) to pause. This flushes and closes every open cache
cleanly before exiting rather than relying solely on shelve's per-write
durability, so nothing done so far is at risk. Rerunning the exact same
command afterward resumes automatically — cached embeddings/iris-codes are
skipped, so only unfinished work is recomputed. Results are also written to
--out incrementally, once per completed section (face, then iris), not only
at the very end — so if you pause between sections, or iris fails/is paused
partway, whatever finished is already on disk in --out rather than lost.
"""

import argparse
import csv
import json
import os
import random
import shelve
import signal
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as pipeline  # noqa: E402  (reuses the live server's real pipeline)
import sopq as sopq_mod  # noqa: E402
import gbsm as gbsm_mod  # noqa: E402

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "api-server", "benchmark")
DEFAULT_CACHE_DIR = os.path.join(os.path.dirname(__file__), ".eval_cache")
IMG_EXTS = (".jpg", ".jpeg", ".png", ".bmp")
SEED = 42


# ------------------------------------------------------------------
# Disk-backed caching
# ------------------------------------------------------------------
# Two independent problems, one mechanism:
#   1. Resumability — a multi-hour run with no checkpointing means a crash
#      (OOM, terminal closed, power loss) loses every embedding computed so
#      far. Every path we process gets written to a shelve db immediately, so
#      a rerun skips anything already done instead of recomputing from zero.
#   2. Peak memory — an iris code+mask pair is ~384KB (512x64x3x2 bits each
#      way); a full CASIA-Iris-Thousand-scale run (train+test) needs ~20,000
#      of those alive at once if held in a plain Python dict — around 7.7GB,
#      which is enough on its own to exhaust a memory-constrained WSL2 VM.
#      A shelve db is accessed like a dict (`in`, `[]`) but pages data to/from
#      disk instead of holding everything resident, so iris code lookups
#      during pair-scoring don't require the whole dataset in RAM.
_OPEN_CACHES = []  # every shelve db opened this run, for graceful-pause flushing


def open_cache(name, cache_dir, disabled):
    """Returns a dict-like object at cache_dir/name — a real dict if caching
    is disabled (--no-cache), otherwise a disk-backed shelve.Shelf. Caller is
    responsible for closing it (a plain dict's .close() is a no-op we add via
    _NullCloseDict below); it's also tracked in _OPEN_CACHES so a Ctrl+C mid-run
    (see install_pause_handler) can flush it even if the caller never gets to."""
    if disabled:
        return _NullCloseDict()
    os.makedirs(cache_dir, exist_ok=True)
    cache = shelve.open(os.path.join(cache_dir, name))
    _OPEN_CACHES.append(cache)
    return cache


def install_pause_handler():
    """Ctrl+C (or SIGTERM) flushes every open cache cleanly and exits, instead
    of relying solely on shelve's per-write durability during an abrupt kill.
    Rerunning the same command afterward resumes from exactly this point —
    see the module docstring's Pause/resume section."""
    def _graceful_exit(signum, frame):
        print("\n\n⏸  Pausing — flushing caches before exit...")
        for cache in _OPEN_CACHES:
            try:
                cache.close()
            except Exception as e:
                print(f"  ⚠ error closing a cache (may already be closed): {e}")
        print("✓ Caches flushed. Rerun the same command to resume from here.")
        sys.exit(130 if signum == signal.SIGINT else 143)

    signal.signal(signal.SIGINT, _graceful_exit)
    signal.signal(signal.SIGTERM, _graceful_exit)


class _NullCloseDict(dict):
    def close(self):
        pass


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


def scan_celeba_flat(images_dir, identity_file):
    """CelebA's img_align_celeba ships as a flat dir of 000001.jpg.. with a
    separate identity_CelebA.txt mapping filename -> integer identity, unlike
    LFW's folder-per-identity layout. Returns the same {identity: [filepaths]}
    shape as scan_identity_folders, without copying/reorganizing the images."""
    identities = defaultdict(list)
    with open(identity_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            fname, ident = line.split()
            path = os.path.join(images_dir, fname)
            if os.path.isfile(path):
                identities[ident].append(path)
    if not identities:
        raise FileNotFoundError(
            f"No images from {identity_file} found under {images_dir}"
        )
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
    impostor = []
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
def embed_all_faces(paths, cache=None):
    """path -> raw128 embedding. Skips images with no detected face.

    `cache` (if given) is a disk-backed lookaside: entries already computed
    on a prior run are reused instead of re-running FaceNet, and every fresh
    embedding is written back before returning — so a crash partway through
    only costs the images embedded since the last successful run, not all of
    them. Face embeddings are small (~1KB each) so the returned dict is still
    fully materialized in memory; this caching is purely about not repeating
    expensive GPU work, not about memory (contrast with iris, where the
    cache itself IS the storage — see extract_all_iris_to_cache).
    """
    out = {}
    for i, p in enumerate(paths):
        if cache is not None and p in cache:
            out[p] = cache[p]
        else:
            try:
                with open(p, "rb") as f:
                    raw128, conf = pipeline.get_raw_embedding_from_bytes(f.read())
                out[p] = raw128
                if cache is not None:
                    cache[p] = raw128
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


def load_celeba_gender_labels(attr_csv_path):
    """CelebA's list_attr_celeba.csv -> {image_id filename: 'M' or 'F'}, from
    the real 'Male' attribute column (+1/-1). This is the standard binary
    gender-fairness axis used in face-verification fairness studies; CelebA
    has no ethnicity/skin-tone label, so that axis is not evaluated here."""
    labels = {}
    with open(attr_csv_path, newline="") as f:
        reader = csv.DictReader(f)
        if "Male" not in reader.fieldnames:
            raise ValueError(f"'Male' column not found in {attr_csv_path}; "
                              f"columns present: {reader.fieldnames}")
        for row in reader:
            labels[row["image_id"]] = "M" if row["Male"].strip() == "1" else "F"
    return labels


def identity_gender(paths, gender_of_file):
    """Majority vote of an identity's per-image gender labels. CelebA
    identities are single real people, so this should be unanimous in
    practice; majority vote only guards against a stray mislabeled image."""
    votes = [gender_of_file[os.path.basename(p)] for p in paths
             if os.path.basename(p) in gender_of_file]
    if not votes:
        return None
    return "M" if votes.count("M") >= votes.count("F") else "F"


def run_face_eval(args):
    print("=" * 85)
    print("FACE — loading dataset and computing FaceNet embeddings (this hits the real pipeline)")
    face_cache = open_cache("face_embeddings", args.cache_dir, args.no_cache)
    identities = scan_identity_folders(args.lfw_root)
    if args.lfw_max_identities and len(identities) > args.lfw_max_identities:
        rng = random.Random(SEED)
        keep = rng.sample(list(identities.keys()), args.lfw_max_identities)
        identities = {k: identities[k] for k in keep}
        print(f"  capped to {args.lfw_max_identities} randomly sampled LFW identities "
              f"(seed={SEED}) for tractable runtime")
    train_ids, test_ids = split_identities(identities, train_frac=args.train_frac)

    train_paths = [p for imgs in train_ids.values() for p in imgs]
    test_paths = [p for imgs in test_ids.values() for p in imgs]
    print(f"  {len(identities)} identities total -> {len(train_ids)} train / {len(test_ids)} test")

    print("Embedding train split (for fitting SOPQ)...")
    train_emb = embed_all_faces(train_paths, face_cache)
    print("Embedding test split (for measuring EER)...")
    test_emb = embed_all_faces(test_paths, face_cache)

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
        if args.celeba_identity_file:
            celeba_ids = scan_celeba_flat(args.celeba_root, args.celeba_identity_file)
        else:
            celeba_ids = scan_identity_folders(args.celeba_root)
        if args.celeba_max_identities and len(celeba_ids) > args.celeba_max_identities:
            rng = random.Random(SEED)
            keep = rng.sample(list(celeba_ids.keys()), args.celeba_max_identities)
            celeba_ids = {k: celeba_ids[k] for k in keep}
            print(f"  capped to {args.celeba_max_identities} randomly sampled CelebA identities "
                  f"(seed={SEED}) for tractable runtime")
        celeba_emb = embed_all_faces([p for imgs in celeba_ids.values() for p in imgs], face_cache)
        celeba_sopq = {p: sopq_mod.apply_sopq(W, v) for p, v in celeba_emb.items()}
        g_pairs, i_pairs = make_pairs(celeba_ids, max_pairs=args.max_pairs)
        eer_celeba, th_celeba = eval_cosine(
            cosine_scores(g_pairs, celeba_sopq), cosine_scores(i_pairs, celeba_sopq)
        )
        result["celeba_64d_sopq"] = {"eer": round(eer_celeba, 5), "th": round(th_celeba, 3),
                                      "source": "measured"}
    else:
        result["celeba_64d_sopq"] = {"status": "SKIPPED — pass --celeba-root to measure this"}

    if args.celeba_root and args.face_attributes_csv:
        print("Demographic fairness (CelebA, gender via real 'Male' attribute)...")
        gender_of_file = load_celeba_gender_labels(args.face_attributes_csv)
        male_ids = {k: v for k, v in celeba_ids.items()
                    if identity_gender(v, gender_of_file) == "M"}
        female_ids = {k: v for k, v in celeba_ids.items()
                      if identity_gender(v, gender_of_file) == "F"}
        unlabeled = len(celeba_ids) - len(male_ids) - len(female_ids)
        print(f"  {len(male_ids)} male-labeled / {len(female_ids)} female-labeled identities "
              f"({unlabeled} unlabeled) of {len(celeba_ids)} total")

        fairness = {}
        for label, subset in (("male", male_ids), ("female", female_ids)):
            if len(subset) < 2:
                fairness[label] = {"status": f"insufficient identities ({len(subset)})"}
                continue
            g_pairs_g, i_pairs_g = make_pairs(subset, max_pairs=args.max_pairs)
            g_scores = cosine_scores(g_pairs_g, celeba_sopq)
            i_scores = cosine_scores(i_pairs_g, celeba_sopq)
            eer_g, th_g = eval_cosine(g_scores, i_scores)
            fairness[label] = {
                "eer": round(eer_g, 5), "th": round(th_g, 3),
                "n_identities": len(subset),
                "n_genuine": len(g_scores), "n_impostor": len(i_scores),
            }
        if "eer" in fairness.get("male", {}) and "eer" in fairness.get("female", {}):
            fairness["eer_gap_pp"] = round(
                abs(fairness["male"]["eer"] - fairness["female"]["eer"]) * 100, 2)
        fairness["source"] = "measured"
        result["demographic_fairness"] = fairness
    elif not args.celeba_root:
        result["demographic_fairness"] = {
            "status": "SKIPPED — requires --celeba-root (fairness is measured on the "
                      "CelebA cross-dataset split, which needs both flags together)"}
    else:
        result["demographic_fairness"] = {"status": "SKIPPED — pass --face-attributes-csv to measure this"}
    result["pad_resilience"] = (
        {"status": "SKIPPED — pass --pad-spoof-dir to measure this"}
        if not args.pad_spoof_dir else {"status": "NOT_IMPLEMENTED_YET"}
    )
    face_cache.close()
    return result, W


# ------------------------------------------------------------------
# Iris evaluation
# ------------------------------------------------------------------
def extract_all_iris_to_cache(paths, cache):
    """Extracts iris codes for `paths` directly into `cache` (a shelve db)
    rather than returning an in-memory dict. A full CASIA-Iris-Thousand-scale
    run needs ~20,000 code+mask pairs (~384KB each, ~7.7GB total) — the
    caller is expected to look codes up from `cache` on demand (one pair, or
    one subject's ~10 captures, at a time) instead of ever materializing the
    whole set, which is what actually exhausted this eval's WSL2 VM."""
    for i, p in enumerate(paths):
        if p not in cache:
            try:
                with open(p, "rb") as f:
                    code, mask, quality = pipeline.get_iris_code_from_bytes(f.read())
                cache[p] = (code, mask)
            except Exception as e:
                print(f"  ⚠ skip {p}: {e}")
        if (i + 1) % 200 == 0:
            print(f"  ...extracted {i + 1}/{len(paths)}")


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
    iris_cache = open_cache("iris_codes", args.cache_dir, args.no_cache)
    subjects = scan_iris_subject_folders(args.casia_thousand_root)
    if args.casia_max_subjects and len(subjects) > args.casia_max_subjects:
        rng = random.Random(SEED)
        keep = rng.sample(list(subjects.keys()), args.casia_max_subjects)
        subjects = {k: subjects[k] for k in keep}
        print(f"  capped to {args.casia_max_subjects} randomly sampled CASIA subject-eyes "
              f"(seed={SEED}) for tractable runtime")
    train_subj, test_subj = split_identities(subjects, train_frac=args.train_frac)

    train_paths = [p for imgs in train_subj.values() for p in imgs]
    test_paths = [p for imgs in test_subj.values() for p in imgs]
    print(f"  {len(subjects)} subject-eyes total -> {len(train_subj)} train / {len(test_subj)} test")

    print("Extracting train split (for fitting GBSM salience)...")
    extract_all_iris_to_cache(train_paths, iris_cache)
    print("Extracting test split (for measuring EER)...")
    extract_all_iris_to_cache(test_paths, iris_cache)

    code_len = next(iris_cache[p][0].shape[0] for p in train_paths if p in iris_cache)

    # Stream one subject's ~10 captures at a time into the salience
    # accumulator instead of stacking every train image into one array —
    # holding all 12,000+ codes (~384KB each) resident at once is exactly
    # what exhausted this eval's WSL2 VM on the first attempt.
    salience_acc = gbsm_mod.SalienceAccumulator(code_len)
    for ident, paths in train_subj.items():
        sub_codes, sub_masks = [], []
        for p in paths:
            if p in iris_cache:
                c, m = iris_cache[p]
                sub_codes.append(c)
                sub_masks.append(m)
        if sub_codes:
            salience_acc.add(np.array(sub_codes), np.array(sub_masks))
    salience = salience_acc.finalize()
    gbsm_idx = gbsm_mod.select_top_bits(salience, d=256)
    stride_idx = gbsm_mod.stride_baseline(code_len, d=256)

    genuine_pairs, impostor_pairs = make_pairs(test_subj, max_pairs=args.max_pairs)
    print(f"  {len(genuine_pairs)} genuine / {len(impostor_pairs)} impostor iris pairs")

    def score_pairs(pairs):
        # Pulls each pair's codes from the disk-backed cache one at a time —
        # never materializes the full test split in memory.
        full, stride, gbsm = [], [], []
        for a, b in pairs:
            if a not in iris_cache or b not in iris_cache:
                continue
            ca, ma = iris_cache[a]
            cb, mb = iris_cache[b]
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
        # Reuses the same iris_cache — paths are globally unique absolute
        # filesystem paths, so CASIA-Thousand and CASIA-Interval entries
        # can't collide in the one shelve db.
        extract_all_iris_to_cache([p for imgs in interval_subj.values() for p in imgs], iris_cache)
        g_pairs, i_pairs = make_pairs(interval_subj, max_pairs=args.max_pairs)

        def score_gbsm_only(pairs):
            # Rotation search must run on the FULL rectangular code (the roll
            # is a circular shift along the theta axis of the (filter, row,
            # col) grid); the GBSM-selected 256 bits are scattered indices
            # into that grid and can't be reshaped/rolled on their own.
            scores = []
            for a, b in pairs:
                if a not in iris_cache or b not in iris_cache:
                    continue
                ca, ma = iris_cache[a]
                cb, mb = iris_cache[b]
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
    iris_cache.close()
    return result


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--lfw-root", help="root/<identity>/<image> face dataset")
    ap.add_argument("--lfw-max-identities", type=int, default=None,
                     help="optional cap on number of LFW identities to use, sampled with the "
                          "fixed SEED — useful for a fast smoke test across all datasets")
    ap.add_argument("--celeba-root", help="same layout, cross-dataset face eval only")
    ap.add_argument("--celeba-identity-file",
                     help="path to identity_CelebA.txt; use when --celeba-root points at the "
                          "flat img_align_celeba folder instead of a per-identity layout")
    ap.add_argument("--celeba-max-identities", type=int, default=None,
                     help="optional cap on number of CelebA identities to embed, sampled with "
                          "the fixed SEED, so a full run doesn't require embedding all ~200k images")
    ap.add_argument("--casia-thousand-root", help="root/<subject>/<L|R>/<image> iris dataset")
    ap.add_argument("--casia-max-subjects", type=int, default=None,
                     help="optional cap on number of CASIA subject-eyes to use, sampled with "
                          "the fixed SEED — useful for a fast smoke test across all datasets")
    ap.add_argument("--casia-interval-root", help="same layout, cross-dataset iris eval only")
    ap.add_argument("--face-attributes-csv",
                     help="path to CelebA's list_attr_celeba.csv; when given together with "
                          "--celeba-root, computes SOPQ EER separately for male- and "
                          "female-labeled identities (real 'Male' attribute column) on the "
                          "CelebA cross-dataset split")
    ap.add_argument("--pad-spoof-dir", help="optional spoof/replay image set for PAD metrics")
    ap.add_argument("--train-frac", type=float, default=0.6)
    ap.add_argument("--max-pairs", type=int, default=6000)
    ap.add_argument("--out", default=os.path.join(RESULTS_DIR, "biometric_accuracy_results.json"))
    ap.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR,
                     help="where embeddings/iris-codes are cached to disk; a rerun with the "
                          "same --cache-dir skips any path already computed instead of "
                          "recomputing it, and iris codes are read from here during pair "
                          "scoring instead of being held fully in memory")
    ap.add_argument("--no-cache", action="store_true",
                     help="disable disk caching entirely (falls back to plain in-memory dicts, "
                          "matching the old behavior); NOT recommended for a full "
                          "CASIA-Iris-Thousand run — see the iris memory-footprint note above")
    args = ap.parse_args()

    if not args.lfw_root and not args.casia_thousand_root:
        ap.error("Provide at least --lfw-root or --casia-thousand-root — there is no synthetic "
                  "fallback in this script anymore.")

    install_pause_handler()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    def write_results(results):
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)

    print("Initializing real pipeline models (FaceNet / MediaPipe / Log-Gabor bank)...")
    pipeline.init_models()

    results = {}
    if args.lfw_root:
        results["face"], _ = run_face_eval(args)
        write_results(results)
        print(f"  (partial results — face section — written to {args.out})")
    if args.casia_thousand_root:
        results["iris"] = run_iris_eval(args)
        write_results(results)

    print("=" * 85)
    print(f"Wrote real, measured results to {args.out}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
