"""
GBSM — Gabor Bit-Salience Masking for phase-quantized iris codes.

Uniform striding (take every Nth bit) is the naive way to downsample a
Log-Gabor IrisCode, and it treats every bit position as equally reliable.
It isn't: the "fragile bits" literature on iris recognition (Hollingsworth,
Bowyer & Flynn, 2009) shows some phase-code bit positions flip constantly
across repeated genuine captures of the same eye (near a quadrant boundary,
or under an eyelash/eyelid), while others are highly stable. GBSM scores
every bit position by (a) how often it disagrees with the majority vote
across repeated captures of the same eye ("fragility") and (b) how often
it falls inside the occlusion mask, then keeps only the d bit positions
that are simultaneously stable and rarely occluded.

Usage (requires >=2 iris captures per subject/eye to score fragility):
    salience = compute_bit_salience(codes, masks, subject_ids)
    idx      = select_top_bits(salience, d=256)
    code256, mask256 = apply_gbsm(code, mask, idx)
"""

import numpy as np


def subject_fragility_occlusion(sub_codes: np.ndarray, sub_masks: np.ndarray):
    """
    One subject's stacked captures -> (fragility_contribution, occlusion_contribution),
    each shape (L,). Split out of compute_bit_salience so a caller with a large
    dataset can stream subjects one at a time (see accumulate/finalize below)
    instead of materializing every capture in memory simultaneously.
    """
    sub_codes = np.asarray(sub_codes, dtype=np.float64)
    sub_masks = np.asarray(sub_masks, dtype=np.float64)

    valid_count = sub_masks.sum(axis=0)
    # Majority vote per bit position over this eye's own captures,
    # counting only unmasked observations.
    vote_sum = (sub_codes * sub_masks).sum(axis=0)
    majority = (vote_sum >= (valid_count / 2.0)).astype(np.float64)

    disagreement = np.abs(sub_codes - majority[None, :]) * sub_masks
    safe_count = np.maximum(valid_count, 1.0)
    fragility_contrib = disagreement.sum(axis=0) / safe_count
    occlusion_contrib = 1.0 - sub_masks.mean(axis=0)
    return fragility_contrib, occlusion_contrib


class SalienceAccumulator:
    """
    Incremental version of compute_bit_salience for datasets too large to hold
    entirely in memory. Feed it one subject's captures at a time via
    .add(sub_codes, sub_masks), then call .finalize() once every subject has
    been added — mathematically identical to compute_bit_salience(codes, masks,
    subject_ids) on the full stacked arrays, but peak memory is only ever
    "one subject's captures" instead of the whole dataset.
    """

    def __init__(self, code_length: int):
        self.L = code_length
        self.fragility = np.zeros(code_length)
        self.occlusion = np.zeros(code_length)
        self.n_scored = 0

    def add(self, sub_codes: np.ndarray, sub_masks: np.ndarray):
        if len(sub_codes) < 2:
            return  # can't estimate fragility from a single capture
        frag_c, occ_c = subject_fragility_occlusion(sub_codes, sub_masks)
        self.fragility += frag_c
        self.occlusion += occ_c
        self.n_scored += 1

    def finalize(self) -> np.ndarray:
        if self.n_scored == 0:
            raise ValueError(
                "No subject in this dataset has >=2 captures — GBSM fragility "
                "scoring requires repeated captures per eye (e.g. CASIA-Iris-"
                "Thousand provides ~10 images per eye)."
            )
        fragility = self.fragility / self.n_scored
        occlusion = self.occlusion / self.n_scored
        salience = 1.0 - 0.5 * (fragility + occlusion)
        return np.clip(salience, 0.0, 1.0)


def compute_bit_salience(codes: np.ndarray, masks: np.ndarray,
                          subject_ids: np.ndarray) -> np.ndarray:
    """
    codes:       (N, L) uint8, one row per iris capture (0/1 phase bits)
    masks:       (N, L) uint8, 1 = usable pixel, 0 = occluded/noisy
    subject_ids: (N,) identity+eye label per row; only subjects with >=2
                 captures contribute to the fragility estimate

    Returns salience: (L,) float in [0, 1]; 1.0 = perfectly stable and
    never occluded across this subject's captures, 0.0 = flips constantly
    or is almost always masked out.

    Convenience wrapper over SalienceAccumulator for callers small enough to
    hold the whole dataset in memory at once. For large datasets, use
    SalienceAccumulator directly and stream subjects from disk instead.
    """
    codes = np.asarray(codes)
    masks = np.asarray(masks)
    subject_ids = np.asarray(subject_ids)

    acc = SalienceAccumulator(codes.shape[1])
    for sid in np.unique(subject_ids):
        rows = np.where(subject_ids == sid)[0]
        acc.add(codes[rows], masks[rows])
    return acc.finalize()


def select_top_bits(salience: np.ndarray, d: int = 256) -> np.ndarray:
    """Indices of the d most salient (stable, unoccluded) bit positions."""
    if d > len(salience):
        raise ValueError(f"d={d} exceeds code length {len(salience)}")
    return np.argsort(salience)[::-1][:d]


def apply_gbsm(code: np.ndarray, mask: np.ndarray, indices: np.ndarray):
    """Subsample a single capture's code/mask down to the selected bits."""
    return np.asarray(code)[indices], np.asarray(mask)[indices]


def stride_baseline(length: int, d: int = 256) -> np.ndarray:
    """Uniform-stride baseline used for comparison against GBSM."""
    stride = max(1, length // d)
    idx = np.arange(0, length, stride)[:d]
    if len(idx) < d:
        raise ValueError(f"Uniform stride only produced {len(idx)} indices, need {d}")
    return idx
