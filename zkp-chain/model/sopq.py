"""
SOPQ — Spherical Orthogonal Projection and Quantization for FaceNet embeddings.

Standard PCA dimensionality reduction minimizes Euclidean reconstruction
error, which is the wrong objective for a system that matches identities by
cosine similarity: PCA has no notion of which directions actually separate
one identity from another. SOPQ instead learns a projection driven by
between-class / within-class scatter (a regularized Fisher discriminant
direction search), then re-orthonormalizes the resulting basis via QR so the
projection matrix W satisfies W @ W.T == I (a true orthogonal projection,
required so that fixed-point quantization and the in-circuit cosine-similarity
proof over F_p behave predictably).

Usage:
    W = fit_sopq(train_embeddings, train_labels, out_dim=64)
    v64 = apply_sopq(W, embedding_128d)          # unit-norm, 64-D
    a   = quantize_fixed_point(v64)              # int64, sigma = 1e6

`fit_sopq` must be trained on a disjoint identity split from whatever you
report accuracy numbers on — reusing the same identities for both fitting
the projection and measuring EER will silently inflate accuracy.
"""

import numpy as np
from scipy.linalg import eigh, qr

DEFAULT_SIGMA = 1_000_000


def fit_sopq(embeddings: np.ndarray, labels: np.ndarray, out_dim: int = 64,
             shrinkage: float = 0.15) -> np.ndarray:
    """
    embeddings: (N, D) L2-normalized FaceNet embeddings (D=128 typically)
    labels:     (N,) identity label per row; identities with a single sample
                contribute nothing to between/within-class scatter and are
                effectively ignored
    shrinkage:  ridge term added to the within-class scatter before solving
                the generalized eigenproblem — needed because D=128 with
                a handful of samples per identity makes the raw within-class
                scatter singular or near-singular

    Returns W: (out_dim, D) with W @ W.T ≈ I_out_dim
    """
    embeddings = np.asarray(embeddings, dtype=np.float64)
    labels = np.asarray(labels)
    n, d = embeddings.shape
    if out_dim >= d:
        raise ValueError(f"out_dim ({out_dim}) must be smaller than input dim ({d})")

    classes = np.unique(labels)
    mu = embeddings.mean(axis=0)

    Sb = np.zeros((d, d))
    Sw = np.zeros((d, d))
    used_classes = 0
    for c in classes:
        X_c = embeddings[labels == c]
        n_c = X_c.shape[0]
        if n_c < 2:
            continue  # can't estimate within-class spread from one sample
        used_classes += 1
        mu_c = X_c.mean(axis=0)
        diff = (mu_c - mu).reshape(-1, 1)
        Sb += n_c * (diff @ diff.T)
        centered = X_c - mu_c
        Sw += centered.T @ centered

    if used_classes < out_dim:
        raise ValueError(
            f"Only {used_classes} identities have >=2 samples; need at least "
            f"{out_dim} to fit a rank-{out_dim} discriminant projection. "
            f"Filter your training split to identities with multiple images."
        )

    Sw_reg = Sw + (shrinkage * np.trace(Sw) / d) * np.eye(d)

    # Generalized eigenproblem: Sb w = lambda * Sw_reg w. Top eigenvectors
    # are the directions maximizing between-class / within-class variance
    # ratio (regularized Fisher discriminant directions).
    eigvals, eigvecs = eigh(Sb, Sw_reg)
    order = np.argsort(eigvals)[::-1]
    top = eigvecs[:, order[:out_dim]]  # (d, out_dim), not orthonormal yet

    # Re-orthonormalize via QR. Discriminant directions from a generalized
    # eigenproblem are Sw_reg-orthogonal, not Euclidean-orthogonal — QR gives
    # us a genuine orthogonal projection (W W^T = I) spanning the same
    # discriminative subspace, which is what the in-circuit norm arithmetic
    # (Eq. sopq-circuit) assumes.
    Q, _ = qr(top)
    W = Q[:, :out_dim].T  # (out_dim, d)
    return W


def apply_sopq(W: np.ndarray, embedding: np.ndarray) -> np.ndarray:
    """Project a single L2-normalized embedding and re-normalize onto the
    unit hypersphere (hence "spherical" — this step is what recovers angular
    discrimination that plain PCA's variance objective throws away)."""
    projected = W @ np.asarray(embedding, dtype=np.float64)
    norm = np.linalg.norm(projected)
    if norm < 1e-12:
        raise ValueError("Degenerate projection (near-zero norm) for this embedding")
    return projected / norm


def quantize_fixed_point(vec: np.ndarray, sigma: float = DEFAULT_SIGMA) -> np.ndarray:
    """Map unit-sphere floats to signed fixed-point integers matching the
    sigma=1e6 scaling used in the Groth16 circuit's field arithmetic."""
    return np.round(np.asarray(vec) * sigma).astype(np.int64)
