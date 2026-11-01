"""Why does PCA-64 beat raw 128-D FaceNet? Effective rank and mean-centring.
Usage (from model/): venv312/bin/python pca_diagnostics.py"""
import sys, types
import numpy as np
from sklearn.decomposition import PCA
sys.modules.setdefault("app", types.ModuleType("app"))
import biometric_accuracy_eval as ev

LFW = "../Datasets/lfw_kaggle/lfw-deepfunneled/lfw-deepfunneled"
cache = ev.open_cache("face_embeddings", ev.DEFAULT_CACHE_DIR, False)
ids = ev.scan_identity_folders(LFW)
train_ids, test_ids = ev.split_identities(ids, train_frac=0.6)
X = np.array([cache[p] for v in train_ids.values() for p in v if p in cache])
test = {p: np.asarray(cache[p]) for v in test_ids.values() for p in v if p in cache}
g_pairs, i_pairs = ev.make_pairs(test_ids, max_pairs=6000)
unit = lambda v: v / np.linalg.norm(v)
eer = lambda emb: ev.eer_np(ev.cosine_scores(g_pairs, emb), ev.cosine_scores(i_pairs, emb))

full = PCA().fit(X)
cum = np.cumsum(full.explained_variance_ratio_)
print("variance explained by first k components:",
      {k: round(float(cum[k - 1]), 6) for k in (48, 56, 60, 64, 65, 80, 128)})
print("singular values 60..68:", np.round(full.singular_values_[59:68], 6))
mu = X.mean(axis=0)
print("raw 128-D EER:            ", round(eer({p: unit(v) for p, v in test.items()}), 5))
print("raw 128-D, mean-centred:  ", round(eer({p: unit(v - mu) for p, v in test.items()}), 5))
cache.close()
