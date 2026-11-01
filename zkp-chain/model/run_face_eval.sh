#!/bin/bash
# run_face_eval.sh — face accuracy evaluation on the GPU (venv312).
# Usage (from anywhere):
#   bash model/run_face_eval.sh insightface [extra args] # deployed: InsightFace buffalo_l (512-D)
#   bash model/run_face_eval.sh deployed  [extra args]   # FaceNet baseline (pre-revision pipeline)
#   bash model/run_face_eval.sh ArcFace   [extra args]   # DeepFace ArcFace port + RetinaFace
# Then: venv312/bin/python face_model_sweep.py --cache <cache> --label <name> (from model/)
# Results: api-server/benchmark/biometric_accuracy_<model>.json
set -e
cd "$(dirname "$0")"
source gpu_env.sh
export PYTHONUNBUFFERED=1   # show progress lines live
D=../Datasets
MODEL="${1:-deployed}"; shift || true
venv312/bin/python biometric_accuracy_eval.py \
  --lfw-root "$D/lfw_kaggle/lfw-deepfunneled/lfw-deepfunneled" \
  --celeba-root "$D/img_align_celeba" \
  --celeba-identity-file "$D/identity_CelebA.txt" \
  --face-attributes-csv "$D/list_attr_celeba.txt" \
  --celeba-max-identities 2000 \
  --face-model "$MODEL" \
  --sopq-dims 16,32,48,64,80,96,112 \
  --out "../api-server/benchmark/biometric_accuracy_${MODEL}.json" \
  "$@"
