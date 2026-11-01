#!/bin/bash
# gpu_env.sh — make the RTX 3050 visible to TensorFlow inside WSL.
# Usage:  source model/gpu_env.sh   (then run venv312/bin/python ...)
#
# WSL ships the CUDA driver in /usr/lib/wsl/lib; the CUDA runtime libraries
# come from the nvidia-* pip wheels installed by `tensorflow[and-cuda]`,
# which TensorFlow does not always find on its own (e.g. libcusolver.so.11).
_MODEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_NV="$_MODEL_DIR/venv312/lib/python3.12/site-packages/nvidia"
_LIBS="/usr/lib/wsl/lib"
for d in "$_NV"/*/lib; do _LIBS="$_LIBS:$d"; done
export LD_LIBRARY_PATH="$_LIBS${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export TF_CPP_MIN_LOG_LEVEL="${TF_CPP_MIN_LOG_LEVEL:-2}"
# DeepFace/RetinaFace build models with tf.keras APIs that break under Keras 3;
# route tf.keras to the tf-keras package (installed via requirements.txt)
export TF_USE_LEGACY_KERAS=1
unset _MODEL_DIR _NV _LIBS d
