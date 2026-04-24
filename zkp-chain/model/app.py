import os

# ============================
# CRITICAL SEGFAULT FIXES
# Must be at the VERY TOP before other imports
# ============================
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Force CPU only
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import cv2
import time
import pickle
import warnings
import numpy as np
import mediapipe as mp
from scipy.ndimage import uniform_filter

# Import DeepFace/TensorFlow LAST
from deepface import DeepFace
from fastapi import FastAPI, File, UploadFile, HTTPException, Body
import uvicorn
from contextlib import asynccontextmanager

warnings.filterwarnings('ignore')

# ============================
# CONFIG — FACE
# ============================
COSINE_THRESHOLD   = 0.50
EUCLIDEAN_THRESHOLD = 1.0
PCA_MODEL_PATH     = "pca_model_64d.pkl"

# ============================
# CONFIG — IRIS
# ============================
NORM_WIDTH  = 512
NORM_HEIGHT = 64

LOG_GABOR_PARAMS = [
    {'wavelength': 18, 'sigma_f': 0.5},
    {'wavelength': 22, 'sigma_f': 0.5},
    {'wavelength': 28, 'sigma_f': 0.5},
]

EYELID_TOP_FRAC    = 0.25
EYELID_BOTTOM_FRAC = 0.20
HAMMING_THRESHOLD  = 0.478

# ============================
# GLOBAL STATE
# ============================
pca_model     = None
mp_detector   = None
log_gabor_bank = None  # Built once at startup


# ============================
# LOAD PCA MODEL
# ============================
def load_pca_model():
    """Load the pre-trained PCA model."""
    try:
        with open(PCA_MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        print(f"✓ PCA model loaded from {PCA_MODEL_PATH}")
        return model
    except FileNotFoundError:
        raise FileNotFoundError(f"PCA model not found at {PCA_MODEL_PATH}")
    except Exception as e:
        raise Exception(f"Error loading PCA model: {str(e)}")


# ============================
# IRIS — FILTER BANK HELPERS
# ============================
def _log_gabor_1d(n, wavelength, sigma_f):
    """1-D Log-Gabor filter in the frequency domain (length n)."""
    f0    = 1.0 / wavelength
    freqs = np.fft.fftfreq(n)
    freqs = np.abs(freqs)
    freqs[0] = 1e-9                          # avoid log(0) at DC
    log_sf = np.log(sigma_f)                 # negative but squared → positive
    lg = np.exp(-(np.log(freqs / f0)) ** 2 / (2.0 * log_sf ** 2))
    lg[0] = 0.0                              # zero DC
    return lg


def build_log_gabor_bank(params=LOG_GABOR_PARAMS):
    """
    Build a bank of 2-D Log-Gabor filters stored in the frequency domain.
    Each filter is stored as a C-contiguous float64 array so numpy's FFT
    multiply never needs to reallocate or copy on each request.
    """
    bank = []
    for p in params:
        wl = p['wavelength']
        sf = p['sigma_f']

        H_col = _log_gabor_1d(NORM_WIDTH, wl, sf)           # (NORM_WIDTH,)

        row_sigma = NORM_HEIGHT / 4.0
        rows  = np.arange(NORM_HEIGHT)
        H_row = np.exp(-0.5 * ((rows - NORM_HEIGHT / 2) / row_sigma) ** 2)
        H_row = np.fft.ifftshift(H_row)                     # (NORM_HEIGHT,)

        H2d = H_row[:, None] * H_col[None, :]               # (H, W)
        # Force C-contiguous + float64 so every request reuses the same buffer
        bank.append(np.ascontiguousarray(H2d, dtype=np.float64))
    return bank


def _warmup_iris_pipeline():
    """
    Run the full iris pipeline once on a synthetic image at server startup.
    Eliminates JIT/cold-start costs in OpenCV (HoughCircles, inpaint,
    morphologyEx) and numpy FFT (FFTW plan caching) so the first real
    request feels as fast as every subsequent one.
    """
    print("⏳ Warming up iris pipeline...")

    # Synthetic eye: dark circle (pupil) inside a lighter circle (iris)
    dummy = np.full((320, 320), 180, dtype=np.uint8)
    cv2.circle(dummy, (160, 160), 90, 210, -1)   # iris region
    cv2.circle(dummy, (160, 160), 35,  30, -1)   # pupil

    dummy_bytes = cv2.imencode('.jpg', dummy)[1].tobytes()
    try:
        get_iris_code_from_bytes(dummy_bytes)
        print("✓ Iris pipeline warm-up complete")
    except Exception as e:
        # Warm-up failure is non-fatal — real images will still work
        print(f"⚠ Iris warm-up hit a non-fatal issue: {e}")


# ============================
# IRIS — DETECTION & SEGMENTATION
# ============================
def _remove_specular(gray_u8, bright_thresh=240, inpaint_radius=4):
    _, mask = cv2.threshold(gray_u8, bright_thresh, 255, cv2.THRESH_BINARY)
    kernel  = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (7, 7))
    mask    = cv2.dilate(mask, kernel, iterations=2)
    return cv2.inpaint(gray_u8, mask, inpaint_radius, cv2.INPAINT_TELEA)


def _detect_pupil_contour(gray_u8):
    """Morphological pupil detection. Returns (cx, cy, r) or None."""
    h, w  = gray_u8.shape
    min_v = np.min(gray_u8)
    _, thresh = cv2.threshold(gray_u8, min_v + 35, 255, cv2.THRESH_BINARY_INV)
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
    thresh = cv2.morphologyEx(thresh, cv2.MORPH_OPEN,  kernel, iterations=2)
    thresh = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel, iterations=2)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None
    best_c, max_area = None, 0
    for c in contours:
        area = cv2.contourArea(c)
        if area < 500 or area > (h * w * 0.15):
            continue
        perimeter = cv2.arcLength(c, True)
        if perimeter == 0:
            continue
        circularity = 4 * np.pi * (area / (perimeter * perimeter))
        if circularity > 0.4 and area > max_area:
            max_area = area
            best_c   = c
    if best_c is None:
        return None
    (x, y), r = cv2.minEnclosingCircle(best_c)
    return int(x), int(y), int(r)


def _integrodiff(gray_u8, r_min, r_max, n_r=40, n_t=360):
    h, w   = gray_u8.shape
    cx0, cy0 = w // 2, h // 2
    thetas = np.linspace(0, 2 * np.pi, n_t, endpoint=False)
    cos_t, sin_t = np.cos(thetas), np.sin(thetas)
    best_score, best = -1, (cx0, cy0, (r_min + r_max) // 2)
    for dy in [0, -int(min(h, w) * 0.05), int(min(h, w) * 0.05)]:
        for dx in [0, -int(min(h, w) * 0.05), int(min(h, w) * 0.05)]:
            cx, cy = cx0 + dx, cy0 + dy
            prev   = None
            for r in np.linspace(r_min, r_max, n_r, dtype=int):
                xs   = np.clip((cx + r * cos_t).astype(int), 0, w - 1)
                ys   = np.clip((cy + r * sin_t).astype(int), 0, h - 1)
                mean = float(gray_u8[ys, xs].mean())
                if prev is not None:
                    score = abs(mean - prev)
                    if score > best_score:
                        best_score = score
                        best = (cx, cy, r)
                prev = mean
    return np.array(best, dtype=int)


def _detect_iris_robust(gray_u8):
    """
    3-tier iris/pupil detection.
    Returns (px, py, pr, ix, iy, ir, quality_tier).
    quality_tier 3 = best (contour + Hough), 1 = integrodiff fallback.
    """
    h, w = gray_u8.shape
    pupil = _detect_pupil_contour(gray_u8)
    if pupil is not None:
        px, py, pr = pupil
        blurred = cv2.GaussianBlur(gray_u8, (9, 9), 2)
        circles = cv2.HoughCircles(
            blurred, cv2.HOUGH_GRADIENT, dp=1, minDist=30,
            param1=50, param2=15,
            minRadius=int(pr * 1.5),
            maxRadius=int(min(h, w) * 0.55)
        )
        if circles is not None:
            best_ic, min_dist = None, float('inf')
            for c in circles[0]:
                ix, iy, ir = c
                dist = np.sqrt((ix - px) ** 2 + (iy - py) ** 2)
                if dist < pr and dist < min_dist:
                    min_dist = dist
                    best_ic  = (int(ix), int(iy), int(ir))
            if best_ic is not None:
                return px, py, pr, best_ic[0], best_ic[1], best_ic[2], 3

    # Integrodiff fallback
    ir_min, ir_max = int(min(h, w) * 0.28), int(min(h, w) * 0.55)
    pr_min, pr_max = int(min(h, w) * 0.05), int(min(h, w) * 0.25)
    ic3 = _integrodiff(gray_u8, ir_min, ir_max)
    pc3 = _integrodiff(gray_u8, pr_min, pr_max)
    return (*pc3, *ic3, 1)


# ============================
# IRIS — NORMALIZATION & MASK
# ============================
def _normalize_iris(gray_f64, px, py, pr, ix, iy, ir):
    """Rubber-sheet unwrap → float64 strip [0, 255]. No histeq."""
    thetas  = np.linspace(0, 2 * np.pi, NORM_WIDTH,  endpoint=False)
    r_fracs = np.linspace(0, 1, NORM_HEIGHT)
    xp = px + pr * np.cos(thetas)
    yp = py + pr * np.sin(thetas)
    xi = ix + ir * np.cos(thetas)
    yi = iy + ir * np.sin(thetas)
    rf = r_fracs[:, None]
    xs = np.clip((xp + rf * (xi - xp)).astype(int), 0, gray_f64.shape[1] - 1)
    ys = np.clip((yp + rf * (yi - yp)).astype(int), 0, gray_f64.shape[0] - 1)
    return gray_f64[ys, xs]


def _build_noise_mask(norm_f64):
    """Returns uint8 mask: 1 = reliable pixel, 0 = occluded."""
    H, W  = norm_f64.shape
    mask  = np.ones((H, W), dtype=np.uint8)
    # Eyelid rows
    mask[:int(H * EYELID_TOP_FRAC),      :] = 0
    mask[H - int(H * EYELID_BOTTOM_FRAC):, :] = 0
    # Residual bright spots
    bright = (norm_f64 > 240).astype(np.uint8)
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
    bright = cv2.dilate(bright, kernel, iterations=1)
    mask[bright == 1] = 0
    # Dark eyelash columns
    top_r    = int(H * EYELID_TOP_FRAC)
    bot_r    = int(H * EYELID_BOTTOM_FRAC)
    mid      = norm_f64[top_r:H - bot_r, :]
    col_mean = mid.mean(axis=0)
    mask[:, col_mean < 25] = 0
    return mask


# ============================
# IRIS — PHASE ENCODING
# ============================
def _extract_iris_code_phase(norm_f64, noise_mask, bank):
    """
    Convolve with each freq-domain filter, quantise phase to 2 bits.
    Returns (code, mask) as flat uint8 arrays.
    """
    strip     = norm_f64 - norm_f64.mean()
    STRIP_FFT = np.fft.fft2(strip)
    code_bits, mask_bits = [], []
    flat_mask = noise_mask.ravel()
    for H2d in bank:
        response  = np.fft.ifft2(STRIP_FFT * H2d)
        bit_real  = (response.real > 0).ravel().astype(np.uint8)
        bit_imag  = (response.imag > 0).ravel().astype(np.uint8)
        code_bits.extend([bit_real, bit_imag])
        mask_bits.extend([flat_mask, flat_mask])
    return np.concatenate(code_bits), np.concatenate(mask_bits)


# ============================
# IRIS — FULL PIPELINE
# ============================
def get_iris_code_from_bytes(img_bytes: bytes):
    """
    Raw image bytes → (iris_code, noise_mask, detection_quality).
    iris_code and noise_mask are flat uint8 numpy arrays.
    """
    np_img   = np.frombuffer(img_bytes, np.uint8)
    raw_u8   = cv2.imdecode(np_img, cv2.IMREAD_GRAYSCALE)
    if raw_u8 is None:
        raise ValueError("Invalid image — could not decode")

    clean_u8 = _remove_specular(raw_u8)
    px, py, pr, ix, iy, ir, quality = _detect_iris_robust(clean_u8)

    clean_f64  = clean_u8.astype(np.float64)
    norm       = _normalize_iris(clean_f64, px, py, pr, ix, iy, ir)
    noise_mask = _build_noise_mask(norm)
    code, mask = _extract_iris_code_phase(norm, noise_mask, log_gabor_bank)

    return code, mask, quality


# ============================
# IRIS — COMPARISON
# ============================
def compare_iris_codes(code_a, mask_a, code_b, mask_b, n_shifts=8):
    """
    Masked normalised Hamming Distance with rotational compensation.
    Returns dict with distance and match decision.
    """
    ca_2d = code_a.reshape(-1, NORM_WIDTH)
    cb_2d = code_b.reshape(-1, NORM_WIDTH)
    ma_2d = mask_a.reshape(-1, NORM_WIDTH)
    mb_2d = mask_b.reshape(-1, NORM_WIDTH)

    min_hd = 1.0

    for shift in range(-n_shifts, n_shifts + 1):
        r_code = np.roll(cb_2d, shift, axis=1).ravel()
        r_mask = np.roll(mb_2d, shift, axis=1).ravel()
        flat_ma = ma_2d.ravel()
        joint   = flat_ma & r_mask
        n_valid = int(joint.sum())
        if n_valid < 200:
            continue
        hd = float((code_a ^ r_code)[joint == 1].sum()) / n_valid
        if hd < min_hd:
            min_hd = hd
        if min_hd < 0.10:
            break

    return {
        "hamming_distance":  min_hd,
        "is_same_person":    min_hd < HAMMING_THRESHOLD,
        "confidence":        float(1.0 - min_hd),
        "threshold_used":    HAMMING_THRESHOLD,
    }


# ============================
# FASTAPI LIFESPAN
# ============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global pca_model, mp_detector, log_gabor_bank

    print("⏳ Initializing models...")

    # Face models
    pca_model = load_pca_model()

    mp_detector = mp.solutions.face_detection.FaceDetection(
        model_selection=0,
        min_detection_confidence=0.5
    )
    print("✓ MediaPipe face detector loaded")

    DeepFace.build_model("Facenet")
    print("✓ DeepFace FaceNet loaded")

    # Iris filter bank (pure numpy, fast)
    log_gabor_bank = build_log_gabor_bank()
    print(f"✓ Log-Gabor filter bank built ({len(log_gabor_bank)} filters, C-contiguous)")

    # Warm up the iris pipeline on a synthetic image so OpenCV's internal
    # JIT plans (HoughCircles, inpaint, morphologyEx) and numpy's FFT
    # plan cache are populated before the first real request arrives.
    _warmup_iris_pipeline()

    print("🚀 Server ready!")
    yield

    # Cleanup
    if mp_detector:
        mp_detector.close()


# ============================
# FASTAPI APP
# ============================
app = FastAPI(lifespan=lifespan)


# ============================
# FACE DETECTION (internal)
# ============================
def detect_face_from_bytes(img_bytes: bytes, margin=20):
    """Detect and crop a face from raw bytes using MediaPipe."""
    np_img = np.frombuffer(img_bytes, np.uint8)
    img    = cv2.imdecode(np_img, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Invalid image")

    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    h, w    = img.shape[:2]
    result  = mp_detector.process(img_rgb)
    if not result.detections:
        raise ValueError("No face detected")

    det  = result.detections[0]
    bbox = det.location_data.relative_bounding_box
    x    = int(bbox.xmin * w)
    y    = int(bbox.ymin * h)
    bw   = int(bbox.width  * w)
    bh   = int(bbox.height * h)
    x1   = max(0, x - margin)
    y1   = max(0, y - margin)
    x2   = min(w, x + bw + margin)
    y2   = min(h, y + bh + margin)

    return img[y1:y2, x1:x2], det.score[0]


# ============================
# FACE EMBEDDING (internal)
# ============================
def get_face_embedding_from_bytes(img_bytes: bytes):
    """Crop → FaceNet embedding → PCA 64D → L2 normalise."""
    face_img, conf = detect_face_from_bytes(img_bytes)

    temp_path = "/tmp/f_crop.jpg"
    cv2.imwrite(temp_path, face_img)

    emb_obj = DeepFace.represent(
        img_path=temp_path,
        model_name="Facenet",
        enforce_detection=False,
        detector_backend="skip"
    )

    if os.path.exists(temp_path):
        os.remove(temp_path)

    embedding_128d = np.array(emb_obj[0]["embedding"])
    embedding_128d = embedding_128d / np.linalg.norm(embedding_128d)
    embedding_64d  = pca_model.transform(embedding_128d.reshape(1, -1))[0]
    embedding_64d  = embedding_64d  / np.linalg.norm(embedding_64d)

    return embedding_64d, conf


# ============================
# FACE EMBEDDING COMPARISON (internal)
# ============================
def compare_face_embeddings(e1, e2):
    cosine = float(np.dot(e1, e2))
    euclid = float(np.linalg.norm(e1 - e2))
    return {
        "cosine_similarity":    cosine,
        "euclidean_distance":   euclid,
        "is_same_person":       cosine > COSINE_THRESHOLD,
        "confidence":           cosine,
        "embedding_dimension":  len(e1),
    }


# ============================
# FACE ENDPOINTS
# ============================
@app.post("/face/get-embedding")
async def api_get_embedding(file: UploadFile = File(...)):
    try:
        img_bytes     = await file.read()
        emb_64d, conf = get_face_embedding_from_bytes(img_bytes)
        return {
            "embedding":  emb_64d.tolist(),
            "confidence": float(conf),
            "dimension":  len(emb_64d),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/face/compare-embeddings")
async def api_compare_embeddings(data: dict = Body(...)):
    try:
        emb1   = np.array(data["face_login"])
        emb2   = np.array(data["face_reg"])
        result = compare_face_embeddings(emb1, emb2)
        return result
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing key: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================
# IRIS ENDPOINTS
# ============================
@app.post("/iris/get-iriscode")
async def api_get_iriscode(file: UploadFile = File(...)):
    """
    Upload a grayscale (or colour) eye image.

    Returns:
      - iris_code   : flat list of 0/1 bits (length = n_filters × 2 × H × W)
      - noise_mask  : flat list of 0/1 bits (same shape as iris_code)
      - dimension   : total length of iris_code / noise_mask
      - quality     : detection quality tier (3 = best, 1 = fallback)
    """
    try:
        img_bytes         = await file.read()
        code, mask, quality = get_iris_code_from_bytes(img_bytes)
        return {
            "iris_code":  code.tolist(),
            "noise_mask": mask.tolist(),
            "dimension":  len(code),
            "quality":    quality,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/iris/compare-iriscodes")
async def api_compare_iriscodes(data: dict = Body(...)):
    """
    Compare two iris codes with masked Hamming Distance.

    Expects JSON body:
      {
        "iris_code_login" : [...],   // flat 0/1 list
        "noise_mask_login": [...],
        "iris_code_reg"   : [...],
        "noise_mask_reg"  : [...]
      }

    Returns:
      - hamming_distance  : float in [0, 1]  (lower = more similar)
      - is_same_person    : bool  (true if distance < HAMMING_THRESHOLD)
      - confidence        : float (= 1 - hamming_distance)
      - threshold_used    : float
    """
    try:
        code_login = np.array(data["iris_code_login"],  dtype=np.uint8)
        mask_login = np.array(data["noise_mask_login"], dtype=np.uint8)
        code_reg   = np.array(data["iris_code_reg"],    dtype=np.uint8)
        mask_reg   = np.array(data["noise_mask_reg"],   dtype=np.uint8)

        result = compare_iris_codes(code_login, mask_login, code_reg, mask_reg)
        return result
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing key: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================
# RUN LOCAL SERVER
# ============================
if __name__ == "__main__":
    uvicorn.run("app:app", host="localhost", port=8000, reload=False)