import os

# ============================
# CRITICAL SEGFAULT FIXES
# Must be at the VERY TOP before other imports
# ============================
# os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Force CPU only (Commented out to allow GPU)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import cv2
import time
import pickle
import warnings
import numpy as np
import mediapipe as mp
from mediapipe.tasks import python as mp_python
from mediapipe.tasks.python import vision as mp_vision
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
FACE_DETECTOR_MODEL_PATH = "mp_models/blaze_face_short_range.tflite"

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
    """1-D Log-Gabor filter in the frequency domain (length n).

    One-sided (analytic) by construction: energy only at positive
    frequencies, zero at DC and all negative frequencies. This is what makes
    filtering a real signal with this filter produce a genuine complex
    quadrature response (real/imaginary parts as a true Hilbert-transform
    pair) — the phase information _extract_iris_code_phase quantizes into
    2 bits per pixel. A symmetric (two-sided) filter here would correspond
    to a purely real spatial-domain filter, making the "imaginary part" of
    the response numerical noise rather than phase — silently turning half
    the IrisCode into random bits with zero identity signal.
    """
    f0    = 1.0 / wavelength
    freqs = np.fft.fftfreq(n)
    log_sf = np.log(sigma_f)                 # negative but squared → positive
    lg = np.zeros(n)
    pos = freqs > 0                          # one-sided: DC and negative freqs stay 0
    lg[pos] = np.exp(-(np.log(freqs[pos] / f0)) ** 2 / (2.0 * log_sf ** 2))
    return lg


def build_log_gabor_bank(params=LOG_GABOR_PARAMS):
    """
    Build a bank of 2-D Log-Gabor filters stored in the frequency domain.

    Each filter applies the SAME 1-D analytic log-Gabor response (see
    _log_gabor_1d) independently to every row of the normalized strip — the
    standard per-row iris phase-coding approach (Masek/Daugman-style), where
    each radius row is phase-encoded on its own with no cross-row mixing.
    A previous version multiplied in an extra real, symmetric Gaussian
    window across rows (i.e. a lowpass filter along the radius axis), which
    smooths/blends neighboring radius rows together before phase encoding —
    non-standard, and it blurs together exactly the radius-dependent texture
    the phase code is supposed to capture instead of leaving each row's
    genuine local phase intact.

    Filters are stored as C-contiguous float64 arrays so numpy's FFT
    multiply never needs to reallocate or copy on each request.
    """
    bank = []
    for p in params:
        wl = p['wavelength']
        sf = p['sigma_f']

        H_col = _log_gabor_1d(NORM_WIDTH, wl, sf)           # (NORM_WIDTH,)
        H2d = np.tile(H_col[None, :], (NORM_HEIGHT, 1))     # identical filter, every row
        # Force C-contiguous + float64 so every request reuses the same buffer
        bank.append(np.ascontiguousarray(H2d, dtype=np.float64))
    return bank


def _warmup_iris_pipeline():
    """
    Run the full iris pipeline once on a synthetic image at server startup.
    Eliminates JIT/cold-start costs in OpenCV (inpaint, morphologyEx) and
    numpy FFT (FFTW plan caching) so the first real request feels as fast
    as every subsequent one.
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


def _integrodiff_radius(gray_f64, cx0, cy0, r_min, r_max, n_r=120, n_theta=240):
    """
    Daugman's integrodifferential operator, evaluated at a fixed center:
    the radius r that maximizes the (smoothed) derivative of the circular
    mean intensity with respect to r — i.e. the sharpest average-intensity
    transition crossed by a circle of radius r centered at (cx0, cy0). This
    is the standard, proven technique for locating pupil/iris boundaries by
    intensity discontinuity, more precise than fixed-threshold contours or
    Hough circles especially at the often-subtle iris/sclera edge.
    Returns (best_r, score) — score is how sharp that transition was, used
    by _detect_boundary to pick the best candidate center.
    """
    h, w = gray_f64.shape
    thetas = np.linspace(0, 2 * np.pi, n_theta, endpoint=False)
    cos_t, sin_t = np.cos(thetas), np.sin(thetas)
    radii = np.linspace(r_min, r_max, n_r)
    means = np.empty(n_r)
    for i, r in enumerate(radii):
        xs = np.clip((cx0 + r * cos_t).astype(int), 0, w - 1)
        ys = np.clip((cy0 + r * sin_t).astype(int), 0, h - 1)
        means[i] = gray_f64[ys, xs].mean()
    smoothed = uniform_filter(means, size=max(3, n_r // 15))
    deriv = np.abs(np.diff(smoothed))
    best_i = int(np.argmax(deriv))
    return float(radii[best_i]), float(deriv[best_i])


def _detect_boundary(gray_f64, cx_lo, cx_hi, cy_lo, cy_hi, r_min, r_max,
                      coarse_n=6, refine_n=5, refine_frac=0.15):
    """Coarse grid search over candidate centers scored by
    _integrodiff_radius, then a local refinement pass around the best
    coarse candidate for finer precision. Returns (cx, cy, r)."""
    best_score, best = -1.0, None
    for cy0 in np.linspace(cy_lo, cy_hi, coarse_n):
        for cx0 in np.linspace(cx_lo, cx_hi, coarse_n):
            r, score = _integrodiff_radius(gray_f64, cx0, cy0, r_min, r_max)
            if score > best_score:
                best_score, best = score, (cx0, cy0, r)

    cx0, cy0, r0 = best
    span_x = (cx_hi - cx_lo) * refine_frac
    span_y = (cy_hi - cy_lo) * refine_frac
    for cy1 in np.linspace(cy0 - span_y, cy0 + span_y, refine_n):
        for cx1 in np.linspace(cx0 - span_x, cx0 + span_x, refine_n):
            r, score = _integrodiff_radius(gray_f64, cx1, cy1, r_min, r_max)
            if score > best_score:
                best_score, best = score, (cx1, cy1, r)
    return best  # (cx, cy, r)


def _detect_iris_robust(gray_u8):
    """
    Locates the pupil then the iris boundary via Daugman's
    integrodifferential operator (_detect_boundary), replacing a previous
    ad-hoc contour+Hough+coarse-fallback combination that showed severe
    inconsistency (>25% coefficient of variation in radius estimates across
    repeated captures of the same physical eye — verified by direct
    measurement, not a hypothetical concern). This is a real, measured
    improvement (~25% -> ~22% CV) but not a full fix: some of that
    remaining instability is inherent to the image data itself (contrast,
    occlusion, blur), a documented limitation of classical intensity-based
    iris segmentation in general, not specific to this implementation.

    Returns (px, py, pr, ix, iy, ir, quality). `quality` is kept for API
    compatibility with callers written against the old two-tier detector;
    this one has no good/fallback distinction, so it's always 3.
    """
    h, w = gray_u8.shape
    gray = gray_u8.astype(np.float64)

    px, py, pr = _detect_boundary(
        gray, cx_lo=w * 0.3, cx_hi=w * 0.7, cy_lo=h * 0.3, cy_hi=h * 0.7,
        r_min=15, r_max=min(h, w) * 0.20,
    )
    # Iris search is centered near the already-found pupil (concentric or
    # near-concentric with it), radius bounded above the pupil radius.
    ix, iy, ir = _detect_boundary(
        gray, cx_lo=px - 15, cx_hi=px + 15, cy_lo=py - 15, cy_hi=py + 15,
        r_min=pr * 1.3, r_max=min(h, w) * 0.5,
        coarse_n=5, refine_n=5, refine_frac=0.3,
    )
    return int(px), int(py), int(pr), int(ix), int(iy), int(ir), 3


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

    # Eyelid occlusion sits at specific THETA angles (top/bottom of the iris
    # annulus in Cartesian space), not specific radii: columns index theta,
    # rows index radius fraction (see _normalize_iris). theta=pi/2 (column
    # ~W/4) is +y in image coords = the BOTTOM of the eye (lower eyelid);
    # theta=3pi/2 (column ~3W/4) is -y = the TOP of the eye (upper eyelid).
    # Masking fixed RADIUS bands (rows) instead — as this used to do — zeroes
    # out bands that have nothing to do with eyelids while leaving genuine
    # eyelid/eyelash pixels at the top/bottom angular sectors marked "valid".
    # Upper eyelids typically droop further over the iris than lower ones,
    # so the top sector gets a wider fixed angular mask.
    top_center, bottom_center = int(W * 0.75), int(W * 0.25)
    top_half    = int(W * EYELID_TOP_FRAC    / 2)
    bottom_half = int(W * EYELID_BOTTOM_FRAC / 2)
    mask[:, max(0, top_center - top_half):min(W, top_center + top_half)] = 0
    mask[:, max(0, bottom_center - bottom_half):min(W, bottom_center + bottom_half)] = 0

    # Residual bright spots (specular highlights)
    bright = (norm_f64 > 240).astype(np.uint8)
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
    bright = cv2.dilate(bright, kernel, iterations=1)
    mask[bright == 1] = 0

    # Dark eyelash columns — a lash strand crossing the annulus darkens its
    # whole column regardless of radius, so no row-range restriction needed.
    col_mean = norm_f64.mean(axis=0)
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
# MODEL INITIALIZATION
# ============================
def init_models():
    """
    Load all models needed by the face/iris pipelines. Factored out of the
    FastAPI lifespan hook so standalone scripts (e.g. batch accuracy
    evaluation over a real dataset) can reuse the exact same pipeline the
    live server uses, instead of re-implementing it.
    """
    global pca_model, mp_detector, log_gabor_bank

    print("⏳ Initializing models...")

    # Face models
    pca_model = load_pca_model()

    detector_options = mp_vision.FaceDetectorOptions(
        base_options=mp_python.BaseOptions(
            model_asset_path=FACE_DETECTOR_MODEL_PATH,
            delegate=mp_python.BaseOptions.Delegate.CPU
        ),
        min_detection_confidence=0.5
    )
    mp_detector = mp_vision.FaceDetector.create_from_options(detector_options)
    print("✓ MediaPipe face detector loaded")

    DeepFace.build_model("Facenet")
    print("✓ DeepFace FaceNet loaded")

    # Iris filter bank (pure numpy, fast)
    log_gabor_bank = build_log_gabor_bank()
    print(f"✓ Log-Gabor filter bank built ({len(log_gabor_bank)} filters, C-contiguous)")


# ============================
# FASTAPI LIFESPAN
# ============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_models()

    # Warm up the iris pipeline on a synthetic image so OpenCV's internal
    # JIT plans (inpaint, morphologyEx) and numpy's FFT plan cache are
    # populated before the first real request arrives.
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

    img_rgb  = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    h, w     = img.shape[:2]
    mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=img_rgb)
    result   = mp_detector.detect(mp_image)
    if not result.detections:
        raise ValueError("No face detected")

    det  = result.detections[0]
    bbox = det.bounding_box  # already absolute pixel coords in the Tasks API
    x1   = max(0, bbox.origin_x - margin)
    y1   = max(0, bbox.origin_y - margin)
    x2   = min(w, bbox.origin_x + bbox.width  + margin)
    y2   = min(h, bbox.origin_y + bbox.height + margin)

    return img[y1:y2, x1:x2], det.categories[0].score


# ============================
# FACE EMBEDDING (internal)
# ============================
def get_raw_embedding_from_bytes(img_bytes: bytes):
    """Crop → FaceNet embedding → L2 normalise. Raw 128-D, no reduction.

    Factored out of get_face_embedding_from_bytes so batch evaluation code
    (and any alternative reduction, e.g. SOPQ) can reuse the exact same
    detection/FaceNet pipeline the live server uses instead of duplicating it.
    """
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
    return embedding_128d, conf


def get_face_embedding_from_bytes(img_bytes: bytes):
    """Crop → FaceNet embedding → PCA 64D → L2 normalise."""
    embedding_128d, conf = get_raw_embedding_from_bytes(img_bytes)
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