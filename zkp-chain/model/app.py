import os
import cv2
import time
import pickle
import numpy as np
from fastapi import FastAPI, File, UploadFile, HTTPException, Body
from fastapi.responses import JSONResponse
import uvicorn
from deepface import DeepFace
import mediapipe as mp


# ============================
# CONFIG
# ============================
COSINE_THRESHOLD = 0.50
EUCLIDEAN_THRESHOLD = 1.0
PCA_MODEL_PATH = "pca_model_64d.pkl"


# ============================
# LOAD PCA MODEL
# ============================
def load_pca_model():
    """Load the pre-trained PCA model."""
    try:
        with open(PCA_MODEL_PATH, 'rb') as f:
            pca_model = pickle.load(f)
        print(f"✓ PCA model loaded successfully from {PCA_MODEL_PATH}")
        return pca_model
    except FileNotFoundError:
        raise FileNotFoundError(f"PCA model not found at {PCA_MODEL_PATH}")
    except Exception as e:
        raise Exception(f"Error loading PCA model: {str(e)}")


pca_model = load_pca_model()


# ============================
# INITIALIZE MODELS
# ============================
mp_detector = mp.solutions.face_detection.FaceDetection(
    model_selection=0,
    min_detection_confidence=0.5
)

DeepFace.build_model("Facenet")   # load Facenet once


# ============================
# FACE DETECTION
# ============================
def detect_face_from_bytes(img_bytes: bytes, margin=20):
    """Detect and crop a face from raw bytes using MediaPipe."""
    np_img = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Invalid image")

    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    h, w = img.shape[:2]

    result = mp_detector.process(img_rgb)
    if not result.detections:
        raise ValueError("No face detected")

    det = result.detections[0]
    bbox = det.location_data.relative_bounding_box

    x = int(bbox.xmin * w)
    y = int(bbox.ymin * h)
    bw = int(bbox.width * w)
    bh = int(bbox.height * h)

    x1 = max(0, x - margin)
    y1 = max(0, y - margin)
    x2 = min(w, x + bw + margin)
    y2 = min(h, y + bh + margin)

    face_img = img[y1:y2, x1:x2]
    confidence = det.score[0]

    return face_img, confidence


# ============================
# EMBEDDING EXTRACTION
# ============================
def get_embedding_from_bytes(img_bytes: bytes):
    """Crop → get FaceNet embedding → reduce to 64D with PCA → normalize."""
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

    # Get 128D embedding
    embedding_128d = np.array(emb_obj[0]["embedding"])
    
    # Normalize 128D embedding
    embedding_128d = embedding_128d / np.linalg.norm(embedding_128d)
    
    # Reduce to 64D using PCA
    embedding_64d = pca_model.transform(embedding_128d.reshape(1, -1))[0]
    
    # Normalize 64D embedding
    embedding_64d = embedding_64d / np.linalg.norm(embedding_64d)

    return embedding_64d, conf


# ============================
# EMBEDDING COMPARISON
# ============================
def compare_embeddings(e1, e2):
    """Cosine + Euclidean → final decision."""
    cosine = float(np.dot(e1, e2))
    euclid = float(np.linalg.norm(e1 - e2))

    is_same = cosine > COSINE_THRESHOLD

    return {
        "cosine_similarity": cosine,
        "euclidean_distance": euclid,
        "is_same_person": is_same,
        "confidence": cosine,
        "embedding_dimension": len(e1)
    }


# ============================
# FASTAPI APP
# ============================
app = FastAPI()


@app.post("/get-embedding")
async def api_get_embedding(file: UploadFile = File(...)):
    try:
        img_bytes = await file.read()
        emb_64d, conf = get_embedding_from_bytes(img_bytes)

        return {
            "embedding": emb_64d.tolist(),
            "confidence": float(conf),
            "dimension": len(emb_64d)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/compare-embeddings")
async def api_compare_embeddings(data: dict = Body(...)):
    try:
        emb1 = np.array(data["face_login"])
        emb2 = np.array(data["face_reg"])

        result = compare_embeddings(emb1, emb2)

        return result

    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing key: {e}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============================
# RUN LOCAL SERVER
# ============================
if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)