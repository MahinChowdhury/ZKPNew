import os
import cv2
import time
import pickle
import numpy as np
from fastapi import FastAPI, File, UploadFile, HTTPException, Body
from fastapi.responses import JSONResponse
import uvicorn
from deepface import DeepFace


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
DeepFace.build_model("Facenet")  # load Facenet once

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
print("✓ OpenCV Haar face detector loaded")


# ============================
# FACE DETECTION
# ============================
def detect_face_from_bytes(img_bytes: bytes, margin=20):
    """Detect and crop a face from raw bytes using OpenCV Haar Cascade."""
    np_img = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(np_img, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Invalid image")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    h, w = img.shape[:2]

    faces = face_cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(30, 30)
    )

    if len(faces) == 0:
        raise ValueError("No face detected")

    # Use the first detected face
    x, y, bw, bh = faces[0]

    x1 = max(0, x - margin)
    y1 = max(0, y - margin)
    x2 = min(w, x + bw + margin)
    y2 = min(h, y + bh + margin)

    face_img = img[y1:y2, x1:x2]
    confidence = 1.0  # Haar doesn't return confidence scores

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