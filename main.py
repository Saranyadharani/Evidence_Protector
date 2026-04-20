from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import magic  # python-magic for MIME sniffing

# --- FILE VALIDATION CONSTANTS ---
ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".xml", ".syslog", ".evtx"}
ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/csv",
    "application/json",
    "application/xml",
    "text/xml",
    "text/x-log",
    "application/octet-stream",  # fallback for .log/.evtx on some systems
}
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB

# Ensure the logic.py file exists and has the analyze_logs function
try:
    from logic import analyze_logs
except ImportError:
    print("WARNING: logic.py not found. Ensure it is in the same directory.")

app = FastAPI()

# --- MIDDLEWARE ---
# Updated to be extremely permissive to avoid "Backend Link Error"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURATION ---
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

DEFAULT_USER = "admin"
DEFAULT_PASS = "admin123"

# --- ENDPOINTS ---

@app.get("/")
async def root():
    """Health check endpoint to verify backend is running."""
    return {"status": "online", "system": "Evidence Protector Pro"}

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username == DEFAULT_USER and password == DEFAULT_PASS:
        return {"status": "success", "message": "Access Granted"}
    raise HTTPException(status_code=401, detail="Invalid Credentials")

@app.post("/analyze")
async def upload_log(file: UploadFile = File(...), threshold: str = Form("60")):
    # ── 1. FILENAME / EXTENSION VALIDATION ──────────────────────────────────
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    _, ext = os.path.splitext(file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{ext}' is not allowed. Accepted types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # ── 2. FILE SIZE VALIDATION ──────────────────────────────────────────────
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."
        )
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # ── 3. MIME TYPE VALIDATION (magic-byte sniffing) ────────────────────────
    try:
        detected_mime = magic.from_buffer(contents, mime=True)
    except Exception:
        detected_mime = "unknown"

    if detected_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"File content type '{detected_mime}' is not permitted. Only log/text files are accepted."
        )

    # ── 4. SAFE FILENAME (prevent path traversal) ────────────────────────────
    safe_name = os.path.basename(file.filename).replace("..", "").replace("/", "").replace("\\", "")
    temp_path = os.path.join(UPLOAD_DIR, safe_name)

    # ── 5. WRITE & ANALYZE ───────────────────────────────────────────────────
    try:
        with open(temp_path, "wb") as buffer:
            buffer.write(contents)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {str(e)}")

    try:
        numeric_threshold = int(threshold)
        results = analyze_logs(temp_path, numeric_threshold)
        return results
    except Exception as e:
        print(f"Analysis Error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    import uvicorn
    # Make sure port 8000 matches your dashboard.js fetch URL
    uvicorn.run(app, host="127.0.0.1", port=8000)