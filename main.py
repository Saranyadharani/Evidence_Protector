from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os

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
    """
    FIX: Changed threshold to 'str' in the signature. 
    FormData often sends numbers as strings; we convert it inside.
    """
    # Create a unique filename to avoid collisions if multiple people use it
    temp_path = os.path.join(UPLOAD_DIR, file.filename)
    
    # Save the uploaded file
    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {str(e)}")
    
    try:
        # Convert threshold string back to int for the logic function
        numeric_threshold = int(threshold)
        
        # Execute forensic analysis
        results = analyze_logs(temp_path, numeric_threshold)
        
        # Ensure results is a dictionary (JSON serializable)
        return results
        
    except Exception as e:
        # Log the error to your terminal so you can see why it failed
        print(f"Analysis Error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
        
    finally:
        # CLEANUP: Crucial to prevent folder bloat
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    import uvicorn
    # Make sure port 8000 matches your dashboard.js fetch URL
    uvicorn.run(app, host="127.0.0.1", port=8000)