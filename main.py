from fastapi import FastAPI, UploadFile, File, Form, HTTPException

from fastapi.middleware.cors import CORSMiddleware

import shutil

import os

from logic import analyze_logs



app = FastAPI()



# --- MIDDLEWARE ---

# This allows your HTML file to communicate with this FastAPI server

app.add_middleware(

    CORSMiddleware,

    allow_origins=["*"],  # This allows your Live Server (5500) to talk to FastAPI (8000)

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)



# --- CONFIGURATION ---

# Create uploads folder if missing to prevent errors

if not os.path.exists("uploads"):

    os.makedirs("uploads")



# Default credentials for the "Secure Terminal"

DEFAULT_USER = "admin"

DEFAULT_PASS = "admin123"



# --- ENDPOINTS ---



@app.post("/login")

async def login(username: str = Form(...), password: str = Form(...)):

    """

    Handles the Pre-Authorized Authentication logic.

    """

    if username == DEFAULT_USER and password == DEFAULT_PASS:

        return {"status": "success", "message": "Access Granted"}

    else:

        # Sends a 401 Unauthorized error if credentials fail

        raise HTTPException(status_code=401, detail="Invalid Credentials")



@app.post("/analyze")

async def upload_log(file: UploadFile = File(...), threshold: int = Form(60)):

    """

    Handles log file uploads and triggers the forensic analysis.

    """

    temp_path = f"uploads/{file.filename}"

   

    # Save the uploaded file temporarily

    with open(temp_path, "wb") as buffer:

        shutil.copyfileobj(file.file, buffer)

   

    try:

        # Call the analysis logic from logic.py

        # This now returns a dictionary containing 'incidents', 'integrity_score', and 'total_gaps'

        results = analyze_logs(temp_path, threshold)

       

        return results

       

    except Exception as e:

        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

       

    finally:

        # CLEANUP: Always remove the file after processing to save space

        if os.path.exists(temp_path):

            os.remove(temp_path)



if __name__ == "__main__":

    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)