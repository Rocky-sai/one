import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field, EmailStr
import motor.motor_asyncio
from dotenv import load_dotenv
import asyncio
import bcrypt
from uuid import uuid4
import shutil
from pdfminer.high_level import extract_text
import json

# ---------- CONFIGURATION ----------

load_dotenv()
MONGODB_URI = os.environ.get("MONGODB_URI")
JWT_SECRET = os.environ.get("JWT_SECRET", "your_jwt_secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------- LOGGING ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("combined.log"),
        logging.FileHandler("error.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------- DATABASE ----------
client = motor.motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
db = client["acharya"]

# ---------- UTILS ----------

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode())

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

async def extract_text_from_pdf(file_path: str) -> str:
    return extract_text(file_path)

# ---------- LIFESPAN EVENT ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if await db.users.count_documents({}) == 0:
        await db.users.insert_many([
            {"username": "admin", "password": get_password_hash("admin123"), "role": "Admin"},
            {"username": "recruiter1", "password": get_password_hash("recruiter123"), "role": "Recruiter"},
            {"username": "candidate1", "password": get_password_hash("candidate123"), "role": "Candidate"}
        ])
    if await db.jobs.count_documents({}) == 0:
        await db.jobs.insert_many([
            {"title": "Software Engineer", "company": "TechCorp", "location": "Remote"},
            {"title": "Data Analyst", "company": "DataWorks", "location": "New York"},
            {"title": "Web Developer", "company": "InnovateTech", "location": "San Francisco"}
        ])
    if await db.clients.count_documents({}) == 0:
        await db.clients.insert_many([
            {"name": "TechCorp", "contact": "hr@techcorp.com"},
            {"name": "DataWorks", "contact": "jobs@dataworks.com"}
        ])
    if await db.chatmessages.count_documents({}) == 0:
        await db.chatmessages.insert_many([
            {"sender": "candidate1", "message": "Hi, anyone preparing for TechCorp?", "timestamp": datetime.utcnow()},
            {"sender": "candidate2", "message": "Yes! Let's discuss coding challenges.", "timestamp": datetime.utcnow()}
        ])
    logger.info("Startup initialized default data if missing.")
    yield
    # Shutdown (if needed)

# ---------- APP SETUP ----------
app = FastAPI(title="Acharya Job Portal Backend", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- MODELS ----------

class User(BaseModel):
    username: str
    password: str
    role: str
    skills: Optional[str] = ""
    experience: Optional[str] = ""
    education: Optional[str] = ""
    projects: Optional[str] = ""

class UserIn(BaseModel):
    username: str
    password: str
    role: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    role: str

class Activity(BaseModel):
    description: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class Job(BaseModel):
    title: str
    company: str
    location: str

class ClientData(BaseModel):
    name: str
    contact: str

class Application(BaseModel):
    candidate: str
    job: str
    resume: str
    status: str = "Pending"
    feedback: Optional[str] = ""

class ChatMessage(BaseModel):
    sender: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class MockTest(BaseModel):
    user: str
    testName: str
    score: int

class CodingPractice(BaseModel):
    user: str
    problem: str
    code: str
    output: Optional[str] = ""

class Question(BaseModel):
    question: str
    correctAnswer: str

class AssignedMockTest(BaseModel):
    candidate: str
    testType: str
    questions: List[Question]
    duration: int
    assignedBy: str
    status: str = "Pending"
    score: Optional[int] = None
    evaluation: Optional[str] = ""
    submittedAt: Optional[datetime] = None
    answers: Optional[List[Any]] = []

class ResumeAnalysis(BaseModel):
    candidate: str
    jobDescription: str
    resumeText: str
    suitabilityScore: Optional[int]
    missingSkills: Optional[List[str]] = []
    capabilityAnalysis: Optional[str] = ""
    analyzedAt: datetime = Field(default_factory=datetime.utcnow)

class ResumeAnalyzeReq(BaseModel):
    resume: str

# ---------- JWT/OAUTH ----------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        return {"username": username, "role": role}
    except JWTError:
        raise credentials_exception

def admin_required(user=Depends(get_current_user)):
    if user['role'] != 'Admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def recruiter_required(user=Depends(get_current_user)):
    if user['role'] != 'Recruiter':
        raise HTTPException(status_code=403, detail="Recruiter access required")
    return user

def candidate_required(user=Depends(get_current_user)):
    if user['role'] != 'Candidate':
        raise HTTPException(status_code=403, detail="Candidate access required")
    return user

# ---------- AI PLACEHOLDER ----------
async def analyze_resume_with_ai(resume_text, job_description):
    # TODO: Replace with actual Gemini/OpenAI API call
    # For now, return mock data
    return {
        "suitabilityScore": 80,
        "missingSkills": ["Docker", "Kubernetes"],
        "capabilityAnalysis": "The candidate has strong skills but lacks some DevOps experience. Suitable for the role with upskilling."
    }

async def evaluate_mock_test_with_ai(test_type, questions, answers):
    # TODO: Replace with actual Gemini/OpenAI API call
    score = 100 * sum(q['correctAnswer'] == a['answer'] for q, a in zip(questions, answers)) // len(questions)
    return {
        "score": score,
        "evaluation": f"Candidate answered {score}% correctly. Good effort!"
    }

# ---------- ENDPOINTS ----------

@app.post("/api/register")
async def register(user: UserIn):
    if user.role not in ['Admin', 'Recruiter', 'Candidate']:
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = await db.users.find_one({"username": user.username})
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = get_password_hash(user.password)
    user_doc = {**user.dict(), "password": hashed}
    await db.users.insert_one(user_doc)
    await db.activities.insert_one({"description": f"User {user.username} registered as {user.role}", "timestamp": datetime.utcnow()})
    logger.info(f"User {user.username} registered as {user.role}")
    return {"success": True}

@app.post("/api/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"username": credentials.username})
    if not user or not verify_password(credentials.password, user["password"]):
        logger.warning(f"Login failed for username {credentials.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"username": user["username"], "role": user["role"]})
    await db.activities.insert_one({"description": f"User {user['username']} logged in", "timestamp": datetime.utcnow()})
    logger.info(f"User {user['username']} logged in")
    return {"access_token": token, "role": user["role"]}

@app.get("/api/activities")
async def get_activities(user=Depends(admin_required)):
    acts = await db.activities.find().sort("timestamp", -1).to_list(100)
    return acts

@app.get("/api/activities/filter")
async def filter_activities(filter: str, user=Depends(admin_required)):
    acts = await db.activities.find({"description": {"$regex": filter, "$options": "i"}}).sort("timestamp", -1).to_list(100)
    return acts

@app.get("/api/jobs")
async def get_jobs(user=Depends(get_current_user)):
    jobs = await db.jobs.find().to_list(100)
    return jobs

@app.get("/api/jobs/{id}")
async def get_job(id: str, user=Depends(recruiter_required)):
    job = await db.jobs.find_one({"_id": id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

@app.put("/api/jobs/{id}")
async def update_job(id: str, job: Job, user=Depends(recruiter_required)):
    result = await db.jobs.find_one_and_update({"_id": id}, {"$set": job.dict()}, return_document=True)
    if not result:
        raise HTTPException(status_code=404, detail="Job not found")
    await db.activities.insert_one({"description": f"Job updated: {job.title} by {user['username']}", "timestamp": datetime.utcnow()})
    return result

@app.delete("/api/jobs/{id}")
async def delete_job(id: str, user=Depends(admin_required)):
    job = await db.jobs.find_one_and_delete({"_id": id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    await db.activities.insert_one({"description": f"Job deleted: {job['title']} by {user['username']}", "timestamp": datetime.utcnow()})
    return {"success": True}

@app.post("/api/jobs", response_model=Job)
async def post_job(job: Job, user=Depends(recruiter_required)):
    await db.jobs.insert_one(job.dict())
    await db.activities.insert_one({"description": f"Job posted: {job.title} by {user['username']}", "timestamp": datetime.utcnow()})
    return job

@app.get("/api/clients")
async def get_clients(user=Depends(admin_required)):
    clients = await db.clients.find().to_list(100)
    return clients

@app.post("/api/clients")
async def add_client(client: ClientData, user=Depends(admin_required)):
    await db.clients.insert_one(client.dict())
    await db.activities.insert_one({"description": f"Client added: {client.name} by {user['username']}", "timestamp": datetime.utcnow()})
    return client

@app.get("/api/users/{username}")
async def get_user_profile(username: str, user=Depends(candidate_required)):
    u = await db.users.find_one({"username": username})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u

@app.put("/api/users/{username}")
async def update_user_profile(username: str, user_data: User, user=Depends(candidate_required)):
    u = await db.users.find_one_and_update({"username": username}, {"$set": user_data.dict()}, return_document=True)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    await db.activities.insert_one({"description": f"Profile updated for {username}", "timestamp": datetime.utcnow()})
    return u

@app.get("/api/applications")
async def get_applications(user=Depends(recruiter_required)):
    apps = await db.applications.find().to_list(100)
    return apps

@app.put("/api/applications/{id}")
async def update_application(id: str, application: Application, user=Depends(recruiter_required)):
    app = await db.applications.find_one_and_update({"_id": id}, {"$set": application.dict()}, return_document=True)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    await db.activities.insert_one({"description": f"Application updated for {application.candidate} by {user['username']}", "timestamp": datetime.utcnow()})
    return app

@app.post("/api/mock-tests")
async def submit_mock_test(test: MockTest, user=Depends(candidate_required)):
    await db.mocktests.insert_one(test.dict())
    await db.activities.insert_one({"description": f"Mock test submitted by {test.user}", "timestamp": datetime.utcnow()})
    return test

@app.post("/api/resume-analyze")
async def analyze_resume(req: ResumeAnalyzeReq, user=Depends(candidate_required)):
    if len(req.resume) > 100:
        analysis = "Good length, but add more specific achievements."
    else:
        analysis = "Resume too short, add more details."
    await db.activities.insert_one({"description": f"Resume analyzed by {user['username']}", "timestamp": datetime.utcnow()})
    return {"success": True, "analysis": analysis}

@app.post("/api/applications")
async def submit_application(app: Application, user=Depends(candidate_required)):
    await db.applications.insert_one({**app.dict(), "candidate": user["username"]})
    await db.activities.insert_one({"description": f"Application submitted by {user['username']}", "timestamp": datetime.utcnow()})
    return app

@app.get("/api/chat-messages")
async def get_chat_messages(user=Depends(candidate_required)):
    msgs = await db.chatmessages.find().sort("timestamp", -1).to_list(100)
    return msgs

@app.post("/api/chat-messages")
async def send_message(msg: ChatMessage, user=Depends(candidate_required)):
    await db.chatmessages.insert_one({**msg.dict(), "sender": user["username"]})
    await db.activities.insert_one({"description": f"Chat message sent by {user['username']}", "timestamp": datetime.utcnow()})
    return msg

@app.post("/api/coding-practice")
async def submit_code(cp: CodingPractice, user=Depends(candidate_required)):
    await db.codingpractices.insert_one({**cp.dict(), "user": user["username"]})
    await db.activities.insert_one({"description": f"Code submitted by {user['username']}", "timestamp": datetime.utcnow()})
    return cp

@app.post("/api/recruiter/analyze-resume")
async def recruiter_analyze_resume(
    candidate: str = Form(...),
    jobDescription: str = Form(...),
    resume: UploadFile = File(...),
    user=Depends(recruiter_required)
):
    file_path = os.path.join(UPLOAD_DIR, f"{uuid4()}_{resume.filename}")
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(resume.file, buffer)
    resume_text = await extract_text_from_pdf(file_path)
    analysis = await analyze_resume_with_ai(resume_text, jobDescription)
    os.remove(file_path)
    doc = {
        "candidate": candidate,
        "jobDescription": jobDescription,
        "resumeText": resume_text,
        **analysis,
        "analyzedAt": datetime.utcnow(),
    }
    await db.resumeanalyses.insert_one(doc)
    logger.info(f"Resume analyzed for {candidate} by recruiter {user['username']}")
    return {"success": True, "analysis": analysis}

@app.get("/api/recruiter/resume-analysis/{candidate}")
async def recruiter_get_resume_analyses(candidate: str, user=Depends(recruiter_required)):
    analyses = await db.resumeanalyses.find({"candidate": candidate}).sort("analyzedAt", -1).to_list(100)
    return {"success": True, "analyses": analyses}

@app.post("/api/recruiter/assign-mock-test")
async def assign_mock_test(
    candidate: str = Form(...),
    testType: str = Form(...),
    questions: str = Form(...),  # Pass as JSON string
    duration: int = Form(...),
    user=Depends(recruiter_required)
):
    qlist = json.loads(questions)
    doc = {
        "candidate": candidate,
        "testType": testType,
        "questions": qlist,
        "duration": duration,
        "assignedBy": user["username"],
        "status": "Pending"
    }
    await db.assignedmocktests.insert_one(doc)
    await db.activities.insert_one({"description": f"Mock test assigned to {candidate} by {user['username']}", "timestamp": datetime.utcnow()})
    return {"success": True, "mockTest": doc}

@app.post("/api/candidate/submit-mock-test/{testId}")
async def submit_mock_test_answers(testId: str, answers: List[Any], user=Depends(candidate_required)):
    mockTest = await db.assignedmocktests.find_one({"_id": testId})
    if not mockTest:
        raise HTTPException(status_code=404, detail="Mock test not found")
    if mockTest['candidate'] != user['username']:
        raise HTTPException(status_code=403, detail="Not authorized")
    if mockTest['status'] == 'Completed':
        raise HTTPException(status_code=400, detail="Test already completed")
    eval_result = await evaluate_mock_test_with_ai(mockTest['testType'], mockTest['questions'], answers)
    await db.assignedmocktests.update_one(
        {"_id": testId},
        {"$set": {
            "status": "Completed",
            "score": eval_result['score'],
            "evaluation": eval_result['evaluation'],
            "submittedAt": datetime.utcnow(),
            "answers": answers,
        }}
    )
    await db.activities.insert_one({"description": f"Mock test submitted by {user['username']}", "timestamp": datetime.utcnow()})
    return {
        "success": True,
        "score": eval_result['score'],
        "evaluation": eval_result['evaluation']
    }

@app.get("/api/recruiter/mock-test-results/{candidate}")
async def recruiter_get_mock_test_results(candidate: str, user=Depends(recruiter_required)):
    tests = await db.assignedmocktests.find({"candidate": candidate, "status": "Completed"}).sort("submittedAt", -1).to_list(100)
    return {"success": True, "tests": tests}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000)