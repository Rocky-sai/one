import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, status, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
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
MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/acharya")
JWT_SECRET = os.environ.get("JWT_SECRET", "your_jwt_secret_key_change_in_production")
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

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode())

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

async def extract_text_from_pdf(file_path: str) -> str:
    try:
        return extract_text(file_path)
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {e}")
        return ""

# ---------- LIFESPAN EVENT ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    try:
        # Test database connection
        await db.command("ping")
        logger.info("Connected to MongoDB successfully")
        
        # Initialize default data if collections are empty
        if await db.users.count_documents({}) == 0:
            default_users = [
                {"username": "admin", "password": get_password_hash("admin123"), "role": "Admin", "skills": "", "experience": "", "education": "", "projects": ""},
                {"username": "recruiter1", "password": get_password_hash("recruiter123"), "role": "Recruiter", "skills": "", "experience": "", "education": "", "projects": ""},
                {"username": "candidate1", "password": get_password_hash("candidate123"), "role": "Candidate", "skills": "Python, JavaScript", "experience": "2 years", "education": "B.Tech", "projects": "Web Development"}
            ]
            await db.users.insert_many(default_users)
            logger.info("Inserted default users")
            
        if await db.jobs.count_documents({}) == 0:
            default_jobs = [
                {"title": "Software Engineer", "company": "TechCorp", "location": "Remote"},
                {"title": "Data Analyst", "company": "DataWorks", "location": "New York"},
                {"title": "Web Developer", "company": "InnovateTech", "location": "San Francisco"}
            ]
            await db.jobs.insert_many(default_jobs)
            logger.info("Inserted default jobs")
            
        if await db.clients.count_documents({}) == 0:
            default_clients = [
                {"name": "TechCorp", "contact": "hr@techcorp.com"},
                {"name": "DataWorks", "contact": "jobs@dataworks.com"}
            ]
            await db.clients.insert_many(default_clients)
            logger.info("Inserted default clients")
            
        logger.info("Database initialization completed")
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    
    yield
    
    # Shutdown
    try:
        client.close()
        logger.info("Database connection closed")
    except Exception as e:
        logger.error(f"Error closing database connection: {e}")

# ---------- APP SETUP ----------
app = FastAPI(
    title="Acharya Job Portal Backend", 
    version="1.0.0", 
    description="A comprehensive job portal platform with AI-powered features",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (for frontend)
app.mount("/static", StaticFiles(directory="."), name="static")

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
    token_type: str = "bearer"
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
        headers={"WWW-Authenticate": "Bearer"},
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
async def analyze_resume_with_ai(resume_text: str, job_description: str):
    """
    Placeholder for AI resume analysis
    In production, integrate with OpenAI, Google Gemini, or similar AI service
    """
    # Mock analysis based on simple keyword matching
    job_keywords = job_description.lower().split()
    resume_keywords = resume_text.lower().split()
    
    common_keywords = set(job_keywords) & set(resume_keywords)
    suitability_score = min(100, len(common_keywords) * 10)
    
    missing_skills = ["Docker", "Kubernetes"] if "docker" not in resume_text.lower() else []
    
    return {
        "suitabilityScore": suitability_score,
        "missingSkills": missing_skills,
        "capabilityAnalysis": f"The candidate shows {suitability_score}% alignment with the job requirements. Consider upskilling in missing areas."
    }

async def evaluate_mock_test_with_ai(test_type: str, questions: List[dict], answers: List[dict]):
    """
    Placeholder for AI test evaluation
    """
    if not answers or not questions:
        return {"score": 0, "evaluation": "No answers provided"}
    
    correct_count = 0
    for i, (question, answer) in enumerate(zip(questions, answers)):
        if i < len(answers) and answer.get('answer', '').strip().lower() == question.get('correctAnswer', '').strip().lower():
            correct_count += 1
    
    score = int((correct_count / len(questions)) * 100) if questions else 0
    
    evaluation = f"Scored {score}% ({correct_count}/{len(questions)} correct). "
    if score >= 80:
        evaluation += "Excellent performance!"
    elif score >= 60:
        evaluation += "Good effort, room for improvement."
    else:
        evaluation += "Needs significant improvement."
    
    return {"score": score, "evaluation": evaluation}

# ---------- ERROR HANDLERS ----------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

# ---------- ENDPOINTS ----------

@app.get("/")
async def root():
    return {"message": "Acharya Job Portal API", "version": "1.0.0", "status": "running"}

@app.get("/health")
async def health_check():
    try:
        await db.command("ping")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}

@app.post("/api/register")
async def register(user: UserIn):
    try:
        if user.role not in ['Admin', 'Recruiter', 'Candidate']:
            raise HTTPException(status_code=400, detail="Invalid role")
        
        # Check if username already exists
        existing = await db.users.find_one({"username": user.username})
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Hash password and create user
        hashed_password = get_password_hash(user.password)
        user_doc = {
            "username": user.username,
            "password": hashed_password,
            "role": user.role,
            "skills": "",
            "experience": "",
            "education": "",
            "projects": ""
        }
        
        await db.users.insert_one(user_doc)
        
        # Log activity
        await db.activities.insert_one({
            "description": f"User {user.username} registered as {user.role}",
            "timestamp": datetime.utcnow()
        })
        
        logger.info(f"User {user.username} registered as {user.role}")
        return {"success": True, "message": "User registered successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    try:
        # Find user
        user = await db.users.find_one({"username": credentials.username})
        if not user:
            logger.warning(f"Login failed: User {credentials.username} not found")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not verify_password(credentials.password, user["password"]):
            logger.warning(f"Login failed: Invalid password for user {credentials.username}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create access token
        access_token = create_access_token(
            data={"username": user["username"], "role": user["role"]}
        )
        
        # Log activity
        await db.activities.insert_one({
            "description": f"User {user['username']} logged in",
            "timestamp": datetime.utcnow()
        })
        
        logger.info(f"User {user['username']} logged in successfully")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user["role"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/activities")
async def get_activities(user=Depends(admin_required)):
    try:
        activities = await db.activities.find().sort("timestamp", -1).limit(100).to_list(100)
        return activities
    except Exception as e:
        logger.error(f"Error fetching activities: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch activities")

@app.get("/api/activities/filter")
async def filter_activities(filter: str, user=Depends(admin_required)):
    try:
        activities = await db.activities.find({
            "description": {"$regex": filter, "$options": "i"}
        }).sort("timestamp", -1).limit(100).to_list(100)
        return activities
    except Exception as e:
        logger.error(f"Error filtering activities: {e}")
        raise HTTPException(status_code=500, detail="Failed to filter activities")

@app.get("/api/jobs")
async def get_jobs(user=Depends(get_current_user)):
    try:
        jobs = await db.jobs.find().to_list(100)
        return jobs
    except Exception as e:
        logger.error(f"Error fetching jobs: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch jobs")

@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, user=Depends(recruiter_required)):
    try:
        from bson import ObjectId
        job = await db.jobs.find_one({"_id": ObjectId(job_id)})
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        job["_id"] = str(job["_id"])
        return job
    except Exception as e:
        logger.error(f"Error fetching job: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch job")

@app.put("/api/jobs/{job_id}")
async def update_job(job_id: str, job: Job, user=Depends(recruiter_required)):
    try:
        from bson import ObjectId
        result = await db.jobs.find_one_and_update(
            {"_id": ObjectId(job_id)},
            {"$set": job.dict()},
            return_document=True
        )
        if not result:
            raise HTTPException(status_code=404, detail="Job not found")
        
        await db.activities.insert_one({
            "description": f"Job updated: {job.title} by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        result["_id"] = str(result["_id"])
        return result
    except Exception as e:
        logger.error(f"Error updating job: {e}")
        raise HTTPException(status_code=500, detail="Failed to update job")

@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str, user=Depends(admin_required)):
    try:
        from bson import ObjectId
        job = await db.jobs.find_one_and_delete({"_id": ObjectId(job_id)})
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        await db.activities.insert_one({
            "description": f"Job deleted: {job['title']} by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        return {"success": True, "message": "Job deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting job: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete job")

@app.post("/api/jobs")
async def post_job(job: Job, user=Depends(recruiter_required)):
    try:
        job_doc = job.dict()
        result = await db.jobs.insert_one(job_doc)
        
        await db.activities.insert_one({
            "description": f"Job posted: {job.title} by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        logger.info(f"Job {job.title} posted by {user['username']}")
        return {"success": True, "message": "Job posted successfully", "job_id": str(result.inserted_id)}
    except Exception as e:
        logger.error(f"Error posting job: {e}")
        raise HTTPException(status_code=500, detail="Failed to post job")

@app.get("/api/clients")
async def get_clients(user=Depends(admin_required)):
    try:
        clients = await db.clients.find().to_list(100)
        return clients
    except Exception as e:
        logger.error(f"Error fetching clients: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch clients")

@app.post("/api/clients")
async def add_client(client: ClientData, user=Depends(admin_required)):
    try:
        await db.clients.insert_one(client.dict())
        
        await db.activities.insert_one({
            "description": f"Client added: {client.name} by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        logger.info(f"Client {client.name} added by {user['username']}")
        return {"success": True, "message": "Client added successfully"}
    except Exception as e:
        logger.error(f"Error adding client: {e}")
        raise HTTPException(status_code=500, detail="Failed to add client")

@app.get("/api/users/{username}")
async def get_user_profile(username: str, user=Depends(get_current_user)):
    try:
        # Users can only access their own profile unless they're admin
        if user['username'] != username and user['role'] != 'Admin':
            raise HTTPException(status_code=403, detail="Access denied")
        
        user_doc = await db.users.find_one({"username": username})
        if not user_doc:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Remove password from response
        user_doc.pop('password', None)
        user_doc['_id'] = str(user_doc.get('_id', ''))
        
        return user_doc
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch user profile")

@app.put("/api/users/{username}")
async def update_user_profile(username: str, user_data: dict, user=Depends(get_current_user)):
    try:
        # Users can only update their own profile unless they're admin
        if user['username'] != username and user['role'] != 'Admin':
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Remove sensitive fields that shouldn't be updated via this endpoint
        update_data = {k: v for k, v in user_data.items() if k not in ['password', 'username', 'role']}
        
        result = await db.users.find_one_and_update(
            {"username": username},
            {"$set": update_data},
            return_document=True
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="User not found")
        
        await db.activities.insert_one({
            "description": f"Profile updated for {username}",
            "timestamp": datetime.utcnow()
        })
        
        # Remove password from response
        result.pop('password', None)
        result['_id'] = str(result.get('_id', ''))
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user profile")

@app.get("/api/applications")
async def get_applications(user=Depends(recruiter_required)):
    try:
        applications = await db.applications.find().to_list(100)
        for app in applications:
            app['_id'] = str(app.get('_id', ''))
        return applications
    except Exception as e:
        logger.error(f"Error fetching applications: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch applications")

@app.put("/api/applications/{app_id}")
async def update_application(app_id: str, application_data: dict, user=Depends(recruiter_required)):
    try:
        from bson import ObjectId
        result = await db.applications.find_one_and_update(
            {"_id": ObjectId(app_id)},
            {"$set": application_data},
            return_document=True
        )
        
        if not result:
            raise HTTPException(status_code=404, detail="Application not found")
        
        await db.activities.insert_one({
            "description": f"Application updated for {result.get('candidate', 'unknown')} by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        result['_id'] = str(result['_id'])
        return result
    except Exception as e:
        logger.error(f"Error updating application: {e}")
        raise HTTPException(status_code=500, detail="Failed to update application")

@app.post("/api/applications")
async def submit_application(app: Application, user=Depends(candidate_required)):
    try:
        app_doc = app.dict()
        app_doc['candidate'] = user['username']
        app_doc['timestamp'] = datetime.utcnow()
        
        await db.applications.insert_one(app_doc)
        
        await db.activities.insert_one({
            "description": f"Application submitted by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        logger.info(f"Application submitted by {user['username']}")
        return {"success": True, "message": "Application submitted successfully"}
    except Exception as e:
        logger.error(f"Error submitting application: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit application")

@app.post("/api/mock-tests")
async def submit_mock_test(test: MockTest, user=Depends(candidate_required)):
    try:
        test_doc = test.dict()
        test_doc['user'] = user['username']
        test_doc['timestamp'] = datetime.utcnow()
        
        await db.mocktests.insert_one(test_doc)
        
        await db.activities.insert_one({
            "description": f"Mock test submitted by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        return {"success": True, "message": "Mock test submitted successfully"}
    except Exception as e:
        logger.error(f"Error submitting mock test: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit mock test")

@app.post("/api/resume-analyze")
async def analyze_resume(req: ResumeAnalyzeReq, user=Depends(candidate_required)):
    try:
        # Simple analysis based on resume length and content
        resume_text = req.resume
        
        if len(resume_text) > 500:
            analysis = "Good length resume. Consider adding more specific achievements and quantifiable results."
        elif len(resume_text) > 200:
            analysis = "Decent resume length. Add more technical skills and project details."
        else:
            analysis = "Resume is too short. Add more details about your experience, skills, and projects."
        
        await db.activities.insert_one({
            "description": f"Resume analyzed by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        logger.info(f"Resume analyzed by {user['username']}")
        return {"success": True, "analysis": analysis}
    except Exception as e:
        logger.error(f"Error analyzing resume: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze resume")

@app.get("/api/chat-messages")
async def get_chat_messages(user=Depends(candidate_required)):
    try:
        messages = await db.chatmessages.find().sort("timestamp", -1).limit(100).to_list(100)
        return messages
    except Exception as e:
        logger.error(f"Error fetching chat messages: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch chat messages")

@app.post("/api/chat-messages")
async def send_message(msg: ChatMessage, user=Depends(candidate_required)):
    try:
        msg_doc = msg.dict()
        msg_doc['sender'] = user['username']
        msg_doc['timestamp'] = datetime.utcnow()
        
        await db.chatmessages.insert_one(msg_doc)
        
        await db.activities.insert_one({
            "description": f"Chat message sent by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        return {"success": True, "message": "Message sent successfully"}
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        raise HTTPException(status_code=500, detail="Failed to send message")

@app.post("/api/coding-practice")
async def submit_code(cp: CodingPractice, user=Depends(candidate_required)):
    try:
        cp_doc = cp.dict()
        cp_doc['user'] = user['username']
        cp_doc['timestamp'] = datetime.utcnow()
        
        await db.codingpractices.insert_one(cp_doc)
        
        await db.activities.insert_one({
            "description": f"Code submitted by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        return {"success": True, "message": "Code submitted successfully"}
    except Exception as e:
        logger.error(f"Error submitting code: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit code")

@app.post("/api/recruiter/analyze-resume")
async def recruiter_analyze_resume(
    candidate: str = Form(...),
    jobDescription: str = Form(...),
    resume: UploadFile = File(...),
    user=Depends(recruiter_required)
):
    try:
        # Save uploaded file
        file_path = os.path.join(UPLOAD_DIR, f"{uuid4()}_{resume.filename}")
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(resume.file, buffer)
        
        # Extract text from PDF
        resume_text = await extract_text_from_pdf(file_path)
        
        # Analyze with AI (placeholder)
        analysis = await analyze_resume_with_ai(resume_text, jobDescription)
        
        # Clean up file
        os.remove(file_path)
        
        # Save analysis to database
        analysis_doc = {
            "candidate": candidate,
            "jobDescription": jobDescription,
            "resumeText": resume_text,
            "suitabilityScore": analysis["suitabilityScore"],
            "missingSkills": analysis["missingSkills"],
            "capabilityAnalysis": analysis["capabilityAnalysis"],
            "analyzedAt": datetime.utcnow(),
            "analyzedBy": user["username"]
        }
        
        await db.resumeanalyses.insert_one(analysis_doc)
        
        logger.info(f"Resume analyzed for {candidate} by recruiter {user['username']}")
        
        return {"success": True, "analysis": analysis}
        
    except Exception as e:
        logger.error(f"Error in resume analysis: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze resume")

@app.get("/api/recruiter/resume-analysis/{candidate}")
async def recruiter_get_resume_analyses(candidate: str, user=Depends(recruiter_required)):
    try:
        analyses = await db.resumeanalyses.find(
            {"candidate": candidate}
        ).sort("analyzedAt", -1).to_list(100)
        
        for analysis in analyses:
            analysis['_id'] = str(analysis.get('_id', ''))
        
        return {"success": True, "analyses": analyses}
    except Exception as e:
        logger.error(f"Error fetching resume analyses: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch resume analyses")

@app.post("/api/recruiter/assign-mock-test")
async def assign_mock_test(test_data: dict, user=Depends(recruiter_required)):
    try:
        test_doc = {
            "candidate": test_data["candidate"],
            "testType": test_data["testType"],
            "questions": test_data["questions"],
            "duration": test_data["duration"],
            "assignedBy": user["username"],
            "status": "Pending",
            "assignedAt": datetime.utcnow()
        }
        
        result = await db.assignedmocktests.insert_one(test_doc)
        
        await db.activities.insert_one({
            "description": f"Mock test assigned to {test_data['candidate']} by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        return {"success": True, "message": "Mock test assigned successfully", "test_id": str(result.inserted_id)}
    except Exception as e:
        logger.error(f"Error assigning mock test: {e}")
        raise HTTPException(status_code=500, detail="Failed to assign mock test")

@app.post("/api/candidate/submit-mock-test/{test_id}")
async def submit_mock_test_answers(test_id: str, answers_data: dict, user=Depends(candidate_required)):
    try:
        from bson import ObjectId
        
        # Find the mock test
        mock_test = await db.assignedmocktests.find_one({"_id": ObjectId(test_id)})
        if not mock_test:
            raise HTTPException(status_code=404, detail="Mock test not found")
        
        if mock_test['candidate'] != user['username']:
            raise HTTPException(status_code=403, detail="Not authorized")
        
        if mock_test['status'] == 'Completed':
            raise HTTPException(status_code=400, detail="Test already completed")
        
        # Evaluate answers
        answers = answers_data.get('answers', [])
        eval_result = await evaluate_mock_test_with_ai(
            mock_test['testType'], 
            mock_test['questions'], 
            answers
        )
        
        # Update test with results
        await db.assignedmocktests.update_one(
            {"_id": ObjectId(test_id)},
            {"$set": {
                "status": "Completed",
                "score": eval_result['score'],
                "evaluation": eval_result['evaluation'],
                "submittedAt": datetime.utcnow(),
                "answers": answers,
            }}
        )
        
        await db.activities.insert_one({
            "description": f"Mock test submitted by {user['username']}",
            "timestamp": datetime.utcnow()
        })
        
        return {
            "success": True,
            "score": eval_result['score'],
            "evaluation": eval_result['evaluation']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting mock test: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit mock test")

@app.get("/api/recruiter/mock-test-results/{candidate}")
async def recruiter_get_mock_test_results(candidate: str, user=Depends(recruiter_required)):
    try:
        tests = await db.assignedmocktests.find({
            "candidate": candidate,
            "status": "Completed"
        }).sort("submittedAt", -1).to_list(100)
        
        for test in tests:
            test['_id'] = str(test.get('_id', ''))
        
        return {"success": True, "tests": tests}
    except Exception as e:
        logger.error(f"Error fetching mock test results: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch mock test results")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)