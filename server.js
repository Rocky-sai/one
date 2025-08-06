const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const winston = require('winston');
const portfinder = require('portfinder');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const pdfParse = require('pdf-parse');
const fs = require('fs');
const path = require('path');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve static files (HTML, CSS, JS)

// Setup logging with winston
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console()
    ],
});

// MongoDB connection with Atlas
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    logger.error('MONGODB_URI is not defined in .env file');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => logger.info('Connected to MongoDB Atlas'))
    .catch(err => {
        logger.error('MongoDB Atlas connection error:', err);
        process.exit(1);
    });

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    logger.error('JWT_SECRET is not defined in .env file');
    process.exit(1);
}

// Gemini AI Setup
const genAI = new GoogleGenerativeAI((process.env.GEMINI_API_KEY || 'AIzaSyCEfBjtgmX3YCBoMUbnIacHXo6BbsIVMX0'));
const geminiModel = genAI.getGenerativeModel({ model: 'gemini-pro' });

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    },
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF files are allowed'), false);
        }
    },
    limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn('No or invalid Authorization header provided');
        return res.status(401).json({ success: false, message: 'Access denied: No token provided' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        logger.warn('Token missing in Authorization header');
        return res.status(401).json({ success: false, message: 'Access denied: Token missing' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn('Invalid token:', err.message);
            return res.status(403).json({ success: false, message: 'Invalid token: ' + err.message });
        }
        req.user = user;
        next();
    });
};

// Define Schemas
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['Admin', 'Recruiter', 'Candidate'], required: true },
    skills: String,
    experience: String,
    education: String,
    projects: String,
});

const activitySchema = new mongoose.Schema({
    description: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
});

const jobSchema = new mongoose.Schema({
    title: { type: String, required: true },
    company: { type: String, required: true },
    location: { type: String, required: true },
});

const clientSchema = new mongoose.Schema({
    name: { type: String, required: true },
    contact: { type: String, required: true },
});

const applicationSchema = new mongoose.Schema({
    candidate: { type: String, required: true },
    job: { type: String, required: true },
    resume: { type: String, required: true },
    status: { type: String, default: 'Pending' },
    feedback: String,
});

const chatMessageSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
});

const mockTestSchema = new mongoose.Schema({
    user: { type: String, required: true },
    testName: { type: String, required: true },
    score: { type: Number, required: true },
});

const codingPracticeSchema = new mongoose.Schema({
    user: { type: String, required: true },
    problem: { type: String, required: true },
    code: { type: String, required: true },
    output: String,
});

const assignedMockTestSchema = new mongoose.Schema({
    candidate: { type: String, required: true },
    testType: { type: String, enum: ['Coding', 'Aptitude'], required: true },
    questions: [{ question: String, correctAnswer: String }],
    duration: { type: Number, required: true }, // Duration in minutes
    assignedBy: { type: String, required: true }, // Recruiter username
    status: { type: String, enum: ['Pending', 'Completed'], default: 'Pending' },
    score: Number,
    evaluation: String,
    submittedAt: Date,
    answers: [{ question: String, answer: String }],
});

const resumeAnalysisSchema = new mongoose.Schema({
    candidate: { type: String, required: true },
    jobDescription: { type: String, required: true },
    resumeText: { type: String, required: true },
    suitabilityScore: Number,
    missingSkills: [String],
    capabilityAnalysis: String,
    analyzedAt: { type: Date, default: Date.now },
});

// Define Models
const User = mongoose.model('User', userSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Job = mongoose.model('Job', jobSchema);
const Client = mongoose.model('Client', clientSchema);
const Application = mongoose.model('Application', applicationSchema);
const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);
const MockTest = mongoose.model('MockTest', mockTestSchema);
const CodingPractice = mongoose.model('CodingPractice', codingPracticeSchema);
const AssignedMockTest = mongoose.model('AssignedMockTest', assignedMockTestSchema);
const ResumeAnalysis = mongoose.model('ResumeAnalysis', resumeAnalysisSchema);

// Input validation middleware
const validateInput = (fields) => (req, res, next) => {
    for (const field of fields) {
        if (!req.body[field] || typeof req.body[field] !== 'string' || req.body[field].trim() === '') {
            logger.warn(`Validation failed: ${field} is missing or invalid`);
            return res.status(400).json({ success: false, message: `Validation error: ${field} is required` });
        }
    }
    next();
};

// Function to extract text from PDF
const extractTextFromPDF = async (filePath) => {
    try {
        const dataBuffer = fs.readFileSync(filePath);
        const data = await pdfParse(dataBuffer);
        return data.text;
    } catch (error) {
        logger.error('Error extracting text from PDF:', error.message);
        throw new Error('Failed to extract text from PDF');
    }
};

// Function to analyze resume using Gemini AI
const analyzeResumeWithGemini = async (resumeText, jobDescription) => {
    try {
        const prompt = `
        You are an experienced HR Manager with 20 years of experience in recruitment and talent acquisition.
        Your task is to analyze the candidate's resume against the provided job description and provide a detailed evaluation.
        The evaluation should include:

        1. **Suitability Score**: A percentage (0-100) indicating how suitable the candidate is for the job based on skills, experience, and qualifications.
        2. **Missing Skills**: A list of key skills mentioned in the job description that are missing from the resume.
        3. **Capability Analysis**: A detailed paragraph (100-150 words) explaining the candidate's capability to perform the job, including strengths, weaknesses, and areas for improvement.

        Here is the resume text:
        ${resumeText}

        Here is the job description:
        ${jobDescription}

        Provide the response in the following JSON format:
        {
            "suitabilityScore": number,
            "missingSkills": [string],
            "capabilityAnalysis": string
        }
        `;

        const result = await geminiModel.generateContent(prompt);
        const analysis = JSON.parse(result.response.text());
        return analysis;
    } catch (error) {
        logger.error('Error analyzing resume with Gemini AI:', error.message);
        throw new Error('Failed to analyze resume with Gemini AI');
    }
};

// API Endpoints

// Register
app.post('/api/register', validateInput(['username', 'password', 'role']), async (req, res) => {
    try {
        const { username, password, role } = req.body;
        if (!['Admin', 'Recruiter', 'Candidate'].includes(role)) {
            return res.status(400).json({ success: false, message: 'Invalid role' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            logger.warn(`Registration failed: Username ${username} already exists`);
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, password: hashedPassword, role });
        await Activity.create({ description: `User ${username} registered as ${role}` });
        logger.info(`User ${username} registered successfully as ${role}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error in /api/register:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Login
app.post('/api/login', validateInput(['username', 'password']), async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            logger.warn(`Login failed: Invalid credentials for username ${username}`);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            logger.warn(`Login failed: Invalid password for username ${username}`);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        await Activity.create({ description: `User ${username} logged in` });
        logger.info(`User ${username} logged in successfully`);
        res.json({ success: true, token, role: user.role });
    } catch (error) {
        logger.error('Error in /api/login:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Activity Monitoring - Get Activities (Admin only)
app.get('/api/activities', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const activities = await Activity.find().sort({ timestamp: -1 });
        res.json(activities);
    } catch (error) {
        logger.error('Error in /api/activities:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Activity Monitoring - Filter Activities (Admin only)
app.get('/api/activities/filter', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const { filter } = req.query;
        if (!filter) {
            return res.status(400).json({ success: false, message: 'Filter parameter is required' });
        }
        const activities = await Activity.find({ description: new RegExp(filter, 'i') }).sort({ timestamp: -1 });
        res.json(activities);
    } catch (error) {
        logger.error('Error in /api/activities/filter:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Jobs Management - Get Jobs (Admin/Recruiter/Candidate)
app.get('/api/jobs', authenticateToken, async (req, res) => {
    try {
        const jobs = await Job.find();
        res.json(jobs);
    } catch (error) {
        logger.error('Error in /api/jobs:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Jobs Management - Search Job (Admin/Recruiter)
app.get('/api/jobs/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin' && req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin or Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const job = await Job.findById(req.params.id);
        if (job) {
            res.json(job);
        } else {
            res.status(404).json({ success: false, message: 'Job not found' });
        }
    } catch (error) {
        logger.error('Error in /api/jobs/:id:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Jobs Management - Update Job (Admin/Recruiter)
app.put('/api/jobs/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin' && req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin or Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const job = await Job.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!job) {
            return res.status(404).json({ success: false, message: 'Job not found' });
        }
        await Activity.create({ description: `Job updated: ${job.title} by ${req.user.username}` });
        logger.info(`Job ${job.title} updated by ${req.user.username}`);
        res.json(job);
    } catch (error) {
        logger.error('Error in /api/jobs/:id (PUT):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Jobs Management - Delete Job (Admin only)
app.delete('/api/jobs/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const job = await Job.findByIdAndDelete(req.params.id);
        if (!job) {
            return res.status(404).json({ success: false, message: 'Job not found' });
        }
        await Activity.create({ description: `Job deleted: ${job.title} by ${req.user.username}` });
        logger.info(`Job ${job.title} deleted by ${req.user.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error in /api/jobs/:id (DELETE):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Clients Data Management - Get Clients (Admin only)
app.get('/api/clients', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Admin') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const clients = await Client.find();
        res.json(clients);
    } catch (error) {
        logger.error('Error in /api/clients:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Clients Data Management - Add Client (Admin only)
app.post('/api/clients', authenticateToken, validateInput(['name', 'contact']), async (req, res) => {
    if (req.user.role !== 'Admin') {
        logger.warn(`Access denied: User ${req.user.username} is not an Admin`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const client = await Client.create(req.body);
        await Activity.create({ description: `Client added: ${client.name} by ${req.user.username}` });
        logger.info(`Client ${client.name} added by ${req.user.username}`);
        res.json(client);
    } catch (error) {
        logger.error('Error in /api/clients (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Job Postings - Post Job (Recruiter only)
app.post('/api/jobs', authenticateToken, validateInput(['title', 'company', 'location']), async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const job = await Job.create(req.body);
        await Activity.create({ description: `Job posted: ${job.title} by ${req.user.username}` });
        logger.info(`Job ${job.title} posted by ${req.user.username}`);
        res.json(job);
    } catch (error) {
        logger.error('Error in /api/jobs (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Profile Checking - Get User Profile (Candidate only)
app.get('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        logger.error('Error in /api/users/:username:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Profile Checking - Update Profile (Candidate only)
app.put('/api/users/:username', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const user = await User.findOneAndUpdate(
            { username: req.params.username },
            req.body,
            { new: true, runValidators: true }
        );
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        await Activity.create({ description: `Profile updated for ${user.username}` });
        logger.info(`Profile updated for ${user.username}`);
        res.json(user);
    } catch (error) {
        logger.error('Error in /api/users/:username (PUT):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Review Application - Get Applications (Recruiter only)
app.get('/api/applications', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const applications = await Application.find();
        res.json(applications);
    } catch (error) {
        logger.error('Error in /api/applications:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Review Application - Update Application (Recruiter only)
app.put('/api/applications/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const application = await Application.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!application) {
            return res.status(404).json({ success: false, message: 'Application not found' });
        }
        await Activity.create({ description: `Application updated for ${application.candidate} by ${req.user.username}` });
        logger.info(`Application updated for ${application.candidate} by ${req.user.username}`);
        res.json(application);
    } catch (error) {
        logger.error('Error in /api/applications/:id (PUT):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Mock Tests - Submit Test (Candidate only)
app.post('/api/mock-tests', authenticateToken, validateInput(['user', 'testName', 'score']), async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const mockTest = await MockTest.create(req.body);
        await Activity.create({ description: `Mock test submitted by ${mockTest.user}` });
        logger.info(`Mock test submitted by ${mockTest.user}`);
        res.json(mockTest);
    } catch (error) {
        logger.error('Error in /api/mock-tests (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// AI-Driven Resume Analyzer - Analyze Resume (Candidate only)
app.post('/api/resume-analyze', authenticateToken, validateInput(['resume']), async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const { resume } = req.body;
        const analysis = resume.length > 100 ? "Good length, but add more specific achievements." : "Resume too short, add more details.";
        await Activity.create({ description: `Resume analyzed by ${req.user.username}` });
        logger.info(`Resume analyzed by ${req.user.username}`);
        res.json({ success: true, analysis });
    } catch (error) {
        logger.error('Error in /api/resume-analyze (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Apply Jobs - Submit Application (Candidate only)
app.post('/api/applications', authenticateToken, validateInput(['job', 'resume']), async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const application = await Application.create({ ...req.body, candidate: req.user.username });
        await Activity.create({ description: `Application submitted by ${application.candidate}` });
        logger.info(`Application submitted by ${application.candidate}`);
        res.json(application);
    } catch (error) {
        logger.error('Error in /api/applications (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Chat Room - Get Messages (Candidate only)
app.get('/api/chat-messages', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const messages = await ChatMessage.find().sort({ timestamp: -1 });
        res.json(messages);
    } catch (error) {
        logger.error('Error in /api/chat-messages:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Chat Room - Send Message (Candidate only)
app.post('/api/chat-messages', authenticateToken, validateInput(['message']), async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const message = await ChatMessage.create({ ...req.body, sender: req.user.username });
        await Activity.create({ description: `Chat message sent by ${message.sender}` });
        logger.info(`Chat message sent by ${message.sender}`);
        res.json(message);
    } catch (error) {
        logger.error('Error in /api/chat-messages (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Virtual Coding Practice - Submit Code (Candidate only)
app.post('/api/coding-practice', authenticateToken, validateInput(['problem', 'code']), async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }
    try {
        const codingPractice = await CodingPractice.create({ ...req.body, user: req.user.username });
        await Activity.create({ description: `Code submitted by ${codingPractice.user}` });
        logger.info(`Code submitted by ${codingPractice.user}`);
        res.json(codingPractice);
    } catch (error) {
        logger.error('Error in /api/coding-practice (POST):', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Recruiter: Upload and Analyze Resume
app.post('/api/recruiter/analyze-resume', authenticateToken, upload.single('resume'), async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    try {
        const { candidate, jobDescription } = req.body;
        if (!candidate || !jobDescription || !req.file) {
            return res.status(400).json({ success: false, message: 'Candidate username, job description, and resume file are required' });
        }

        // Extract text from the uploaded PDF
        const resumeText = await extractTextFromPDF(req.file.path);

        // Analyze the resume using Gemini AI
        const analysis = await analyzeResumeWithGemini(resumeText, jobDescription);

        // Save the analysis to the database
        const resumeAnalysis = await ResumeAnalysis.create({
            candidate,
            jobDescription,
            resumeText,
            suitabilityScore: analysis.suitabilityScore,
            missingSkills: analysis.missingSkills,
            capabilityAnalysis: analysis.capabilityAnalysis,
        });

        // Delete the uploaded file after analysis
        fs.unlinkSync(req.file.path);

        logger.info(`Resume analyzed for candidate ${candidate} by recruiter ${req.user.username}`);
        res.json({
            success: true,
            analysis: {
                suitabilityScore: analysis.suitabilityScore,
                missingSkills: analysis.missingSkills,
                capabilityAnalysis: analysis.capabilityAnalysis,
            },
        });
    } catch (error) {
        logger.error('Error in /api/recruiter/analyze-resume:', error.message);
        res.status(500).json({ success: false, message: 'Server error: ' + error.message });
    }
});

// Recruiter: Get Resume Analysis Results
app.get('/api/recruiter/resume-analysis/:candidate', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    try {
        const { candidate } = req.params;
        const analyses = await ResumeAnalysis.find({ candidate }).sort({ analyzedAt: -1 });
        res.json({ success: true, analyses });
    } catch (error) {
        logger.error('Error in /api/recruiter/resume-analysis:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Recruiter: Assign Mock Test to Candidate
app.post('/api/recruiter/assign-mock-test', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    try {
        const { candidate, testType, questions, duration } = req.body;
        if (!candidate || !testType || !questions || !duration) {
            return res.status(400).json({ success: false, message: 'Candidate, test type, questions, and duration are required' });
        }

        if (!['Coding', 'Aptitude'].includes(testType)) {
            return res.status(400).json({ success: false, message: 'Invalid test type' });
        }

        if (!Array.isArray(questions) || questions.length === 0) {
            return res.status(400).json({ success: false, message: 'Questions must be a non-empty array' });
        }

        const mockTest = await AssignedMockTest.create({
            candidate,
            testType,
            questions,
            duration,
            assignedBy: req.user.username,
        });

        await Activity.create({ description: `Mock test assigned to ${candidate} by ${req.user.username}` });
        logger.info(`Mock test assigned to ${candidate} by ${req.user.username}`);
        res.json({ success: true, mockTest });
    } catch (error) {
        logger.error('Error in /api/recruiter/assign-mock-test:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Candidate: Submit Mock Test Answers
app.post('/api/candidate/submit-mock-test/:testId', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Candidate') {
        logger.warn(`Access denied: User ${req.user.username} is not a Candidate`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    try {
        const { testId } = req.params;
        const { answers } = req.body;

        if (!answers || !Array.isArray(answers)) {
            return res.status(400).json({ success: false, message: 'Answers must be a non-empty array' });
        }

        const mockTest = await AssignedMockTest.findById(testId);
        if (!mockTest) {
            return res.status(404).json({ success: false, message: 'Mock test not found' });
        }

        if (mockTest.candidate !== req.user.username) {
            return res.status(403).json({ success: false, message: 'You are not authorized to submit this test' });
        }

        if (mockTest.status === 'Completed') {
            return res.status(400).json({ success: false, message: 'Test already completed' });
        }

        // Evaluate the test using Gemini AI
        const prompt = `
        You are an expert evaluator for ${mockTest.testType} tests.
        Evaluate the candidate's answers against the correct answers provided.
        Calculate a score (out of 100) based on the number of correct answers.
        Provide a detailed evaluation (100-150 words) of the candidate's performance, including strengths, weaknesses, and areas for improvement.

        Test Questions and Correct Answers:
        ${JSON.stringify(mockTest.questions)}

        Candidate's Answers:
        ${JSON.stringify(answers)}

        Provide the response in the following JSON format:
        {
            "score": number,
            "evaluation": string
        }
        `;

        const result = await geminiModel.generateContent(prompt);
        const evaluationResult = JSON.parse(result.response.text());

        mockTest.status = 'Completed';
        mockTest.score = evaluationResult.score;
        mockTest.evaluation = evaluationResult.evaluation;
        mockTest.submittedAt = new Date();
        mockTest.answers = answers;
        await mockTest.save();

        await Activity.create({ description: `Mock test submitted by ${req.user.username}` });
        logger.info(`Mock test submitted by ${req.user.username}`);
        res.json({
            success: true,
            score: evaluationResult.score,
            evaluation: evaluationResult.evaluation,
        });
    } catch (error) {
        logger.error('Error in /api/candidate/submit-mock-test:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Recruiter: View Mock Test Results
app.get('/api/recruiter/mock-test-results/:candidate', authenticateToken, async (req, res) => {
    if (req.user.role !== 'Recruiter') {
        logger.warn(`Access denied: User ${req.user.username} is not a Recruiter`);
        return res.status(403).json({ success: false, message: 'Access denied' });
    }

    try {
        const { candidate } = req.params;
        const tests = await AssignedMockTest.find({ candidate, status: 'Completed' }).sort({ submittedAt: -1 });
        res.json({ success: true, tests });
    } catch (error) {
        logger.error('Error in /api/recruiter/mock-test-results:', error.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Initialize some data (for testing)
const initializeData = async () => {
    try {
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                username: 'admin',
                password: hashedPassword,
                role: 'Admin',
                skills: 'JavaScript, Python, SQL',
                experience: '3 years',
                education: 'B.Tech in Computer Science',
                projects: 'To-Do App, E-commerce Website',
            });

            await User.create({
                username: 'recruiter1',
                password: await bcrypt.hash('recruiter123', 10),
                role: 'Recruiter',
            });

            await User.create({
                username: 'candidate1',
                password: await bcrypt.hash('candidate123', 10),
                role: 'Candidate',
                skills: 'JavaScript, React',
                experience: '2 years',
                education: 'B.Sc in Computer Science',
                projects: 'Portfolio Website',
            });
            logger.info('Initialized default users');
        }

        const jobCount = await Job.countDocuments();
        if (jobCount === 0) {
            await Job.insertMany([
                { title: 'Software Engineer', company: 'TechCorp', location: 'Remote' },
                { title: 'Data Analyst', company: 'DataWorks', location: 'New York' },
                { title: 'Web Developer', company: 'InnovateTech', location: 'San Francisco' },
            ]);
            logger.info('Initialized default jobs');
        }

        const clientCount = await Client.countDocuments();
        if (clientCount === 0) {
            await Client.insertMany([
                { name: 'TechCorp', contact: 'hr@techcorp.com' },
                { name: 'DataWorks', contact: 'jobs@dataworks.com' },
            ]);
            logger.info('Initialized default clients');
        }

        const chatCount = await ChatMessage.countDocuments();
        if (chatCount === 0) {
            await ChatMessage.insertMany([
                { sender: 'candidate1', message: 'Hi, anyone preparing for TechCorp?' },
                { sender: 'candidate2', message: 'Yes! Let\'s discuss coding challenges.' },
            ]);
            logger.info('Initialized default chat messages');
        }
    } catch (error) {
        logger.error('Error initializing data:', error.message);
    }
};

// Start the server with port conflict handling
const startServer = async () => {
    try {
        await initializeData();

        let PORT = process.env.PORT || 3000;
        portfinder.basePort = PORT;
        PORT = await portfinder.getPortPromise();

        const server = app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT}`);
        });

        // Handle server errors
        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                logger.error(`Port ${PORT} is already in use`);
                process.exit(1);
            } else {
                logger.error('Server error:', err.message);
                process.exit(1);
            }
        });

        // Graceful shutdown handlers
        process.on('SIGINT', async () => {
            logger.info('Received SIGINT. Shutting down gracefully...');
            server.close(() => {
                logger.info('Server closed');
                mongoose.connection.close()
                    .then(() => {
                        logger.info('MongoDB connection closed');
                        process.exit(0);
                    })
                    .catch((err) => {
                        logger.error('Error closing MongoDB connection:', err.message);
                        process.exit(1);
                    });
            });
        });

        process.on('SIGTERM', async () => {
            logger.info('Received SIGTERM. Shutting down gracefully...');
            server.close(() => {
                logger.info('Server closed');
                mongoose.connection.close()
                    .then(() => {
                        logger.info('MongoDB connection closed');
                        process.exit(0);
                    })
                    .catch((err) => {
                        logger.error('Error closing MongoDB connection:', err.message);
                        process.exit(1);
                    });
            });
        });
    } catch (error) {
        logger.error('Error starting server:', error.message);
        process.exit(1);
    }
};

startServer();