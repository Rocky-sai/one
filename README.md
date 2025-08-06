# 🎯 ACHARYA - Career Forging Platform

A comprehensive job portal platform with AI-powered features for candidates, recruiters, and administrators.

## ✨ Features

### For Candidates
- 👤 Profile Management
- 📝 Job Applications
- 📊 Mock Tests & Assessments
- 📄 AI-Powered Resume Analysis
- 📚 Learning Resources
- 🤖 AI Learning Assistant
- 💬 Chat Room
- 💻 Virtual Coding Practice
- 🔧 AI Coding Assistant
- 🎤 Interview Simulation
- 🏢 Company-Based Tests
- 🎓 Internship Selection
- 📈 Progress Tracking
- 🎯 AI Career Mentor

### For Recruiters
- 💼 Job Posting Management
- 📋 Application Review
- 📊 Resume Analysis with AI
- 🧪 Mock Test Assignment
- 📈 Candidate Performance Analytics

### For Administrators
- 📊 Activity Monitoring
- 💼 Job Management
- 🏢 Client Data Management
- 👥 User Management

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MongoDB (local or Atlas)
- Modern web browser

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd acharya-job-portal
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   - Copy `.env.example` to `.env`
   - Update MongoDB URI and JWT secret

4. **Start the server**
   ```bash
   python start_server.py
   ```

   Or manually:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

5. **Access the application**
   - Frontend: http://localhost:8000/static/index.html
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

## 🏗️ Architecture

### Backend (FastAPI)
- **Framework**: FastAPI with async/await
- **Database**: MongoDB with Motor (async driver)
- **Authentication**: JWT tokens
- **File Upload**: PDF resume processing
- **API Documentation**: Auto-generated with Swagger/OpenAPI

### Frontend
- **Vanilla JavaScript** with modern ES6+ features
- **Responsive CSS** with glassmorphism design
- **Modular architecture** with separate dashboards
- **Real-time updates** and notifications

### Database Schema
- **Users**: Authentication and profile data
- **Jobs**: Job postings and requirements
- **Applications**: Candidate applications
- **Activities**: System activity logs
- **Mock Tests**: Test assignments and results
- **Resume Analyses**: AI-powered resume evaluations

## 🔧 Configuration

### Environment Variables
```env
# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/acharya

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key

# Server Configuration
HOST=0.0.0.0
PORT=8000
```

### Default Users
The system creates default users on first startup:
- **Admin**: username: `admin`, password: `admin123`
- **Recruiter**: username: `recruiter1`, password: `recruiter123`
- **Candidate**: username: `candidate1`, password: `candidate123`

## 📡 API Endpoints

### Authentication
- `POST /api/register` - User registration
- `POST /api/login` - User login

### Jobs
- `GET /api/jobs` - List all jobs
- `POST /api/jobs` - Create job (Recruiter)
- `PUT /api/jobs/{id}` - Update job (Recruiter)
- `DELETE /api/jobs/{id}` - Delete job (Admin)

### Applications
- `GET /api/applications` - List applications (Recruiter)
- `POST /api/applications` - Submit application (Candidate)
- `PUT /api/applications/{id}` - Update application (Recruiter)

### Resume Analysis
- `POST /api/recruiter/analyze-resume` - Analyze resume (Recruiter)
- `GET /api/recruiter/resume-analysis/{candidate}` - Get analyses (Recruiter)

### Mock Tests
- `POST /api/recruiter/assign-mock-test` - Assign test (Recruiter)
- `POST /api/candidate/submit-mock-test/{id}` - Submit test (Candidate)
- `GET /api/recruiter/mock-test-results/{candidate}` - Get results (Recruiter)

## 🎨 UI/UX Improvements

### Modern Design
- **Glassmorphism** effects with backdrop blur
- **Gradient backgrounds** and smooth animations
- **Responsive design** for all screen sizes
- **Intuitive navigation** with visual feedback

### User Experience
- **Loading states** and progress indicators
- **Error handling** with user-friendly messages
- **Form validation** with real-time feedback
- **Accessibility** features and keyboard navigation

### Performance
- **Lazy loading** for better performance
- **Optimized images** and assets
- **Efficient API calls** with proper caching
- **Progressive enhancement** for older browsers

## 🔒 Security Features

- **JWT Authentication** with secure token handling
- **Password hashing** with bcrypt
- **Input validation** and sanitization
- **CORS protection** with configurable origins
- **File upload security** with type validation

## 🧪 Testing

### Manual Testing
1. Register users with different roles
2. Test authentication flows
3. Verify role-based access control
4. Test file upload functionality
5. Validate API responses

### Automated Testing (Future)
- Unit tests for API endpoints
- Integration tests for database operations
- Frontend testing with Jest/Cypress
- Performance testing with load tools

## 📈 Monitoring & Logging

- **Structured logging** with Winston
- **Activity tracking** for audit trails
- **Error logging** with stack traces
- **Performance monitoring** capabilities

## 🚀 Deployment

### Local Development
```bash
python start_server.py
```

### Production Deployment
1. **Environment Setup**
   - Set production environment variables
   - Configure MongoDB Atlas
   - Set secure JWT secret

2. **Server Configuration**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
   ```

3. **Reverse Proxy** (Nginx example)
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the API documentation at `/docs`
- Review the logs in `combined.log`

## 🔮 Future Enhancements

- **Real-time chat** with WebSocket support
- **Video interviews** integration
- **Advanced AI features** with OpenAI/Gemini
- **Mobile app** development
- **Analytics dashboard** with charts
- **Email notifications** system
- **Social media integration**
- **Multi-language support**

---

**Built with ❤️ for empowering careers through technology**