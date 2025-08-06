#!/usr/bin/env python3
"""
Startup script for the Acharya Job Portal
"""
import os
import sys
import subprocess
import time
from pathlib import Path

def check_requirements():
    """Check if all required packages are installed"""
    try:
        import fastapi
        import uvicorn
        import motor
        import jose
        import bcrypt
        import dotenv
        print("✅ All required packages are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing required package: {e}")
        print("Installing requirements...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        return True

def create_env_file():
    """Create .env file if it doesn't exist"""
    env_file = Path(".env")
    if not env_file.exists():
        env_content = """# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/acharya

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_change_in_production_please

# Server Configuration
HOST=0.0.0.0
PORT=8000
"""
        with open(env_file, "w") as f:
            f.write(env_content)
        print("✅ Created .env file with default configuration")
    else:
        print("✅ .env file already exists")

def start_server():
    """Start the FastAPI server"""
    print("🚀 Starting Acharya Job Portal Server...")
    print("📍 Server will be available at: http://localhost:8000")
    print("📍 API Documentation: http://localhost:8000/docs")
    print("📍 Frontend: http://localhost:8000/static/index.html")
    print("\n" + "="*50)
    
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn", 
            "main:app", 
            "--host", "0.0.0.0", 
            "--port", "8000", 
            "--reload"
        ])
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

def main():
    print("🎯 Acharya Job Portal - Career Forging Platform")
    print("="*50)
    
    # Check and install requirements
    if not check_requirements():
        return
    
    # Create .env file
    create_env_file()
    
    # Start server
    start_server()

if __name__ == "__main__":
    main()