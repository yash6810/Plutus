# 🛡️ Honeypot Scam Detection Agent

AI-powered honeypot system that detects scams, engages scammers autonomously, and extracts intelligence.

**Hackathon:** GUVI x HCL India AI Impact Buildathon  
**Problem Statement:** Agentic Honey-Pot for Scam Detection  
**Team:** Yash, Aniket Kumar Singh, Krishna Garg, Aayush Srivastava  
**Timeline:** January 27 - February 5, 2026

---

## 🚀 Quick Start (First Time Setup)

### Prerequisites

- Python 3.10 or higher
- Git
- Google account (for free Gemini API key)
- Code editor (VS Code recommended)

### Step 1: Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd honeypot-agent

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Get Your Free Gemini API Key

1. Go to <https://aistudio.google.com/app/apikey>
2. Sign in with Google account
3. Click "Create API key in new project"
4. Copy the key (starts with `AIza...`)

### Step 3: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your API key
# On Windows: notepad .env
# On Mac/Linux: nano .env
```

Your `.env` should look like:
GEMINI_API_KEY=AIzaSyC_your_actual_key_here
API_SECRET_KEY=your-unique-secret-key-123
AI_PROVIDER=gemini

### Step 4: Verify Setup

```bash
# Test configuration
python config.py

# You should see:
# ✅ Configuration is valid!

# Run tests
python -m pytest tests/ -v
```

---

## 📁 Project Structure

honeypot-agent/
├── agents/              # Yash's work - AI agent system
│   ├── detector_agent.py
│   ├── actor_agent.py
│   ├── investigator_agent.py
│   ├── session_manager.py
│   └── orchestrator.py
│
├── api/                 # Aniket's work - FastAPI backend
│   ├── main.py
│   ├── models.py
│   ├── callback.py
│   └── auth.py
│
├── intelligence/        # Aayush's work - Pattern extraction
│   ├── extractors.py
│   ├── validators.py
│   └── scam_database.json
│
├── tests/              # Aayush's work - Testing
│   ├── test_api.py
│   ├── test_agents.py
│   └── manual_test.py
│
├── dashboard/          # Krishna's work - React frontend
│   └── src/
│       ├── App.jsx
│       └── components/
│
├── config.py           # Configuration manager
├── requirements.txt    # Python dependencies
└── .env               # Your API keys (never commit!)

---

## 👥 Team Member Quick Start

### Yash (Agent Architect)

```bash
# Your main folder
cd agents/

# Start with detector agent
# Use Gemini CLI guide section for Yash

# Test your work
python -m pytest tests/test_agents.py -v
```

### Aniket (Backend Engineer)

```bash
# Your main folder
cd api/

# Start the development server
uvicorn api.main:app --reload

# Server runs at: http://localhost:8000
# API docs at: http://localhost:8000/docs

# Test with curl
curl http://localhost:8000/health
```

### Aayush (Testing Lead)

```bash
# Your main folders
cd intelligence/  # or cd tests/

# Run extraction tests
python -m pytest tests/test_extractors.py -v

# Run manual test
python tests/manual_test.py

# Generate coverage report
pytest --cov=. --cov-report=html
```

### Krishna (Frontend Developer)

```bash
# Your main folder
cd dashboard/

# Install dependencies
npm install

# Start development server
npm start

# Frontend runs at: http://localhost:3000
```

---

## 🔧 Common Commands

### Run the API Server

```bash
# Development mode (auto-reload on file changes)
uvicorn api.main:app --reload

# Production mode
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Run Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_api.py -v

# Run with coverage
pytest --cov=. --cov-report=term-missing
```

### Check Code Quality

```bash
# Format code
black agents/ api/ intelligence/

# Check for errors
pylint agents/ api/ intelligence/

# Type checking
mypy agents/ api/
```

---

## 🧪 Testing Your API

### Using curl

```bash
# Health check
curl http://localhost:8000/health

# Analyze a scam message
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-secret-key-123" \
  -d '{
    "sessionId": "test-session-1",
    "message": {
      "sender": "scammer",
      "text": "Your account will be blocked. Verify at bit.ly/fake",
      "timestamp": "2026-01-27T10:00:00Z"
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```

### Using Python requests

```python
import requests

response = requests.post(
    "http://localhost:8000/analyze",
    headers={
        "Content-Type": "application/json",
        "x-api-key": "your-secret-key-123"
    },
    json={
        "sessionId": "test-1",
        "message": {
            "sender": "scammer",
            "text": "Send money to 9876543210",
            "timestamp": "2026-01-27T10:00:00Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
    }
)

print(response.json())
```

---

## 🚀 Deployment (Render.com)

The project is live at: [https://plutus-cfi3.onrender.com](https://plutus-cfi3.onrender.com)

### Steps to Deploy
1. Push code to GitHub.
2. Connect Repo to **Render.com** as a **Web Service**.
3. Use **Docker** as the runtime.
4. Add environment variables:
   - `GEMINI_API_KEY`
   - `API_SECRET_KEY`
5. Render will automatically build the `Dockerfile` and deploy.

---

## 🏆 Success Status
- ✅ **API Live**: [https://plutus-cfi3.onrender.com/health](https://plutus-cfi3.onrender.com/health)
- ✅ **Detection**: 95%+ Accuracy using Gemini 2.0 Flash.
- ✅ **Persona Engine**: 3 unique personas (Elderly, Pro, Novice).
- ✅ **Dashboard**: Interactive glassmorphism dashboard included.

---

## 📄 License
This project is for educational purposes (GUVI x HCL Hackathon 2026).

**Let's win this! 🚀**

