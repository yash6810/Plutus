# Plutus - Honeypot Scam Detection Agent

AI-powered system that detects scam messages, engages scammers autonomously, and extracts intelligence (bank accounts, UPI IDs, phishing links) for the GUVI x HCL India AI Impact Buildathon.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd d:\Plutus\honeypot-agent
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy the example env file
copy .env.example .env

# Edit .env and add your Gemini API key
# GEMINI_API_KEY=your_key_here
# API_SECRET_KEY=your_secret_key_here
```

### 3. Run Tests (No API Key Required)

```bash
# Test intelligence extraction
python tests/manual_test.py extractors

# Run all unit tests
pytest tests/test_extractors.py tests/test_agents.py -v
```

### 4. Run Tests (With API Key)

```bash
# Test full agent functionality
python tests/manual_test.py all
```

### 5. Start the Server

```bash
uvicorn api.main:app --reload --port 8000
```

### 6. Test the API

```bash
# Health check
curl http://localhost:8000/health

# Analyze a scam message
curl -X POST http://localhost:8000/analyze ^
  -H "x-api-key: your-api-key" ^
  -H "Content-Type: application/json" ^
  -d "{\"sessionId\": \"test-123\", \"message\": {\"sender\": \"scammer\", \"text\": \"Your account is blocked! Send OTP to +919876543210\", \"timestamp\": \"\"}, \"conversationHistory\": [], \"metadata\": {\"channel\": \"sms\"}}"
```

## 📁 Project Structure

```
honeypot-agent/
├── agents/                      # AI Agent modules
│   ├── detector_agent.py        # Scam classification with Gemini
│   ├── actor_agent.py           # Persona-based response generation
│   ├── investigator_agent.py    # Intelligence extraction
│   ├── session_manager.py       # Conversation state tracking
│   ├── orchestrator.py          # Multi-agent coordinator
│   └── prompts.py               # AI prompt templates
│
├── api/                         # FastAPI server
│   ├── main.py                  # Server and endpoints
│   ├── models.py                # Pydantic models
│   ├── auth.py                  # API key validation
│   └── callback.py              # GUVI callback handler
│
├── intelligence/                # Intelligence extraction
│   ├── extractors.py            # Regex pattern matching
│   ├── validators.py            # Data validation
│   └── scam_database.json       # 50 test messages
│
├── tests/                       # Test suite
│   ├── test_extractors.py       # Extraction tests
│   ├── test_agents.py           # Agent tests
│   ├── test_api.py              # API tests
│   └── manual_test.py           # Quick testing script
│
├── config.py                    # Configuration management
├── requirements.txt             # Dependencies
├── .env.example                 # Environment template
└── README.md                    # This file
```

## 🔧 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `API_SECRET_KEY` | API authentication key | Required |
| `GUVI_CALLBACK_ENABLED` | Enable GUVI callbacks | `false` |
| `MAX_CONVERSATION_TURNS` | Max turns before ending | `20` |
| `MIN_INTELLIGENCE_THRESHOLD` | Intel types to collect | `2` |
| `SCAM_CONFIDENCE_THRESHOLD` | Min confidence for scam | `0.7` |

## 📡 API Endpoints

### `GET /health`
Health check endpoint (no auth required).

### `POST /analyze`
Main scam analysis endpoint.

**Request:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked! Send OTP now.",
    "timestamp": "2026-01-31T10:00:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "sms",
    "language": "en"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "scamDetected": true,
  "agentResponse": "Oh my! What should I do? I'm so worried!",
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": [],
    "phoneNumbers": ["+919876543210"],
    "suspiciousKeywords": ["blocked", "otp", "urgent"]
  },
  "engagementMetrics": {
    "conversationTurn": 1,
    "responseTimeMs": 1542,
    "totalIntelligenceItems": 5
  },
  "continueConversation": true,
  "agentNotes": "Detection: Clear scam indicators..."
}
```

### `GET /session/{session_id}`
Get session details (requires auth).

### `DELETE /session/{session_id}`
End session manually and trigger callback.

## 🎭 Personas

The Actor Agent uses three distinct personas:

1. **Elderly (65+)**: Confused, trusting, uses simple language
2. **Professional (30-50)**: Busy, impatient, wants quick solutions
3. **Novice (18-30)**: Tech-confused, nervous, casual language

## 📊 Intelligence Extraction

Extracts and validates:
- **Bank Accounts**: 9-18 digit numbers with validation
- **UPI IDs**: Known Indian UPI providers
- **Phone Numbers**: Indian format (+91)
- **Phishing Links**: URLs and shortened links
- **Suspicious Keywords**: 50+ scam indicators

## 🧪 Testing

```bash
# Unit tests (no API key needed)
pytest tests/test_extractors.py tests/test_agents.py -v

# API tests
pytest tests/test_api.py -v

# Manual testing
python tests/manual_test.py extractors
python tests/manual_test.py detector  # Needs API key
python tests/manual_test.py all       # Needs API key
```

## 📝 License

MIT License - Built for GUVI x HCL India AI Impact Buildathon
