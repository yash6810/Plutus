"""
FastAPI server for the Honeypot Scam Detection Agent.

Provides REST API endpoints for scam message analysis.
"""

import logging
import sys
import os
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import config
from api.models import IncomingMessage, ApiResponse, HealthResponse, ErrorResponse
from api.auth import verify_api_key
from api.callback import trigger_callback
from agents.orchestrator import create_orchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

# Global orchestrator instance
orchestrator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler for startup and shutdown.
    """
    global orchestrator
    
    # Startup
    logger.info("=" * 50)
    logger.info("Honeypot Scam Detection Agent Starting...")
    logger.info("=" * 50)
    
    try:
        # Validate configuration
        config.validate()
        
        # Initialize orchestrator
        orchestrator = create_orchestrator(
            api_key=config.GEMINI_API_KEY,
            model_name=config.AI_MODEL_NAME,
            max_turns=config.MAX_CONVERSATION_TURNS,
            min_intelligence_types=config.MIN_INTELLIGENCE_THRESHOLD,
            stale_threshold=config.STALE_CONVERSATION_THRESHOLD,
            scam_confidence_threshold=config.SCAM_CONFIDENCE_THRESHOLD
        )
        
        logger.info("Orchestrator initialized successfully")
        logger.info(f"Configuration: {config.get_summary()}")
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        logger.error("Please set GEMINI_API_KEY in your .env file")
        # Continue without orchestrator for health checks
    
    logger.info("Server ready to accept requests")
    logger.info("=" * 50)
    
    yield
    
    # Shutdown
    logger.info("Shutting down Honeypot Agent...")


# Create FastAPI application
app = FastAPI(
    title="Plutus - Scam Detection Agent",
    description="AI-powered system that detects scam messages, engages scammers, and extracts intelligence",
    version="1.0.0",
    lifespan=lifespan,
)

# Add CORS middleware for React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "error": exc.detail,
            "detail": None
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "Internal server error",
            "detail": str(exc) if config.API_SECRET_KEY == "default-dev-key-change-in-production" else None
        }
    )


# =============================================================================
# Endpoints
# =============================================================================

@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - returns basic info."""
    return HealthResponse(
        status="ok",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )


@app.post("/", response_model=ApiResponse)
async def root_analyze(
    data: IncomingMessage,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Root POST endpoint - redirects to /analyze for GUVI tester compatibility.
    
    The official GUVI evaluation tester may POST to the root URL.
    This endpoint provides the same functionality as /analyze.
    """
    # Forward to the analyze endpoint logic
    return await analyze_scam_message(data, background_tasks, x_api_key)


@app.get("/tester")
async def serve_tester():
    """Serve the Honeypot API Endpoint Tester page."""
    tester_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tester.html")
    return FileResponse(tester_path, media_type="text/html")


@app.get("/dashboard")
async def serve_dashboard():
    """Serve the Plutus Dashboard page."""
    dashboard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard.html")
    return FileResponse(dashboard_path, media_type="text/html")


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns server status and configuration summary.
    No authentication required.
    """
    return HealthResponse(
        status="ok",
        timestamp=datetime.now().isoformat(),
        version="1.0.0",
        config_summary={
            "orchestrator_ready": orchestrator is not None,
            "gemini_api_key_set": bool(config.GEMINI_API_KEY),
            "callback_enabled": config.GUVI_CALLBACK_ENABLED,
        }
    )


@app.post("/analyze", response_model=ApiResponse)
async def analyze_scam_message(
    data: IncomingMessage,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Analyze a scam message and generate a response.
    
    This is the main endpoint that:
    1. Validates the API key
    2. Detects if the message is a scam
    3. Generates a persona-based response
    4. Extracts intelligence
    5. Tracks conversation state
    6. Triggers callback when conversation ends
    
    Args:
        data: Incoming message data
        background_tasks: FastAPI background task manager
        x_api_key: API key for authentication
        
    Returns:
        ApiResponse with analysis results
    """
    # Validate API key
    await verify_api_key(x_api_key)
    
    # Check orchestrator is ready
    if orchestrator is None:
        raise HTTPException(
            status_code=503,
            detail="Service unavailable. Check GEMINI_API_KEY configuration."
        )
    
    # Log incoming request
    logger.info(f"Analyze request: session={data.sessionId}, message_len={len(data.message.get('text', ''))}")
    
    try:
        # Process message through orchestrator
        result = orchestrator.process_message(
            session_id=data.sessionId,
            message=data.message,
            history=data.conversationHistory,
            metadata=data.metadata
        )
        
        # If conversation ended, trigger callback in background
        if not result.get("continueConversation", True):
            session_summary = orchestrator.get_session_summary(data.sessionId)
            background_tasks.add_task(
                trigger_callback,
                data.sessionId,
                session_summary
            )
            logger.info(f"Conversation ended for session {data.sessionId}, callback scheduled")
        
        # Return response
        return ApiResponse(
            status=result.get("status", "success"),
            scamDetected=result.get("scamDetected", False),
            agentResponse=result.get("agentResponse", ""),
            extractedIntelligence=result.get("extractedIntelligence", {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }),
            engagementMetrics=result.get("engagementMetrics", {
                "conversationTurn": 0,
                "responseTimeMs": 0,
                "totalIntelligenceItems": 0
            }),
            continueConversation=result.get("continueConversation", True),
            agentNotes=result.get("agentNotes", "")
        )
        
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error processing message: {str(e)}"
        )


@app.get("/session/{session_id}")
async def get_session(
    session_id: str,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Get session summary (for debugging/monitoring).
    
    Args:
        session_id: Session identifier
        x_api_key: API key for authentication
        
    Returns:
        Session summary dict
    """
    await verify_api_key(x_api_key)
    
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="Service unavailable")
    
    summary = orchestrator.get_session_summary(session_id)
    
    if "error" in summary:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return summary


@app.delete("/session/{session_id}")
async def end_session(
    session_id: str,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="x-api-key")
):
    """
    Manually end a session and trigger callback.
    
    Args:
        session_id: Session identifier
        x_api_key: API key for authentication
        
    Returns:
        Session summary
    """
    await verify_api_key(x_api_key)
    
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="Service unavailable")
    
    # End the session
    ended = orchestrator.end_session_manually(session_id, "manual_end")
    
    if not ended:
        raise HTTPException(status_code=404, detail="Session not found or already ended")
    
    # Get summary and trigger callback
    summary = orchestrator.get_session_summary(session_id)
    background_tasks.add_task(trigger_callback, session_id, summary)
    
    return {
        "status": "success",
        "message": f"Session {session_id} ended",
        "summary": summary
    }


# =============================================================================
# Honeypot Tester Endpoint
# =============================================================================

class HoneypotTestRequest(BaseModel):
    """Request model for honeypot testing."""
    url: str
    api_key: str


@app.post("/api/test-honeypot")
async def test_honeypot_endpoint(data: HoneypotTestRequest):
    """
    Test an external honeypot API endpoint.
    
    This endpoint proxies a test request to validate:
    - API authentication
    - Endpoint availability
    - Response structure
    - Basic honeypot behavior
    """
    import httpx
    import time
    
    results = {
        "url": data.url,
        "timestamp": datetime.now().isoformat(),
        "tests": {
            "connectivity": {"passed": False, "message": ""},
            "authentication": {"passed": False, "message": ""},
            "response_structure": {"passed": False, "message": ""},
            "honeypot_behavior": {"passed": False, "message": ""}
        },
        "response_time_ms": 0,
        "raw_response": None,
        "overall_status": "failed"
    }
    
    # Sample test message
    test_payload = {
        "sessionId": f"tester-{int(time.time())}",
        "message": {
            "sender": "scammer",
            "text": "URGENT: Your bank account has been compromised! Send OTP now to verify.",
            "timestamp": datetime.now().isoformat()
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "sms",
            "language": "en",
            "locale": "en-IN"
        }
    }
    
    try:
        start_time = time.time()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Test the /analyze endpoint
            analyze_url = data.url.rstrip('/') + '/analyze'
            
            response = await client.post(
                analyze_url,
                json=test_payload,
                headers={"x-api-key": data.api_key, "Content-Type": "application/json"}
            )
            
            end_time = time.time()
            results["response_time_ms"] = int((end_time - start_time) * 1000)
            
            # Test 1: Connectivity
            results["tests"]["connectivity"]["passed"] = True
            results["tests"]["connectivity"]["message"] = f"Successfully connected (HTTP {response.status_code})"
            
            # Test 2: Authentication
            if response.status_code == 401 or response.status_code == 403:
                results["tests"]["authentication"]["passed"] = False
                results["tests"]["authentication"]["message"] = "Authentication failed - check your API key"
            elif response.status_code >= 200 and response.status_code < 300:
                results["tests"]["authentication"]["passed"] = True
                results["tests"]["authentication"]["message"] = "API key accepted"
            else:
                results["tests"]["authentication"]["passed"] = False
                results["tests"]["authentication"]["message"] = f"Unexpected status code: {response.status_code}"
            
            # Parse response
            try:
                response_data = response.json()
                results["raw_response"] = response_data
                
                # Test 3: Response Structure
                required_fields = ["status", "scamDetected", "agentResponse", "extractedIntelligence", "continueConversation"]
                missing_fields = [f for f in required_fields if f not in response_data]
                
                if not missing_fields:
                    results["tests"]["response_structure"]["passed"] = True
                    results["tests"]["response_structure"]["message"] = "Response contains all required fields"
                else:
                    results["tests"]["response_structure"]["passed"] = False
                    results["tests"]["response_structure"]["message"] = f"Missing fields: {', '.join(missing_fields)}"
                
                # Test 4: Honeypot Behavior
                if response_data.get("scamDetected") == True and response_data.get("agentResponse"):
                    results["tests"]["honeypot_behavior"]["passed"] = True
                    results["tests"]["honeypot_behavior"]["message"] = "Scam detected and response generated"
                elif response_data.get("status") == "success":
                    results["tests"]["honeypot_behavior"]["passed"] = True
                    results["tests"]["honeypot_behavior"]["message"] = "Honeypot responded successfully"
                else:
                    results["tests"]["honeypot_behavior"]["passed"] = False
                    results["tests"]["honeypot_behavior"]["message"] = "Unexpected honeypot behavior"
                    
            except Exception as json_err:
                results["tests"]["response_structure"]["message"] = f"Failed to parse JSON: {str(json_err)}"
                results["raw_response"] = response.text[:500]
        
        # Calculate overall status
        passed_tests = sum(1 for t in results["tests"].values() if t["passed"])
        if passed_tests == 4:
            results["overall_status"] = "passed"
        elif passed_tests >= 2:
            results["overall_status"] = "partial"
        else:
            results["overall_status"] = "failed"
            
    except httpx.ConnectError:
        results["tests"]["connectivity"]["message"] = "Failed to connect - check URL and server status"
    except httpx.TimeoutException:
        results["tests"]["connectivity"]["message"] = "Connection timed out (30s limit)"
    except Exception as e:
        results["tests"]["connectivity"]["message"] = f"Error: {str(e)}"
    
    return results


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
