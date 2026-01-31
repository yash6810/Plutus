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
from fastapi.responses import JSONResponse

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
