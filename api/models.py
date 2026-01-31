"""
Pydantic models for API request/response validation.

Defines the schema for:
- Incoming messages from GUVI
- API responses
- Intelligence structures
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


class MessageContent(BaseModel):
    """Structure of an individual message."""
    
    sender: str = Field(..., description="Message sender identifier")
    text: str = Field(..., description="Message text content")
    timestamp: Optional[str] = Field(None, description="ISO8601 timestamp")


class MessageMetadata(BaseModel):
    """Metadata about the message context."""
    
    channel: str = Field("sms", description="Communication channel (sms, whatsapp, email)")
    language: str = Field("en", description="Message language code")
    locale: str = Field("en-IN", description="Locale identifier")


class IncomingMessage(BaseModel):
    """
    Request model for the /analyze endpoint.
    
    Matches the expected format from GUVI evaluation system.
    """
    
    sessionId: str = Field(..., description="Unique session identifier")
    message: Dict[str, Any] = Field(..., description="Message object with sender, text, timestamp")
    conversationHistory: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of previous messages in the conversation"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Channel, language, and locale information"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc-123-xyz",
                "message": {
                    "sender": "scammer",
                    "text": "Your account has been blocked. Send OTP to verify.",
                    "timestamp": "2026-01-31T10:00:00Z"
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "sms",
                    "language": "en",
                    "locale": "en-IN"
                }
            }
        }


class ExtractedIntelligence(BaseModel):
    """Structure for extracted intelligence data."""
    
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class EngagementMetrics(BaseModel):
    """Metrics about the conversation engagement."""
    
    conversationTurn: int = Field(..., description="Current turn number")
    responseTimeMs: int = Field(..., description="Response time in milliseconds")
    totalIntelligenceItems: int = Field(..., description="Total intelligence items extracted")


class ApiResponse(BaseModel):
    """
    Response model for the /analyze endpoint.
    
    Matches the expected format for GUVI evaluation system.
    """
    
    status: str = Field(..., description="Response status (success/error)")
    scamDetected: bool = Field(..., description="Whether scam was detected")
    agentResponse: str = Field(..., description="Generated response to send to scammer")
    extractedIntelligence: ExtractedIntelligence = Field(
        ..., 
        description="Intelligence extracted from the message"
    )
    engagementMetrics: EngagementMetrics = Field(
        ...,
        description="Conversation metrics"
    )
    continueConversation: bool = Field(
        ...,
        description="Whether to continue the conversation"
    )
    agentNotes: str = Field(
        default="",
        description="Internal notes about the analysis"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "scamDetected": True,
                "agentResponse": "Oh my! What should I do? I'm so worried!",
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": ["scammer@paytm"],
                    "phishingLinks": ["http://fake-bank.com"],
                    "phoneNumbers": ["+919876543210"],
                    "suspiciousKeywords": ["urgent", "verify", "blocked"]
                },
                "engagementMetrics": {
                    "conversationTurn": 1,
                    "responseTimeMs": 1842,
                    "totalIntelligenceItems": 5
                },
                "continueConversation": True,
                "agentNotes": "Scam detected with high confidence. Using elderly persona."
            }
        }


class ErrorResponse(BaseModel):
    """Error response model."""
    
    status: str = Field(default="error")
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")


class HealthResponse(BaseModel):
    """Health check response model."""
    
    status: str = Field(default="ok")
    timestamp: str = Field(..., description="Current server timestamp")
    version: str = Field(default="1.0.0")
    config_summary: Optional[Dict[str, Any]] = Field(
        None,
        description="Configuration summary (optional)"
    )


class CallbackPayload(BaseModel):
    """
    Payload for the GUVI callback endpoint.
    
    Sent when a conversation ends.
    """
    
    sessionId: str = Field(..., description="Session identifier")
    scamDetected: bool = Field(..., description="Whether scam was detected")
    totalMessagesExchanged: int = Field(..., description="Total conversation turns")
    extractedIntelligence: ExtractedIntelligence = Field(
        ...,
        description="All extracted intelligence"
    )
    agentNotes: str = Field(
        default="",
        description="Summary notes about the engagement"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc-123-xyz",
                "scamDetected": True,
                "totalMessagesExchanged": 12,
                "extractedIntelligence": {
                    "bankAccounts": ["1234567890123456"],
                    "upiIds": ["scammer@paytm", "fraud@ybl"],
                    "phishingLinks": ["http://fake-bank.com"],
                    "phoneNumbers": ["+919876543210"],
                    "suspiciousKeywords": ["urgent", "verify", "OTP"]
                },
                "agentNotes": "Successfully extracted 2 UPI IDs and 1 phone number through 12-turn engagement."
            }
        }
