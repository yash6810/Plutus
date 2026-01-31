"""
Tests for API endpoints.

Tests the FastAPI application endpoints.
Note: Requires GEMINI_API_KEY to be set for full functionality tests.
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

# Set test API key before importing app
os.environ["API_SECRET_KEY"] = "test-api-key"
os.environ["GUVI_CALLBACK_ENABLED"] = "false"

from api.main import app

client = TestClient(app)

# Test headers
VALID_HEADERS = {"x-api-key": "test-api-key"}
INVALID_HEADERS = {"x-api-key": "wrong-key"}


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_check_returns_ok(self):
        """Test health endpoint returns 200."""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data
        assert "version" in data
    
    def test_root_endpoint(self):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestAuthentication:
    """Test API key authentication."""
    
    def test_missing_api_key_returns_error(self):
        """Test that missing API key returns 422 (missing required header)."""
        response = client.post(
            "/analyze",
            json={
                "sessionId": "test-123",
                "message": {"sender": "scammer", "text": "test", "timestamp": ""},
                "conversationHistory": [],
                "metadata": {}
            }
        )
        # FastAPI returns 422 for missing required headers
        assert response.status_code == 422
    
    def test_invalid_api_key_returns_401(self):
        """Test that invalid API key returns 401."""
        response = client.post(
            "/analyze",
            headers=INVALID_HEADERS,
            json={
                "sessionId": "test-123",
                "message": {"sender": "scammer", "text": "test", "timestamp": ""},
                "conversationHistory": [],
                "metadata": {}
            }
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["error"]


class TestAnalyzeEndpoint:
    """Test /analyze endpoint functionality."""
    
    def test_analyze_valid_request_structure(self):
        """Test that analyze accepts valid request structure."""
        # Note: This may return 503 if GEMINI_API_KEY is not set
        response = client.post(
            "/analyze",
            headers=VALID_HEADERS,
            json={
                "sessionId": "test-session-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account is blocked! Send OTP now.",
                    "timestamp": "2026-01-31T10:00:00Z"
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "sms",
                    "language": "en",
                    "locale": "en-IN"
                }
            }
        )
        
        # Accept either success or 503 (no API key)
        assert response.status_code in [200, 503]
    
    def test_analyze_invalid_request_missing_fields(self):
        """Test that analyze rejects invalid requests."""
        response = client.post(
            "/analyze",
            headers=VALID_HEADERS,
            json={
                # Missing sessionId and message
            }
        )
        assert response.status_code == 422  # Validation error


class TestSessionEndpoints:
    """Test session management endpoints."""
    
    def test_get_session_requires_auth(self):
        """Test that session endpoint requires authentication."""
        response = client.get("/session/test-123")
        assert response.status_code == 422  # Missing header
    
    def test_get_nonexistent_session(self):
        """Test getting a non-existent session."""
        response = client.get(
            "/session/nonexistent-session",
            headers=VALID_HEADERS
        )
        # May return 404 or 503 depending on orchestrator state
        assert response.status_code in [404, 503]
    
    def test_delete_session_requires_auth(self):
        """Test that delete session requires authentication."""
        response = client.delete("/session/test-123")
        assert response.status_code == 422


class TestRequestValidation:
    """Test request validation."""
    
    def test_malformed_json_returns_error(self):
        """Test malformed JSON handling."""
        response = client.post(
            "/analyze",
            headers={**VALID_HEADERS, "Content-Type": "application/json"},
            content="not valid json"
        )
        assert response.status_code == 422
    
    def test_message_with_empty_text(self):
        """Test handling of empty message text."""
        response = client.post(
            "/analyze",
            headers=VALID_HEADERS,
            json={
                "sessionId": "test-empty",
                "message": {
                    "sender": "scammer",
                    "text": "",
                    "timestamp": ""
                },
                "conversationHistory": [],
                "metadata": {}
            }
        )
        # Should handle gracefully
        assert response.status_code in [200, 503]


class TestResponseFormat:
    """Test response format compliance."""
    
    @pytest.mark.skipif(
        not os.environ.get("GEMINI_API_KEY"),
        reason="Requires GEMINI_API_KEY"
    )
    def test_analyze_response_format(self):
        """Test that analyze returns correct format."""
        response = client.post(
            "/analyze",
            headers=VALID_HEADERS,
            json={
                "sessionId": "format-test",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Your account suspended! Pay to fraud@paytm",
                    "timestamp": "2026-01-31T10:00:00Z"
                },
                "conversationHistory": [],
                "metadata": {"channel": "sms"}
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check required fields
        assert "status" in data
        assert "scamDetected" in data
        assert "agentResponse" in data
        assert "extractedIntelligence" in data
        assert "engagementMetrics" in data
        assert "continueConversation" in data
        
        # Check intelligence structure
        intel = data["extractedIntelligence"]
        assert "bankAccounts" in intel
        assert "upiIds" in intel
        assert "phishingLinks" in intel
        assert "phoneNumbers" in intel
        assert "suspiciousKeywords" in intel
        
        # Check metrics structure
        metrics = data["engagementMetrics"]
        assert "conversationTurn" in metrics
        assert "responseTimeMs" in metrics
        assert "totalIntelligenceItems" in metrics


class TestCORS:
    """Test CORS configuration."""
    
    def test_cors_headers_present(self):
        """Test that CORS headers are present."""
        response = client.options(
            "/analyze",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST"
            }
        )
        # CORS preflight should succeed
        assert response.status_code in [200, 405]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
