"""
GUVI callback handler for sending final results.

Sends accumulated intelligence to the GUVI evaluation endpoint
when a conversation ends.
"""

import logging
import asyncio
from typing import Dict, Any, Optional

import httpx

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

logger = logging.getLogger(__name__)


class CallbackHandler:
    """
    Handler for sending callbacks to GUVI endpoint.
    
    Implements retry logic with exponential backoff.
    
    Attributes:
        callback_url: GUVI callback endpoint URL
        timeout: Request timeout in seconds
        max_retries: Maximum retry attempts
        enabled: Whether callbacks are enabled
    """
    
    def __init__(
        self,
        callback_url: Optional[str] = None,
        timeout: int = 10,
        max_retries: int = 3,
        enabled: Optional[bool] = None
    ):
        """
        Initialize the callback handler.
        
        Args:
            callback_url: Override callback URL
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            enabled: Override enabled status
        """
        self.callback_url = callback_url or config.GUVI_CALLBACK_URL
        self.timeout = timeout or config.CALLBACK_TIMEOUT
        self.max_retries = max_retries
        self.enabled = enabled if enabled is not None else config.GUVI_CALLBACK_ENABLED
        
        logger.info(
            f"CallbackHandler initialized: enabled={self.enabled}, "
            f"url={self.callback_url[:50]}..."
        )
    
    async def send_final_callback(
        self,
        session_id: str,
        final_data: Dict[str, Any]
    ) -> bool:
        """
        Send final intelligence summary to GUVI.
        
        Args:
            session_id: Session identifier
            final_data: Session summary data
            
        Returns:
            True if successful, False if all retries failed
        """
        if not self.enabled:
            logger.info(f"Callback disabled, skipping for session {session_id}")
            return True  # Return True as "successful" skip
        
        # Build callback payload
        payload = self._build_payload(session_id, final_data)
        
        logger.info(f"Sending callback for session {session_id} to {self.callback_url}")
        
        # Retry with exponential backoff: 2s, 4s, 8s
        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        self.callback_url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code in [200, 201, 202]:
                        logger.info(
                            f"Callback successful for session {session_id}: "
                            f"status={response.status_code}"
                        )
                        return True
                    else:
                        logger.warning(
                            f"Callback returned {response.status_code} for session {session_id}: "
                            f"{response.text[:200]}"
                        )
                        
            except httpx.TimeoutException:
                logger.warning(
                    f"Callback timeout for session {session_id} "
                    f"(attempt {attempt + 1}/{self.max_retries})"
                )
                
            except httpx.RequestError as e:
                logger.error(
                    f"Callback request error for session {session_id} "
                    f"(attempt {attempt + 1}/{self.max_retries}): {str(e)}"
                )
                
            except Exception as e:
                logger.error(
                    f"Unexpected error during callback for session {session_id}: {str(e)}"
                )
            
            # Exponential backoff: 2, 4, 8 seconds
            if attempt < self.max_retries - 1:
                delay = 2 ** (attempt + 1)
                logger.info(f"Retrying callback in {delay} seconds...")
                await asyncio.sleep(delay)
        
        logger.error(
            f"All callback attempts failed for session {session_id}"
        )
        return False
    
    def _build_payload(
        self,
        session_id: str,
        final_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build the callback payload from session data.
        
        Args:
            session_id: Session identifier
            final_data: Session summary data
            
        Returns:
            Callback payload dict
        """
        # Extract intelligence safely
        intel = final_data.get("extractedIntelligence", {})
        
        # Build agent notes summary
        notes_parts = []
        if final_data.get("personaUsed"):
            notes_parts.append(f"Persona: {final_data['personaUsed']}")
        if final_data.get("endReason"):
            notes_parts.append(f"End reason: {final_data['endReason']}")
        if final_data.get("highValueIntelCount", 0) > 0:
            notes_parts.append(
                f"Extracted {final_data['highValueIntelCount']} high-value items"
            )
        
        agent_notes = ". ".join(notes_parts) if notes_parts else "Conversation completed."
        
        return {
            "sessionId": session_id,
            "scamDetected": final_data.get("scamDetected", False),
            "totalMessagesExchanged": final_data.get("totalMessagesExchanged", 0),
            "extractedIntelligence": {
                "bankAccounts": intel.get("bankAccounts", []),
                "upiIds": intel.get("upiIds", []),
                "phishingLinks": intel.get("phishingLinks", []),
                "phoneNumbers": intel.get("phoneNumbers", []),
                "suspiciousKeywords": intel.get("suspiciousKeywords", []),
            },
            "agentNotes": agent_notes,
        }
    
    def is_enabled(self) -> bool:
        """Check if callbacks are enabled."""
        return self.enabled
    
    def enable(self) -> None:
        """Enable callbacks."""
        self.enabled = True
        logger.info("Callbacks enabled")
    
    def disable(self) -> None:
        """Disable callbacks."""
        self.enabled = False
        logger.info("Callbacks disabled")


# Singleton instance
callback_handler = CallbackHandler()


async def trigger_callback(session_id: str, session_summary: Dict[str, Any]) -> bool:
    """
    Convenience function to trigger a callback.
    
    Args:
        session_id: Session identifier
        session_summary: Session summary from orchestrator
        
    Returns:
        True if successful
    """
    return await callback_handler.send_final_callback(session_id, session_summary)
