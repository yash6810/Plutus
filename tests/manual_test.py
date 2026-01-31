"""
Manual testing script for the Honeypot Agent.

This script provides quick tests for:
1. Intelligence extraction
2. Detection agent (requires GEMINI_API_KEY)
3. Actor agent (requires GEMINI_API_KEY)
4. Full orchestrator flow (requires GEMINI_API_KEY)
5. API endpoint testing

Usage:
    python tests/manual_test.py [test_name]
    
    test_name options:
    - extractors: Test intelligence extraction
    - detector: Test scam detection
    - actor: Test response generation
    - orchestrator: Test full flow
    - api: Test API endpoint
    - all: Run all tests (default)
"""

import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


def test_extractors():
    """Test intelligence extraction without API key."""
    print("\n" + "=" * 60)
    print("TEST: Intelligence Extraction")
    print("=" * 60)
    
    from intelligence.extractors import IntelligenceExtractor
    
    extractor = IntelligenceExtractor()
    
    test_messages = [
        "URGENT: Your account is blocked! Pay to fraud@paytm or call +919876543210",
        "Congratulations! You won Rs.25 Lakhs! Claim at http://fake-lottery.com",
        "Your KYC expired. Update at www.bank-kyc.com with account 1234567890123456",
    ]
    
    for i, msg in enumerate(test_messages, 1):
        print(f"\n--- Message {i} ---")
        print(f"Input: {msg[:60]}...")
        result = extractor.extract_all(msg)
        print(f"Bank Accounts: {result['bankAccounts']}")
        print(f"UPI IDs: {result['upiIds']}")
        print(f"Phone Numbers: {result['phoneNumbers']}")
        print(f"Phishing Links: {result['phishingLinks']}")
        print(f"Keywords: {result['suspiciousKeywords'][:5]}...")
        print(f"Total Items: {extractor.get_intelligence_count(result)}")
    
    print("\n✅ Extractor tests passed!")


def test_detector():
    """Test scam detection (requires GEMINI_API_KEY)."""
    print("\n" + "=" * 60)
    print("TEST: Detector Agent")
    print("=" * 60)
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not set. Skipping detector test.")
        return
    
    from agents.detector_agent import DetectorAgent
    
    detector = DetectorAgent(api_key=api_key)
    
    test_messages = [
        ("SCAM", "URGENT: Your bank account is suspended! Send OTP to +919876543210 immediately or account will be closed."),
        ("LEGITIMATE", "Hi, this is a reminder about your dentist appointment tomorrow at 3 PM."),
    ]
    
    for expected, msg in test_messages:
        print(f"\n--- Expected: {expected} ---")
        print(f"Input: {msg[:50]}...")
        result = detector.detect_scam(msg)
        print(f"Is Scam: {result['is_scam']}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Reason: {result['reason'][:80]}...")
        print(f"Indicators: {result['indicators'][:3]}")
    
    print("\n✅ Detector tests completed!")


def test_actor():
    """Test actor response generation (requires GEMINI_API_KEY)."""
    print("\n" + "=" * 60)
    print("TEST: Actor Agent")
    print("=" * 60)
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not set. Skipping actor test.")
        return
    
    from agents.actor_agent import ActorAgent
    
    actor = ActorAgent(api_key=api_key)
    
    scammer_message = "Your account will be blocked in 24 hours! Send Rs.1000 to verify@paytm immediately!"
    
    personas = ["elderly", "professional", "novice"]
    
    for persona in personas:
        print(f"\n--- Persona: {persona} ---")
        response = actor.generate_response(
            message=scammer_message,
            persona=persona,
            history=[]
        )
        print(f"Scammer: {scammer_message[:50]}...")
        print(f"Agent ({persona}): {response}")
    
    print("\n✅ Actor tests completed!")


def test_orchestrator():
    """Test full orchestrator flow (requires GEMINI_API_KEY)."""
    print("\n" + "=" * 60)
    print("TEST: Full Orchestrator Flow")
    print("=" * 60)
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not set. Skipping orchestrator test.")
        return
    
    from agents.orchestrator import create_orchestrator
    
    orchestrator = create_orchestrator(
        api_key=api_key,
        max_turns=5,
        min_intelligence_types=2
    )
    
    session_id = "manual-test-001"
    
    # Simulate conversation
    messages = [
        "URGENT: Your SBI account is blocked! Update KYC at http://sbi-fake.com or call +919876543210",
        "Send Rs.500 to verify@paytm to unblock your account immediately!",
        "Why are you not responding? Your account 1234567890123456 will be closed!",
    ]
    
    history = []
    
    for i, msg_text in enumerate(messages, 1):
        print(f"\n--- Turn {i} ---")
        print(f"Scammer: {msg_text[:60]}...")
        
        message = {
            "sender": "scammer",
            "text": msg_text,
            "timestamp": f"2026-01-31T10:{i:02d}:00Z"
        }
        
        result = orchestrator.process_message(
            session_id=session_id,
            message=message,
            history=history,
            metadata={"channel": "sms", "language": "en"}
        )
        
        print(f"Scam Detected: {result['scamDetected']}")
        print(f"Agent Response: {result['agentResponse']}")
        print(f"Intelligence: {result['extractedIntelligence']}")
        print(f"Continue: {result['continueConversation']}")
        
        # Add to history
        history.append(message)
        if result['agentResponse']:
            history.append({
                "sender": "agent",
                "text": result['agentResponse'],
                "timestamp": f"2026-01-31T10:{i:02d}:30Z"
            })
        
        if not result['continueConversation']:
            print("\n🔔 Conversation ended!")
            break
    
    # Get summary
    summary = orchestrator.get_session_summary(session_id)
    print("\n--- Session Summary ---")
    print(json.dumps(summary, indent=2, default=str))
    
    print("\n✅ Orchestrator test completed!")


def test_api():
    """Test API endpoint (server must be running)."""
    print("\n" + "=" * 60)
    print("TEST: API Endpoint")
    print("=" * 60)
    
    import requests
    
    base_url = "http://localhost:8000"
    api_key = os.environ.get("API_SECRET_KEY", "default-dev-key-change-in-production")
    
    # Test health endpoint
    print("\n--- Health Check ---")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except requests.exceptions.ConnectionError:
        print("❌ Server not running. Start with: uvicorn api.main:app --reload")
        return
    
    # Test analyze endpoint
    print("\n--- Analyze Endpoint ---")
    headers = {"x-api-key": api_key}
    payload = {
        "sessionId": "api-test-001",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked! Pay to fraud@paytm or call +919876543210",
            "timestamp": "2026-01-31T10:00:00Z"
        },
        "conversationHistory": [],
        "metadata": {"channel": "sms", "language": "en"}
    }
    
    response = requests.post(
        f"{base_url}/analyze",
        headers=headers,
        json=payload,
        timeout=30
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"Scam Detected: {result['scamDetected']}")
        print(f"Agent Response: {result['agentResponse']}")
        print(f"Intelligence: {result['extractedIntelligence']}")
    else:
        print(f"Error: {response.json()}")
    
    print("\n✅ API tests completed!")


def main():
    """Run manual tests."""
    print("\n" + "=" * 60)
    print("HONEYPOT AGENT - MANUAL TESTS")
    print("=" * 60)
    
    test_name = sys.argv[1] if len(sys.argv) > 1 else "all"
    
    tests = {
        "extractors": test_extractors,
        "detector": test_detector,
        "actor": test_actor,
        "orchestrator": test_orchestrator,
        "api": test_api,
    }
    
    if test_name == "all":
        for name, test_func in tests.items():
            try:
                test_func()
            except Exception as e:
                print(f"\n❌ Error in {name}: {e}")
    elif test_name in tests:
        tests[test_name]()
    else:
        print(f"Unknown test: {test_name}")
        print(f"Available tests: {', '.join(tests.keys())}, all")
    
    print("\n" + "=" * 60)
    print("TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
