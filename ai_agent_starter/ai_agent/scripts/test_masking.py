"""
Test script untuk memverifikasi password masking
"""
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ai_agent.core.tools_http import HTTPTools

def test_masking():
    print("🧪 Testing Password Masking Functionality\n")
    print("="*60)
    
    # Initialize HTTPTools
    http_tool = HTTPTools(
        base_url="http://localhost:3000",
        token_header="Authorization",
        token_prefix="Bearer"
    )
    
    # Test case 1: Simple password
    print("\n📝 Test 1: Simple Password Field")
    test_data_1 = {
        "email": "danny.prasetya@sigma.co.id",
        "password": "G3l45C!sS3cur3@?"
    }
    masked_1 = http_tool._mask_sensitive_data(test_data_1)
    print(f"Original: {json.dumps(test_data_1, indent=2)}")
    print(f"Masked:   {json.dumps(masked_1, indent=2)}")
    assert masked_1["password"] == "G3l4...r3@?", "❌ Password not masked correctly!"
    assert masked_1["email"] == "danny.prasetya@sigma.co.id", "❌ Email should not be masked!"
    print("✅ PASSED: Password masked, email preserved")
    
    # Test case 2: JWT tokens
    print("\n📝 Test 2: JWT Access/Refresh Tokens")
    test_data_2 = {
        "status_code": 200,
        "body": {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwfQ.abcdef123456",
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "refresh_token": "def50200a1b2c3d4e5f6789012345678901234567890",
            "user": {
                "id": 1,
                "name": "Danny Prasetya"
            }
        }
    }
    masked_2 = http_tool._mask_sensitive_data(test_data_2)
    print(f"Masked Response: {json.dumps(masked_2, indent=2)}")
    assert masked_2["body"]["token"].startswith("eyJh"), "❌ Token should preserve first 4 chars!"
    assert masked_2["body"]["token"].endswith("3456"), "❌ Token should preserve last 4 chars!"
    assert "..." in masked_2["body"]["token"], "❌ Token should contain ellipsis!"
    assert masked_2["body"]["user"]["name"] == "Danny Prasetya", "❌ User name should not be masked!"
    print("✅ PASSED: Tokens masked, other fields preserved")
    
    # Test case 3: Nested objects with API keys
    print("\n📝 Test 3: Nested Objects with API Keys")
    test_data_3 = {
        "config": {
            "api_key": "sk_live_51234567890abcdefghijklmnop",
            "client_secret": "cs_test_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            "webhook_url": "https://example.com/webhook"
        },
        "metadata": {
            "region": "us-east-1"
        }
    }
    masked_3 = http_tool._mask_sensitive_data(test_data_3)
    print(f"Masked Config: {json.dumps(masked_3, indent=2)}")
    assert masked_3["config"]["api_key"] == "sk_l...mnop", "❌ API key not masked correctly!"
    assert masked_3["config"]["client_secret"].startswith("cs_t"), "❌ Client secret should preserve first 4!"
    assert masked_3["config"]["webhook_url"] == "https://example.com/webhook", "❌ URL should not be masked!"
    print("✅ PASSED: API keys masked, URLs preserved")
    
    # Test case 4: Array of credentials
    print("\n📝 Test 4: Array of Credentials")
    test_data_4 = {
        "users": [
            {"username": "admin", "password": "Admin123!@#"},
            {"username": "user1", "password": "User1Pass!"},
            {"username": "user2", "password": "short"}
        ]
    }
    masked_4 = http_tool._mask_sensitive_data(test_data_4)
    print(f"Masked Users: {json.dumps(masked_4, indent=2)}")
    assert masked_4["users"][0]["password"] == "Admi...3!@#", "❌ First password not masked!"
    assert masked_4["users"][1]["password"] == "User...ass!", "❌ Second password not masked!"
    assert masked_4["users"][2]["password"] == "***masked***", "❌ Short password should be fully masked!"
    print("✅ PASSED: All passwords in array masked correctly")
    
    # Test case 5: Case insensitivity
    print("\n📝 Test 5: Case-Insensitive Field Detection")
    test_data_5 = {
        "PASSWORD": "UpperCase123!",
        "Access_Token": "mixed_case_token_12345678",
        "api_KEY": "camelCase_key_abcdefgh"
    }
    masked_5 = http_tool._mask_sensitive_data(test_data_5)
    print(f"Masked Mixed Case: {json.dumps(masked_5, indent=2)}")
    assert "..." in str(masked_5["PASSWORD"]), "❌ Uppercase PASSWORD not detected!"
    assert "..." in str(masked_5["Access_Token"]), "❌ Mixed case Access_Token not detected!"
    assert "..." in str(masked_5["api_KEY"]), "❌ Mixed case api_KEY not detected!"
    print("✅ PASSED: Case-insensitive detection works")
    
    print("\n" + "="*60)
    print("🎉 ALL TESTS PASSED!")
    print("\n📊 Summary:")
    print("  ✅ Password masking: Working")
    print("  ✅ Token masking: Working")
    print("  ✅ API key masking: Working")
    print("  ✅ Nested object handling: Working")
    print("  ✅ Array handling: Working")
    print("  ✅ Case-insensitive detection: Working")
    print("\n🔒 Artifacts are safe to commit to Git!")

if __name__ == "__main__":
    try:
        test_masking()
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
