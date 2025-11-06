# 🔒 Security Artifact Masking

## Overview

BYE BAC automatically masks sensitive information in all saved artifacts to prevent credential leakage and ensure secure sharing/committing to version control.

## Protected Fields

### Automatically Masked Keywords

The system identifies and masks fields containing these keywords (case-insensitive):

**Credentials & Passwords:**

- `password`
- `passwd`
- `pwd`

**Tokens & Secrets:**

- `access_token`
- `refresh_token`
- `token`
- `bearer`
- `jwt`
- `api_key`
- `apikey`
- `secret`
- `client_secret`
- `auth_token`
- `private_key`
- `session_id`
- `authorization`

## Masking Strategy

### Short Values (≤8 characters)

Completely masked:

```json
{
  "password": "***masked***"
}
```

### Long Values (>8 characters)

First 4 and last 4 characters preserved for debugging:

```json
{
  "access_token": "eyJh...3kJ0",
  "password": "G3l4...r3@?"
}
```

### Headers

Authorization headers use partial masking (first 6 + last 4):

```json
{
  "Authorization": "Bearer eyJhbG...kJ0Q"
}
```

## Examples

### Before Masking (RAW REQUEST)

```json
{
  "request": {
    "method": "POST",
    "url": "/api/auth/login",
    "json": {
      "email": "danny.prasetya@sigma.co.id",
      "password": "G3l45C!sS3cur3@?"
    }
  },
  "response": {
    "status_code": 200,
    "body": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjo...",
      "refresh_token": "def50200a1b2c3d4e5f6..."
    }
  }
}
```

### After Masking (SAVED ARTIFACT)

```json
{
  "request": {
    "method": "POST",
    "url": "/api/auth/login",
    "json": {
      "email": "danny.prasetya@sigma.co.id",
      "password": "G3l4...r3@?"
    }
  },
  "response": {
    "status_code": 200,
    "body": {
      "token": "eyJh...kJ0Q",
      "refresh_token": "def5...c3d4"
    }
  }
}
```

## Security Benefits

### ✅ Safe for Version Control

Artifacts can be committed to Git without exposing:

- User passwords
- API keys
- JWT tokens
- OAuth secrets

### ✅ Academic Submission Ready

Share test results with advisors/professors without security risks:

```bash
# Safe to commit
git add ai_agent/runs/artifacts/
git commit -m "Add security test artifacts"
git push origin thesis-submission
```

### ✅ Team Collaboration

Multiple developers can review artifacts without credential leakage:

- Code reviews
- Pull requests
- Documentation
- Thesis appendices

### ✅ Compliance

Meets security best practices:

- OWASP Sensitive Data Exposure prevention
- PCI DSS requirement 3.4 (mask PAN)
- GDPR data minimization principle

## Implementation

### Recursive Masking

The `_mask_sensitive_data()` method recursively traverses:

- **Dictionaries:** Checks each key for sensitive keywords
- **Lists:** Masks items within arrays
- **Nested Objects:** Handles complex JSON structures

### Preserved Context

Non-sensitive fields remain intact for debugging:

- HTTP methods (GET, POST, etc.)
- URLs and endpoints
- Status codes
- Non-sensitive parameters
- Email addresses (useful for role identification)

## Testing Masking

Run a test and check artifacts:

```bash
# Run security tests
byebac
/runagent

# Check masked artifacts
cd ai_agent/runs/artifacts/auth_admin_hc/AUTH/
cat 1762098955208_POST_auth_login.json

# Should see:
# "password": "G3l4...r3@?"  ✅ MASKED
# "token": "eyJh...3kJ0"     ✅ MASKED
```

## Backward Compatibility

### Existing Artifacts

Old artifacts with plaintext passwords remain untouched. To re-mask:

1. Clean old artifacts: `byebac` → `/clean`
2. Re-run tests to generate masked artifacts

### Configuration

No configuration needed - masking is automatic and always-on.

## Security Notes

### ⚠️ In-Memory Data

Sensitive data is **NOT masked in memory** during test execution - only when saving to disk. This ensures:

- Correct test logic (can validate actual tokens)
- Accurate response parsing
- Proper authentication flows

### ⚠️ Log Files

Console output and log files may still contain sensitive data. Avoid sharing:

- Terminal screenshots with full responses
- Debug logs with `-vv` verbosity
- Error traces showing full JSON payloads

### ✅ Best Practice

For maximum security when sharing results:

1. Share only the Markdown report (`BAC_Security_Test_Report-*.md`)
2. If sharing artifacts, use the masked JSON files
3. Never share raw `auth.yaml` or credentials

## Code Reference

**Implementation:** `ai_agent/core/tools_http.py`

- Line 124-178: `_mask_sensitive_data()` method
- Line 217-220: Applied before artifact saving
- Line 68-87: Header masking `_mask_headers_for_artifact()`

---

**Last Updated:** 2025-01-08  
**Version:** 1.0.0  
**Security Level:** Production-Ready 🔒
