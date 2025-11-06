# 🤖 LLM Summary Setup Guide

## Overview
AI Agent dapat menghasilkan ringkasan otomatis dan rekomendasi prioritas menggunakan Large Language Model (LLM). Saat ini mendukung:
- **Google Gemini** (Recommended - Free tier available)
- **OpenAI GPT** (Requires paid API key)

## Quick Setup

### Option 1: Google Gemini (Recommended)

1. **Dapatkan API Key Gratis**
   - Kunjungi: https://aistudio.google.com/app/apikey
   - Login dengan Google Account
   - Klik "Create API Key"
   - Copy API key yang dihasilkan

2. **Set Environment Variable**
   
   **PowerShell (Session):**
   ```powershell
   $env:GEMINI_API_KEY = "YOUR_API_KEY_HERE"
   ```

   **PowerShell (Permanent - User):**
   ```powershell
   [System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', 'YOUR_API_KEY_HERE', 'User')
   ```

   **PowerShell (Permanent - Machine/Admin):**
   ```powershell
   [System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', 'YOUR_API_KEY_HERE', 'Machine')
   ```

3. **Verify Setup**
   ```powershell
   # Check if key is set
   echo $env:GEMINI_API_KEY
   
   # Should show your key (or first few characters)
   ```

### Option 2: OpenAI

1. **Dapatkan API Key** (Paid)
   - Kunjungi: https://platform.openai.com/api-keys
   - Create new API key
   - Add credit/payment method

2. **Set Environment Variable**
   ```powershell
   $env:OPENAI_API_KEY = "sk-YOUR_API_KEY_HERE"
   ```

## Usage

Setelah API key diset, jalankan agent seperti biasa:

```powershell
# Load CLI
. .\QUICK_SETUP.ps1

# Run agent
byebac /runagent

# Check status - akan menampilkan LLM summary
byebac /status

# Open report - akan ada section AI Summary
byebac /report
```

## LLM Summary Output Example

```markdown
================================================================================
🤖 AI SECURITY ASSESSMENT SUMMARY
================================================================================

📊 EXECUTIVE SUMMARY
• Tested: 96 requests across 2 roles (Admin_HC, Employee)
• Vulnerabilities Found: 6 potential issues
• Accuracy: 88.9% | Precision: 75% | Recall: 60%
• Detection Time: 263.65 seconds

⚠️ CRITICAL FINDINGS
1. BOLA (Broken Object Level Authorization) - Employee accessing Admin resources
   → GET /roles, /permissions, /users
   → Priority: HIGH - Immediate fix required

2. IDOR (Insecure Direct Object Reference) - Cross-user data access
   → GET /employee/attachments/{item_id}/*
   → Priority: MEDIUM - Review access controls

🔧 RECOMMENDED ACTIONS (Priority Order)
1. [URGENT] Implement role-based access control for /roles, /permissions, /users
2. [HIGH] Add user-scoped authorization checks for attachment endpoints
3. [MEDIUM] Review and strengthen RBAC policy enforcement
4. [LOW] Monitor and log all cross-role access attempts

📋 DETAILED METRICS
• True Positives: 9 (correctly blocked unauthorized requests)
• False Positives: 3 (incorrectly blocked authorized requests)
• False Negatives: 6 (missed vulnerabilities)
• True Negatives: 63 (correctly allowed authorized requests)
================================================================================
```

## Troubleshooting

### "LLM summary unavailable (provider not configured)"
- ✅ Check: `echo $env:GEMINI_API_KEY` or `echo $env:OPENAI_API_KEY`
- ❌ Empty? Set the environment variable (see steps above)
- 🔄 Restart PowerShell after setting permanent env vars

### "API quota exceeded"
**Gemini (Free Tier):**
- Limit: 60 requests/minute
- Solution: Wait 1 minute or upgrade to paid tier

**OpenAI:**
- Check billing: https://platform.openai.com/usage
- Add credits if needed

### "Invalid API key"
- Verify key is correct (copy-paste carefully)
- Check for extra spaces/quotes
- Gemini: Regenerate at https://aistudio.google.com/app/apikey
- OpenAI: Create new key at https://platform.openai.com/api-keys

## Configuration

LLM settings in `ai_agent/config/agent.yaml`:

```yaml
llm:
  triage_enabled: true          # Enable LLM summary generation
  followups_enabled: true       # LLM suggests follow-up tests
  redact_enabled: true          # Redact sensitive data before sending to LLM
  redact_max_chars: 1000        # Max chars sent to LLM per snippet
```

## Privacy & Security

✅ **Safe to use:**
- Agent redacts sensitive data before sending to LLM
- Only test metadata and sanitized results are shared
- No credentials, tokens, or PII sent to LLM

🔒 **Data sent to LLM:**
- Test endpoints (paths/methods)
- HTTP status codes
- Confusion matrix metrics
- Sanitized vulnerability descriptions

❌ **Never sent:**
- Passwords
- API tokens
- User credentials
- Request/response bodies with sensitive data

## Cost Estimation

### Google Gemini (Free Tier)
- **Cost:** FREE up to 60 requests/min
- **Typical usage:** 1 summary per test run = ~$0.00
- **Upgrade:** Only if > 60 req/min needed

### OpenAI GPT-4
- **Cost:** ~$0.01-0.03 per summary (varies by token count)
- **Monthly:** If running 100 tests/month = ~$1-3
- **Recommended model:** gpt-4o-mini (cheaper, still good quality)

## Advanced: Provider Selection

Edit `ai_agent/config/agent.yaml`:

```yaml
llm:
  provider: "google_genai"  # or "openai"
```

Or set environment variable:
```powershell
$env:LLM_PROVIDER = "google_genai"  # or "openai"
```

Priority (if both keys set):
1. Check LLM_PROVIDER env var
2. Use `google_genai` if GEMINI_API_KEY exists
3. Use `openai` if OPENAI_API_KEY exists
4. Fallback: Show "unavailable" message

---

## Quick Start (TL;DR)

```powershell
# 1. Get Gemini API key (free): https://aistudio.google.com/app/apikey
# 2. Set it:
$env:GEMINI_API_KEY = "YOUR_KEY_HERE"

# 3. Run agent:
. .\QUICK_SETUP.ps1
byebac /runagent

# 4. View summary:
byebac /status
```

Done! 🎉
