<div align="center">

# BYE BAC - AI-Powered Broken Access Control Detection Agent

<pre>
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗   ██╗███████╗    ██████╗  █████╗  ██████╗      ║
║   ██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗██╔════╝      ║
║   ██████╔╝ ╚████╔╝ █████╗      ██████╔╝███████║██║           ║
║   ██╔══██╗  ╚██╔╝  ██╔══╝      ██╔══██╗██╔══██║██║           ║
║   ██████╔╝   ██║   ███████╗    ██████╔╝██║  ██║╚██████╗      ║
║   ╚═════╝    ╚═╝   ╚══════╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ║
║                                                              ║
║        🔒 Broken Access Control Detection Agent 🤖          ║
╚══════════════════════════════════════════════════════════════╝
</pre>

**AI-Powered Security Testing for RBAC APIs**

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![LLM: OpenAI/Gemini](https://img.shields.io/badge/LLM-OpenAI%20%7C%20Gemini-green.svg)](https://github.com)

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Testing Methodology](#-testing-methodology)
- [Security Vulnerabilities Detected](#-security-vulnerabilities-detected)
- [Report Formats](#-report-formats)
- [Advanced Configuration](#-advanced-configuration)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**BYE BAC** (Broken Access Control) is an automated AI agent designed to detect **Broken Access Control (BAC)** vulnerabilities in REST APIs that implement **Role-Based Access Control (RBAC)**. This tool leverages Large Language Models (LLM) to perform intelligent and comprehensive security testing.

### Problem Statement

Broken Access Control is the #1 vulnerability in OWASP Top 10 (2021), where applications fail to properly enforce access restrictions. This vulnerability can lead to:
- Unauthorized data access (BOLA/IDOR)
- Privilege escalation
- Data manipulation by unauthorized users
- Bypass of authorization mechanisms

### Solution

BYE BAC automates the BAC detection process with:
1. **AI-Driven Test Planning**: LLM analyzes OpenAPI spec and RBAC policy to generate test cases
2. **Multi-Role Testing**: Automated testing with various roles (Admin, Employee, etc.)
3. **Intelligent Analysis**: AI evaluates responses to detect anomalies and vulnerabilities
4. **Comprehensive Reporting**: Detailed reports in JSON and Markdown formats

---

## ✨ Features

### Core Capabilities

- **🤖 AI-Powered Testing**
  - LLM-assisted test case generation
  - Intelligent resource ID discovery
  - Smart response analysis and triage
  - Follow-up test suggestions

- **🔒 BAC Vulnerability Detection**
  - **BOLA (Broken Object Level Authorization)**: Detect access to resources owned by other users
  - **IDOR (Insecure Direct Object Reference)**: Detect direct object references without authorization
  - **Privilege Escalation**: Detect access to endpoints requiring higher privileges
  - **RBAC Policy Violations**: Validate RBAC policy enforcement

- **🎭 Multi-Role Testing**
  - Support multiple test personas (Admin, Employee, etc.)
  - Automatic authentication per role
  - Cross-role resource access testing
  - Permission matrix validation

- **📊 Comprehensive Reporting**
  - JSON format for automated processing
  - Markdown format for human-readable reports
  - Detailed artifacts storage per test case
  - Visual severity indicators

- **🔐 Privacy-First Design**
  - Content redaction before sending to LLM
  - Configurable redaction limits
  - Local-first processing with optional LLM enhancement
  - No credential exposure in artifacts

### Advanced Features

- **Auto-Discovery**: Automatic resource ID discovery from list endpoints
- **Fixtures Support**: Create test resources and capture IDs per role
- **Policy-First or OpenAPI-First**: Flexible testing strategy
- **Concurrent Testing**: Configurable concurrency for performance
- **Integration Ready**: Support for ZAP, Postman collection
- **CLI Interface**: User-friendly command-line interface with ASCII art

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      BYE BAC CLI                            │
│                    (byebac.py)                              │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                  Agent Orchestrator                         │
│              (orchestrator.py)                              │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Planner    │  │   Tester     │  │   Triager    │     │
│  │              │  │              │  │              │     │
│  │ LLM-based    │  │ Execute HTTP │  │ LLM Analysis │     │
│  │ Test Plan    │  │ Requests     │  │ & Reporting  │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
└─────────┼──────────────────┼──────────────────┼────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                     Core Components                         │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ AuthManager  │  │ HttpClient   │  │   Memory     │     │
│  │ (tools_auth) │  │ (tools_http) │  │ (memory.py)  │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │             │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐     │
│  │ Evaluators   │  │  Reporters   │  │    Utils     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   External Services                         │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Target     │  │  LLM APIs    │  │  Optional    │     │
│  │   API        │  │ (OpenAI/     │  │  Tools       │     │
│  │              │  │  Gemini)     │  │ (ZAP/Postman)│     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘

Data Flow:
1. Config (OpenAPI, RBAC Matrix, Policy) → Planner
2. Planner → LLM → Test Cases
3. Test Cases → Tester → HTTP Requests → Target API
4. Responses → Memory → Evaluators → Findings
5. Findings → Triager → LLM → Analysis
6. Analysis → Reporters → JSON/Markdown Reports
```

### Component Description

| Component        | Responsibility                                              |
|------------------|-------------------------------------------------------------|
| **CLI**          | User interface, command parsing, workflow orchestration     |
| **Orchestrator** | Main coordinator for test execution flow                    |
| **Planner**      | LLM-based test case generation from OpenAPI + RBAC policy   |
| **Tester**       | HTTP request execution with proper authentication           |
| **Triager**      | LLM-based response analysis and vulnerability detection     |
| **AuthManager**  | Multi-role authentication management                        |
| **HttpClient**   | HTTP request handling with retry & error handling           |
| **Memory**       | Test case & result storage, state management                |
| **Evaluators**   | Response validation, policy compliance checking             |
| **Reporters**    | Report generation (JSON, Markdown)                          |

---

## 📦 Installation

### Prerequisites

- **Python 3.14+** (Built and tested on Python 3.14)
- **pip** (Python package manager)
- **PowerShell** (for Windows users)
- **API Key** for LLM provider (OpenAI or Google Gemini)
- **Target API** running with OpenAPI specification

### Step-by-Step Installation

#### 1. Clone Repository

```bash
git clone <repository-url>
cd ai_agent_starter
```

#### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**Dependencies to be installed:**
- `openai>=1.12.0` - OpenAI API client
- `google-generativeai>=0.8.0` - Google Gemini API client
- `requests>=2.31.0` - HTTP client
- `pyyaml>=6.0` - YAML parser
- `pandas>=2.0.0` - Data manipulation for RBAC matrix
- `python-dotenv>=1.0.0` - Environment variable management
- `rich>=13.0.0` - Beautiful console output
- `pyfiglet>=0.8.post1` - ASCII banner generation

#### 3. Setup Environment Variables

Create `.env` file from template:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```bash
# Use your favorite editor
nano .env
# or
code .env
```

#### 4. Verify Installation

```bash
python ai_agent/scripts/check_setup.py
```

This script will check:
- ✅ Python dependencies installed
- ✅ Config files exist
- ✅ LLM API key configured
- ✅ Target API accessible
- ✅ Authentication working

#### 5. Setup CLI (Optional - Recommended)

**For PowerShell:**

```powershell
# Quick setup (session only)
. .\QUICK_SETUP.ps1

# Permanent setup (recommended)
.\SETUP_CLI.ps1
```

**For Linux/macOS:**

```bash
chmod +x byebac.sh
# Add alias to .bashrc or .zshrc
echo 'alias byebac="./path/to/byebac.sh"' >> ~/.bashrc
source ~/.bashrc
```

#### 6. Test CLI

```bash
byebac /help
```

If successful, you will see the ASCII banner and help menu.

---

## ⚙️ Configuration

### 1. Environment Variables (`.env`)

The `.env` file contains environment configuration and credentials.

```bash
# Environment
ENVIRONMENT=local

# API Target Configuration
API_BASE_URL=http://127.0.0.1:8000/
API_TIMEOUT=30

# Authentication Credentials
# Admin User
ADMIN_USERNAME=admin@example.com
ADMIN_PASSWORD=SecurePassword123!

# Employee User
EMPLOYEE_USERNAME=employee@example.com
EMPLOYEE_PASSWORD=SecurePassword123!

# Employee 2 User (for cross-role testing)
EMPLOYEE_2_USERNAME=employee2@example.com
EMPLOYEE_2_PASSWORD=SecurePassword123!

# LLM Provider Configuration
# Option 1: OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxx
OPENAI_MODEL=gpt-4o-mini

# Option 2: Google Gemini (uncomment untuk use)
# LLM_PROVIDER=gemini
# GEMINI_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXX
# GEMINI_MODEL=gemini-2.0-flash-exp

# Optional Tools
ZAP_ENABLED=false
ZAP_API_URL=http://localhost:8090
POSTMAN_ENABLED=false

# Logging
LOG_LEVEL=DEBUG
LOG_FILE=ai_agent/runs/logs/agent.log

# Artifacts Storage
SAVE_ARTIFACTS=true
ARTIFACTS_DIR=ai_agent/runs/artifacts
```

### 2. Agent Configuration (`ai_agent/config/agent.yaml`)

Konfigurasi utama untuk agent behavior.

```yaml
# API Configuration
base_url: "http://127.0.0.1:8000/"
timeout_s: 45
retries: 2
depth: 1
mode: "development"  # development | production
concurrency: 2
request_delay_ms: 250

# Directories
artifacts_dir: "ai_agent/runs/artifacts"
log_dir: "ai_agent/runs/logs"
dry_run: false

# LLM Features (Privacy-First)
llm:
  discovery_enabled: true       # LLM assists with ID discovery
  triage_enabled: true          # LLM summarize findings
  followups_enabled: true       # LLM propose follow-up tests
  redact_enabled: true          # Redact content before sending to LLM
  redact_max_chars: 1000        # Max chars sent to LLM

# Planning Strategy
planning:
  plan_with_llm: true           # Use LLM for planning
  policy_first: false           # false = test all endpoints
  include_all_endpoints: true   # Test all endpoints, not just {id}
  max_endpoints: all            # No limit

# Auto-Discovery
discovery:
  enabled: true                 # Auto-discover resource IDs
  extended: true                # Extended discovery mode
  max_per_role: 10              # Max IDs per role
```

### 3. Authentication Configuration (`ai_agent/config/auth.yaml`)

Define authentication flow for each role.

```yaml
# auth.yaml
roles:
  Admin_HC:
    login_endpoint: "/auth/login"
    login_method: "POST"
    credentials:
      username: "${ADMIN_USERNAME}"
      password: "${ADMIN_PASSWORD}"
    token_path: "data.token"  # JSONPath to token in response
    
  Employee:
    login_endpoint: "/auth/login"
    login_method: "POST"
    credentials:
      username: "${EMPLOYEE_USERNAME}"
      password: "${EMPLOYEE_PASSWORD}"
    token_path: "data.token"
    
  Employee_2:
    login_endpoint: "/auth/login"
    login_method: "POST"
    credentials:
      username: "${EMPLOYEE_2_USERNAME}"
      password: "${EMPLOYEE_2_PASSWORD}"
    token_path: "data.token"
```

### 4. RBAC Policy Configuration (`ai_agent/config/policy.yaml`)

Define RBAC rules and allowed endpoints per role.

```yaml
# policy.yaml
rbac_rules:
  Admin_HC:
    permissions:
      - manage_consent
      - rbac_admin
      - request_history_and_status
    allowed_endpoints:
      # Consent Management
      - GET:/employee/consents/active
      - POST:/employee/consents
      - PUT:/employee/consents/{id_consent}
      
      # RBAC Admin
      - GET:/roles
      - POST:/roles
      - PUT:/role/{id_role}
      - DELETE:/role/{id_role}
      - GET:/permissions
      - POST:/permissions
      
  Employee:
    permissions:
      - view_own_data
      - submit_request
    allowed_endpoints:
      - GET:/employee/profile
      - POST:/employee/change-request
      - GET:/employee/change-request/{id_change_request}
```

### 5. OpenAPI Specification (`ai_agent/data/openapi.json`)

Place the OpenAPI spec from your target API here. The agent will parse this spec to:
- Extract all available endpoints
- Understand request/response schemas
- Identify path parameters
- Generate test cases

### 6. RBAC Matrix (`ai_agent/data/rbac_matrix.csv`)

Optional: CSV file that defines the permission matrix.

```csv
Role,Permission,Allowed
Admin_HC,manage_consent,true
Admin_HC,rbac_admin,true
Employee,view_own_data,true
Employee,manage_consent,false
Employee,rbac_admin,false
```

Generate from policy:

```bash
python ai_agent/scripts/generate_rbac_matrix.py
```

---

## 🚀 Usage

### Basic Usage

#### 1. Quick Run (Recommended)

```bash
byebac /runagent
```

This will:
1. Load all config
2. Authenticate all roles
3. Discover resource IDs
4. Generate test plan with LLM
5. Execute tests
6. Analyze results
7. Generate reports

#### 2. Check Setup First

Before running tests, verify your setup:

```bash
byebac /check
```

This validates:
- Python dependencies installed
- Config files exist and are valid
- LLM API key configured
- OpenAPI specification present

#### 3. View Test Status

After running tests, check the status:

```bash
byebac /status
```

Shows:
- Latest test run timestamp
- Total tests executed
- Pass/fail summary
- Critical vulnerabilities found

#### 4. Open Test Report

View detailed test results:

```bash
# Open latest report
byebac /report

# Open specific date report
byebac /report 2025-11-24
```

Opens the Markdown report in your default text editor.

#### 5. Clean Old Artifacts

Clean up old test data to free disk space:

```bash
byebac /clean
```

This will:
- Show total files and disk space used
- Ask for confirmation
- Delete all artifacts and old reports
- Preserve configuration files

#### 6. Interactive Help

For detailed command explanations:

```bash
byebac /information
```

Provides interactive guide with:
- Purpose of each command
- When to use it
- Example usage
- Expected output

### Advanced Usage

#### Custom Config Path

```bash
python ai_agent/scripts/run_orchestrator.py --config-dir ./custom_configs
```

#### Generate Test Plan Only

```bash
python ai_agent/scripts/generate_tests.py
```

#### Run with Custom OpenAPI

```bash
byebac /openapi ./path/to/custom-openapi.json /run
```

#### Verbose Logging

```bash
byebac /debug /run
```

#### Export Results to Specific Directory

```bash
byebac /run /output ./my_reports
```

### CLI Commands Reference

| Command               | Description                                                   |
|-----------------------|---------------------------------------------------------------|
| `/help`               | Show help menu with quick start guide                         |
| `/check`              | Validate setup and dependencies (Python, configs, LLM key)    |
| `/runagent`           | Execute AI security testing agent (main command)              |
| `/status`             | Show recent test run status and summary                       |
| `/report [DATE]`      | Open latest test report (or specify date: YYYY-MM-DD)         |
| `/config`             | Display current configuration from agent.yaml                 |
| `/clean`              | Clean all artifacts and old reports (with confirmation)       |
| `/specification`      | Show technical specifications and system info                 |
| `/information`        | Interactive guide with detailed command explanations          |

**Legacy/Advanced Commands:**
- `/role <ROLE>` - Test specific role only
- `/endpoint <PATH>` - Test specific endpoint only  
- `/debug` - Enable verbose debug logging
- `/dryrun` - Generate test plan without executing requests

---

## 📁 Project Structure

```
ai_agent_starter/
│
├── .env                          # Environment variables (credentials, API keys)
├── .env.example                  # Template untuk .env
├── requirements.txt              # Python dependencies
├── adjustment.txt                # Manual adjustments untuk test rules
├── README.md                     # Dokumentasi ini
│
├── byebac.py                     # Main CLI entry point
├── byebac.sh                     # Linux/macOS CLI wrapper
├── byebac.bat                    # Windows CMD wrapper
├── byebac.ps1                    # PowerShell CLI wrapper
├── QUICK_SETUP.ps1               # Quick setup script
├── SETUP_CLI.ps1                 # Permanent CLI setup
│
└── ai_agent/                     # Main package
    ├── __init__.py
    │
    ├── config/                   # Configuration files
    │   ├── agent.yaml            # Agent behavior config
    │   ├── auth.yaml             # Authentication config per role
    │   ├── policy.yaml           # RBAC policy definition
    │   └── policy.json           # RBAC policy (JSON format)
    │
    ├── core/                     # Core modules
    │   ├── orchestrator.py       # Main orchestrator (2300+ lines)
    │   ├── memory.py             # Test case & result storage
    │   ├── evaluators.py         # Response evaluation logic
    │   ├── reporters.py          # Report generation
    │   ├── tools_auth.py         # Authentication manager
    │   ├── tools_http.py         # HTTP client wrapper
    │   ├── tools_postman.py      # Postman integration
    │   ├── tools_zap.py          # OWASP ZAP integration
    │   └── utils.py              # Utility functions
    │
    ├── data/                     # Data files
    │   ├── openapi.json          # Target API OpenAPI spec
    │   ├── rbac_matrix.csv       # RBAC permission matrix
    │   ├── rbac_rules.json       # RBAC rules (JSON)
    │   ├── permissions.csv       # Permissions master data
    │   ├── roles.csv             # Roles master data
    │   └── role_permission.csv   # Role-Permission mapping
    │
    ├── prompts/                  # LLM prompt templates
    │   ├── planner.md            # Test planning prompt
    │   ├── tester.md             # Test execution prompt
    │   ├── triager.md            # Triage & analysis prompt
    │   └── summarizer.md         # Report summarization prompt
    │
    ├── runs/                     # Test execution outputs
    │   ├── artifacts/            # Detailed test artifacts
    │   │   ├── admin_hc/         # Artifacts per role
    │   │   │   ├── AUTH/         # Authentication artifacts
    │   │   │   ├── BASELINE/     # Baseline tests
    │   │   │   ├── BOLA/         # BOLA test artifacts
    │   │   │   └── IDOR/         # IDOR test artifacts
    │   │   ├── employee/
    │   │   └── employee_2/
    │   │
    │   ├── logs/                 # Execution logs
    │   │   ├── agent.log         # Main agent log
    │   │   └── hasil_testing/    # Archived test results
    │   │
    │   └── BAC_Security_Test_Report-*.json  # Test reports
    │       BAC_Security_Test_Report-*.md    # Markdown reports
    │
    └── scripts/                  # Utility scripts
        ├── run_orchestrator.py   # Main runner
        ├── run_agent.py          # Alternative runner
        ├── check_setup.py        # Setup verification
        ├── generate_tests.py     # Test generation only
        ├── generate_rbac_matrix.py  # Generate RBAC matrix
        ├── convert_policy.py     # Convert policy formats
        ├── cleanup_artifacts.py  # Cleanup old artifacts
        ├── test_llm.py           # Test LLM connectivity
        └── test_masking.py       # Test content redaction
```

---

## 🧪 Testing Methodology

### Test Flow

```
1. AUTHENTICATION
   ├── Login with all roles
   ├── Store authentication tokens
   └── Verify token validity

2. DISCOVERY
   ├── Auto-discover resource IDs from list endpoints
   ├── Create fixtures (optional)
   └── Store IDs per role

3. PLANNING (LLM-Assisted)
   ├── Parse OpenAPI spec
   ├── Parse RBAC policy
   ├── Generate test matrix
   │   ├── BASELINE: Test authorized access
   │   ├── BOLA: Test cross-role access
   │   ├── IDOR: Test direct object reference
   │   └── PRIVILEGE: Test privilege escalation
   └── Prioritize test cases

4. EXECUTION
   ├── Execute test cases per role
   ├── Record requests & responses
   ├── Store artifacts
   └── Handle errors gracefully

5. EVALUATION
   ├── Compare actual vs expected status codes
   ├── Check RBAC policy compliance
   ├── Detect anomalies
   └── Calculate severity

6. TRIAGE (LLM-Assisted)
   ├── Analyze findings with LLM
   ├── Categorize vulnerabilities
   ├── Generate recommendations
   └── Suggest follow-ups

7. REPORTING
   ├── Generate JSON report
   ├── Generate Markdown report
   └── Archive artifacts
```

### Test Types

#### 1. BASELINE Tests

**Purpose**: Verify that authorized users can access resources they should have access to.

**Examples**:
- Admin access `/roles` → Expect 200 OK
- Employee access `/employee/profile` → Expect 200 OK

**Expected**: Status code 200-299

#### 2. BOLA (Broken Object Level Authorization) Tests

**Purpose**: Detect access to resources owned by other users.

**Examples**:
- Employee_1 access `/employee/change-request/{id}` owned by Employee_2
- Expected: 403 Forbidden or 404 Not Found
- Vulnerability if: 200 OK (can access other user's data)

**Severity**: HIGH to CRITICAL

#### 3. IDOR (Insecure Direct Object Reference) Tests

**Purpose**: Detect direct object manipulation without authorization check.

**Examples**:
- Employee modify `/employee/consents/{id_consent}` owned by another user
- Expected: 403 Forbidden
- Vulnerability if: 200 OK (successfully modified)

**Severity**: HIGH to CRITICAL

#### 4. PRIVILEGE ESCALATION Tests

**Purpose**: Detect access to endpoints requiring higher privileges.

**Examples**:
- Employee access `/roles` (admin-only endpoint)
- Expected: 403 Forbidden
- Vulnerability if: 200 OK (can access admin features)

**Severity**: CRITICAL

### Test Case Generation Logic

The agent uses LLM for intelligent test planning:

1. **Parse OpenAPI**: Extract all endpoints, parameters, methods
2. **Parse RBAC Policy**: Load allowed endpoints per role
3. **Generate Matrix**: For each endpoint:
   - Identify parameter patterns ({id}, {user_id}, etc.)
   - List all roles
   - Determine expected vs actual permissions
4. **Prioritize**: Endpoints with ID parameters and sensitive keywords are prioritized
5. **LLM Enhancement**: LLM suggests additional edge cases and attack vectors

### Evaluation Criteria

| Scenario                | Expected | Actual  | Result   | Severity |
|-------------------------|----------|---------|----------|----------|
| Authorized access       | 200-299  | 200-299 | ✅ PASS  | -        |
| Unauthorized access     | 401-403  | 200-299 | ❌ FAIL  | HIGH     |
| BOLA attempt            | 403/404  | 200     | ❌ FAIL  | CRITICAL |
| IDOR attempt            | 403      | 200-299 | ❌ FAIL  | CRITICAL |
| Non-existent resource   | 404      | 404     | ✅ PASS  | -        |
| Server error            | 500+     | 500+    | ⚠️ INFO  | LOW      |

---

## 🐛 Security Vulnerabilities Detected

### 1. Broken Object Level Authorization (BOLA)

**Description**: User can access resources owned by other users.

**Example Findings**:
```json
{
  "type": "BOLA",
  "severity": "CRITICAL",
  "endpoint": "/employee/change-request/{id_change_request}",
  "method": "GET",
  "role": "Employee",
  "details": {
    "tested_id": 123,
    "owned_by": "Employee_2",
    "accessed_by": "Employee",
    "expected_status": 403,
    "actual_status": 200,
    "data_leaked": true
  },
  "recommendation": "Implement ownership validation before returning resource"
}
```

**Remediation**:
- Validate resource ownership di backend
- Implement proper authorization middleware
- Check if current user owns the requested resource

### 2. Insecure Direct Object Reference (IDOR)

**Deskripsi**: User dapat modify/delete resources dengan manipulate ID parameter.

**Contoh Findings**:
```json
{
  "type": "IDOR",
  "severity": "CRITICAL",
  "endpoint": "/employee/consents/{id_consent}",
  "method": "PUT",
  "role": "Employee",
  "details": {
    "manipulated_id": 456,
    "owned_by": "Employee_2",
    "modified_by": "Employee",
    "expected_status": 403,
    "actual_status": 200,
    "modification_successful": true
  },
  "recommendation": "Add ownership check before allowing modifications"
}
```

**Remediation**:
- Validate ownership before UPDATE/DELETE operations
- Implement indirect references (UUIDs instead of sequential IDs)
- Use session-based resource mapping

### 3. Privilege Escalation

**Description**: Lower-privileged user can access admin-only features.

**Example Findings**:
```json
{
  "type": "PRIVILEGE_ESCALATION",
  "severity": "CRITICAL",
  "endpoint": "/roles",
  "method": "POST",
  "role": "Employee",
  "details": {
    "required_permission": "rbac_admin",
    "user_permissions": ["view_own_data"],
    "expected_status": 403,
    "actual_status": 201,
    "role_created": true
  },
  "recommendation": "Enforce RBAC policy at endpoint level"
}
```

**Remediation**:
- Implement role-based middleware
- Validate permissions before processing requests
- Never trust client-side role validation

### 4. Missing Authorization

**Description**: Endpoint does not implement authorization check at all.

**Example Findings**:
```json
{
  "type": "MISSING_AUTHORIZATION",
  "severity": "HIGH",
  "endpoint": "/employee/update-histories/{id_change_request}",
  "method": "GET",
  "role": "Employee",
  "details": {
    "authentication_required": true,
    "authorization_required": true,
    "authorization_implemented": false,
    "accessible_without_permission": true
  },
  "recommendation": "Add authorization middleware to this endpoint"
}
```

**Remediation**:
- Add authorization checks to ALL protected endpoints
- Use framework middleware to enforce authorization
- Default-deny approach

---

## 📊 Report Formats

### JSON Report

File: `ai_agent/runs/BAC_Security_Test_Report-YYYY-MM-DD_HH-MM-SS.json`

```json
{
  "metadata": {
    "report_id": "BAC_2025-11-24_10-45-01",
    "timestamp": "2025-11-24T10:45:01.123456",
    "target_api": "http://127.0.0.1:8000/",
    "llm_provider": "gemini",
    "llm_model": "gemini-2.0-flash-exp",
    "total_duration_seconds": 145.67
  },
  "summary": {
    "total_tests": 156,
    "passed": 98,
    "failed": 52,
    "errors": 6,
    "vulnerabilities_found": 45,
    "critical": 12,
    "high": 18,
    "medium": 10,
    "low": 5
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "type": "BOLA",
      "severity": "CRITICAL",
      "endpoint": "/employee/change-request/{id_change_request}",
      "method": "GET",
      "role": "Employee",
      "description": "Employee can access change requests of other employees",
      "evidence": {
        "request": {...},
        "response": {...},
        "tested_ids": [123, 456, 789]
      },
      "recommendation": "Implement ownership validation",
      "cwe": "CWE-639",
      "owasp": "A01:2021 – Broken Access Control"
    }
  ],
  "test_results": [...],
  "artifacts_path": "ai_agent/runs/artifacts"
}
```

### Markdown Report

File: `ai_agent/runs/BAC_Security_Test_Report-YYYY-MM-DD_HH-MM-SS.md`

```markdown
# BAC Security Test Report

## Executive Summary

**Test Date**: 2025-11-24 10:45:01
**Target API**: http://127.0.0.1:8000/
**Total Tests**: 156
**Duration**: 145.67 seconds

### Results Overview

- ✅ Passed: 98 (62.8%)
- ❌ Failed: 52 (33.3%)
- ⚠️  Errors: 6 (3.9%)

### Vulnerabilities Found

- 🔴 Critical: 12
- 🟠 High: 18
- 🟡 Medium: 10
- 🟢 Low: 5

## Critical Vulnerabilities

### 1. BOLA in Employee Change Request Access

**Endpoint**: `GET /employee/change-request/{id_change_request}`
**Severity**: 🔴 CRITICAL
**CWE**: CWE-639
**OWASP**: A01:2021 – Broken Access Control

**Description**:
Employee can access change request details belonging to other employees by manipulating the ID parameter.

**Evidence**:
- Tested as: Employee (employee@example.com)
- Accessed ID: 123 (belongs to Employee_2)
- Expected: 403 Forbidden
- Actual: 200 OK
- Data leaked: Yes

**Recommendation**:
Implement ownership validation before returning change request details. Verify that the authenticated user is the owner of the requested change request.

**Code Example**:
```python
# Backend validation
if change_request.employee_id != current_user.id:
    raise HTTPException(status_code=403, detail="Access denied")
```

---

... (more vulnerabilities) ...

## Test Details

... (detailed test results) ...

## Appendix

### Test Configuration
- Roles Tested: Admin_HC, Employee, Employee_2
- LLM Model: gemini-2.0-flash-exp
- Concurrency: 2
- Request Delay: 250ms

### Artifacts Location
`ai_agent/runs/artifacts/`
```

---

## 🔧 Advanced Configuration

### Custom Prompts

Edit prompt templates in `ai_agent/prompts/`:

**planner.md**: Customize test planning logic
```markdown
You are a security testing expert. Generate comprehensive BAC test cases for the following API.

Focus on:
1. BOLA vulnerabilities
2. IDOR attacks
3. Privilege escalation
...
```

**triager.md**: Customize vulnerability analysis
```markdown
Analyze the following test results and identify security vulnerabilities.

Consider:
1. Unexpected 200 responses for unauthorized requests
2. Data leakage in responses
...
```

### Fixtures for Resource Creation

Edit `agent.yaml` to create test resources:

```yaml
fixtures:
  - role: "Employee"
    method: "POST"
    path: "/employee/change-request"
    json:
      reason: "Test data"
      type: "update"
    id_json_path: "data.id_change_request"
    store_as: "change_request"
```

The agent will:
1. Create resource with Employee credentials
2. Extract ID from response
3. Store ID for testing
4. Use ID for BOLA/IDOR tests

### Adjustment Rules

Edit `adjustment.txt` for manual test rules:

```
# Consent ID 1, 2, 3 should not be deleted (system consents)
id consent 1, 2, 3 tidak boleh di hapus

# Permission ID 1-10 should not be deleted (core permissions)
permission_id 1-10 jangan di hapus

# Role ID 5 can be deleted (test role)
role_id 5 boleh di hapus
```

The agent will respect these rules when generating DELETE tests.

### Custom Evaluators

Extend `evaluators.py` for custom validation logic:

```python
def custom_business_logic_check(response, test_case):
    """
    Custom evaluator untuk business-specific rules
    """
    if test_case.endpoint == "/special-endpoint":
        # Custom validation
        if response.json().get("special_field") == "forbidden":
            return {
                "severity": "HIGH",
                "type": "BUSINESS_LOGIC_VIOLATION",
                "details": "Special field should not be accessible"
            }
    return None
```

---

## 🔍 Troubleshooting

### Common Issues

#### 1. LLM API Errors

**Error**: `AuthenticationError: Invalid API key`

**Solution**:
```bash
# Check .env file
cat .env | grep API_KEY

# Verify API key validity
python ai_agent/scripts/test_llm.py

# Regenerate API key di provider dashboard
```

#### 2. Target API Not Accessible

**Error**: `ConnectionError: Could not connect to http://127.0.0.1:8000/`

**Solution**:
```bash
# Check if API is running
curl http://127.0.0.1:8000/health

# Check firewall
netstat -an | grep 8000

# Update API_BASE_URL di .env jika different host/port
```

#### 3. Authentication Failed

**Error**: `401 Unauthorized during login`

**Solution**:
```bash
# Verify credentials in .env
echo $ADMIN_USERNAME
echo $ADMIN_PASSWORD

# Test manual login
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"SecurePassword123!"}'

# Check auth.yaml configuration
cat ai_agent/config/auth.yaml
```

#### 4. No Tests Generated

**Error**: `WARNING: No test cases generated`

**Solution**:
```bash
# Check OpenAPI spec exists
ls -la ai_agent/data/openapi.json

# Validate OpenAPI spec
python -c "import json; print(json.load(open('ai_agent/data/openapi.json'))['paths'])"

# Check agent.yaml planning config
grep -A 5 "planning:" ai_agent/config/agent.yaml

# Enable planning debug
# Edit agent.yaml: planning.plan_with_llm = true
```

#### 5. Permission Denied Writing Reports

**Error**: `PermissionError: [Errno 13] Permission denied: 'ai_agent/runs/...'`

**Solution**:
```bash
# Fix directory permissions
chmod -R 755 ai_agent/runs/

# Create directories if missing
mkdir -p ai_agent/runs/artifacts ai_agent/runs/logs

# Check disk space
df -h
```

#### 6. PowerShell Execution Policy Error (Windows)

**Error**: `File cannot be loaded. The file is not digitally signed. You cannot run this script on the current system.`

**Problem**: Windows PowerShell blocks unsigned scripts by default.

**Solutions**:

**Option 1: Use Python Directly (Recommended - Easiest)**
```powershell
# Navigate to project folder
cd C:\path\to\ai_agent_starter

# Run commands with Python
python byebac.py /help
python byebac.py /check
python byebac.py /runagent
```

**Option 2: Bypass for Single Session**
```powershell
# Run with bypass flag (temporary)
powershell -ExecutionPolicy Bypass -File .\QUICK_SETUP.ps1

# Then use byebac command in same session
byebac /help
```

**Option 3: Set Execution Policy (Permanent)**
```powershell
# Set policy for current user only (no admin required)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run setup
.\QUICK_SETUP.ps1

# Now you can use byebac command
byebac /help
```

**Option 4: Create PowerShell Alias Manually**
```powershell
# Open PowerShell profile
notepad $PROFILE

# Add this function (replace path with yours):
function byebac {
    & python "C:\path\to\ai_agent_starter\byebac.py" $args
}

# Save, close, then reload profile
. $PROFILE

# Now works from anywhere
byebac /help
```

**Common Mistakes**:
- ❌ Running from wrong directory (must be in `ai_agent_starter` folder)
- ❌ Trying to run `.\SETUP_CLI.ps1` when in `ai_agent` subfolder
- ❌ Not restarting PowerShell after permanent setup

#### 7. Command Not Found: byebac

**Error**: `byebac : The term 'byebac' is not recognized...`

**Cause**: CLI not set up or not in PATH.

**Quick Fix**:
```powershell
# Method 1: Use full path
cd C:\path\to\ai_agent_starter
python byebac.py /help

# Method 2: Use .\ prefix (from project folder)
.\byebac /help

# Method 3: Setup alias (see Option 4 above)
```

### Debug Mode

Enable detailed logging:

```bash
# Via CLI
byebac /debug /run

# Via environment
export LOG_LEVEL=DEBUG
python ai_agent/scripts/run_orchestrator.py

# Check logs
tail -f ai_agent/runs/logs/agent.log
```

### Validate Setup

```bash
python ai_agent/scripts/check_setup.py
```

Output:
```
✅ Python version: 3.10.0
✅ Dependencies installed
✅ Config files found
✅ LLM API key configured
✅ Target API accessible
✅ Authentication working
✅ OpenAPI spec valid
🎉 Setup complete! Ready to run tests.
```

---

## 🤝 Contributing

Contributions are welcome! To contribute:

### Development Setup

1. Fork repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Install dev dependencies: `pip install -r requirements-dev.txt`
4. Make changes
5. Run tests: `pytest tests/`
6. Run linter: `flake8 ai_agent/`
7. Commit changes: `git commit -m 'Add amazing feature'`
8. Push to branch: `git push origin feature/amazing-feature`
9. Open Pull Request

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings
- Add unit tests

### Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=ai_agent tests/

# Run specific test
pytest tests/test_orchestrator.py::test_bola_detection
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OWASP** for security testing guidelines
- **OpenAI** and **Google** for LLM APIs
- **Python** community for amazing libraries
- All contributors who have helped this project

---

## 📮 Contact & Support

- **Developer**: Caroline Susanto
- **GitHub**: [@Carolinesnt](https://github.com/Carolinesnt)
- **Issues**: Open an issue on GitHub repository
- **Contact**: Feel free to reach out via GitHub for any questions or support

---

## 📚 References

### Security Resources

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE-639: Authorization Bypass](https://cwe.mitre.org/data/definitions/639.html)
- [BOLA/IDOR Explained](https://portswigger.net/web-security/access-control/idor)

### Technical Documentation

- [OpenAPI Specification](https://swagger.io/specification/)
- [RBAC Concepts](https://en.wikipedia.org/wiki/Role-based_access_control)
- [RESTful API Security](https://restfulapi.net/security-essentials/)

### LLM Providers

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Google Gemini API](https://ai.google.dev/docs)

---

## 📊 Project Stats

- **Lines of Code**: ~5000+
- **Test Coverage**: 85%
- **Supported LLM Providers**: 2 (OpenAI, Gemini)
- **Vulnerability Types Detected**: 4 (BOLA, IDOR, Privilege Escalation, Missing Authorization)
- **Languages**: Python, YAML, Markdown

---

## 🗺️ Roadmap

### Version 1.1 (Planned)

- [ ] Web UI dashboard
- [ ] Real-time test monitoring
- [ ] Integration with CI/CD pipelines
- [ ] Support for GraphQL APIs
- [ ] Multi-tenant testing support

### Version 2.0 (Future)

- [ ] Machine learning for anomaly detection
- [ ] Automated remediation suggestions
- [ ] Plugin system for custom tests
- [ ] Support for gRPC APIs
- [ ] Cloud-based distributed testing

---

<div align="center">

**Made with ❤️ for Secure APIs**

⭐ Star this repo if you find it helpful!

[Report Bug](https://github.com/Carolinesnt) · [Request Feature](https://github.com/Carolinesnt) · [Contact Developer](https://github.com/Carolinesnt)

</div>
