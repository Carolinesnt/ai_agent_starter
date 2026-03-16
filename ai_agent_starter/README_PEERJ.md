# BYE BAC: AI-Powered Broken Access Control Detection Agent

## Description
BYE BAC is an automated security testing agent for detecting Broken Access Control (BAC) issues in REST APIs that use Role-Based Access Control (RBAC).  
The project combines policy-aware test planning, role-based authentication, HTTP execution, and result evaluation to identify BAC categories such as BOLA/IDOR, privilege escalation, and authorization bypass.

This README is prepared as a compact research-oriented documentation file for submission/review purposes.

## Dataset Information
The dataset is **self-curated** and **author-created** for this research (self-constructed experimental dataset; not from an internal ESS application, company backend, or production system). Full description and suggested Figshare/Methods text: `docs/SELF_CURATED_DATASET_LEGEND.txt`.

The project uses structured security testing data in `ai_agent/data`:

- `openapi.json`: OpenAPI specification (authored for the experimental API) used to discover endpoints, parameters, and payload shapes.
- `roles.csv`: list of roles defined in the test environment.
- `permissions.csv`: list of defined permissions/actions.
- `role_permission.csv`: role-to-permission mapping.
- `rbac_matrix.csv`: flattened role-permission matrix used by the orchestrator/planning logic.
- `rbac_rules.json`: optional/legacy artifact (not the primary runtime source for policy checks).

### Dataset Purpose
- Define the access model and expected authorization behavior.
- Support automatic generation of role-aware BAC test scenarios.
- Provide machine-readable policy context for deterministic and LLM-assisted testing.

## Code Information
Main code package: `ai_agent`

Core modules:
- `ai_agent/core/orchestrator.py`: end-to-end flow controller (load config, plan, execute, evaluate, report).
- `ai_agent/core/tools_auth.py`: role login/token acquisition and identity mapping.
- `ai_agent/core/tools_http.py`: HTTP execution with retries, auth header injection, and artifact persistence.
- `ai_agent/core/evaluators.py`: expected-vs-actual comparison and classification metrics.
- `ai_agent/core/reporters.py`: JSON/Markdown report generation.
- `ai_agent/core/utils.py`: helper loaders/parsers for YAML/JSON/CSV/OpenAPI.

Runtime/config files:
- `ai_agent/config/agent.yaml`
- `ai_agent/config/auth.yaml`
- `ai_agent/config/policy.yaml` (canonical runtime policy file)

Entry points:
- `byebac.py` (CLI)
- `ai_agent/scripts/run_agent.py` (direct runner)

## Usage Instructions
### Step-by-Step Quick Start (Reviewer Friendly)
Run from project root (`ai_agent_starter`):

```bash
# 1) Install dependencies
pip install -r requirements.txt

# 2) Validate setup
byebac /check

# 3) Execute BAC scan
byebac /runagent

# 4) Check run summary
byebac /status

# 5) Open latest report path
byebac /report
```

If `byebac` command is not available in your shell, use:

```bash
python byebac.py /check
python byebac.py /runagent
python byebac.py /status
python byebac.py /report
```

### 1) Environment setup
On Windows PowerShell:

```powershell
./scripts/setup_venv.ps1
./scripts/activate_venv.ps1
pip install -r requirements.txt
```

Or manually:

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### 2) Configure runtime inputs
1. Update `ai_agent/config/agent.yaml` with your `base_url` and execution settings.  
2. Update `ai_agent/config/auth.yaml` with login endpoint, credential fields, and role definitions.  
3. Update `ai_agent/config/policy.yaml` with allow/deny RBAC expectations.  
4. Ensure `ai_agent/data/openapi.json` and RBAC CSV files are present and aligned with target API behavior.  
5. Set environment variables for credentials and API keys (if LLM features are enabled).

### 3) Run the agent
From project root:

```bash
python byebac.py /runagent
```

Alternative:

```bash
python ai_agent/scripts/run_agent.py
```

### 4) Output artifacts
Results are saved in `ai_agent/runs`:
- `BAC_Security_Test_Report-*.json`
- `BAC_Security_Test_Report-*.md`
- request/response artifacts for evidence and traceability

Optional cleanup after testing:

```bash
byebac /clean
```

## Requirements
Minimum software/runtime requirements:
- Python 3.14+ (project target)
- pip
- Network access to target API under test

Python dependencies (from `requirements.txt`):
- `openai>=1.12.0`
- `requests>=2.31.0`
- `pyyaml>=6.0`
- `pandas>=2.0.0`
- `python-dotenv>=1.0.0`
- `rich>=13.0.0`
- `google-generativeai>=0.8.0` (optional/fallback)
- `google-genai>=0.2.0` (optional/preferred for Gemini)
- `pyfiglet>=0.8.post1`

## Methodology
High-level testing methodology:
1. **Load Inputs**: read OpenAPI, RBAC matrix, policy, and auth settings.
2. **Plan Tests**: generate BAC-oriented test plans (policy-first and/or OpenAPI-driven, optionally LLM-assisted).
3. **Authenticate by Role**: obtain tokens/identities for each test persona.
4. **Execute Requests**: run endpoint/mutation combinations across roles and resource IDs.
5. **Evaluate**: compare observed status/result with expected policy behavior.
6. **Classify Findings**: assign categories such as TP/TN/FP/FN and BAC type.
7. **Report**: produce JSON/Markdown outputs and request/response artifacts.

## Citations
If this project/dataset is used in a manuscript, cite:
- The BYE BAC project repository (software citation).
- OWASP Top 10 (for BAC context), especially A01: Broken Access Control.

**Code (Zenodo):**
https://doi.org/10.5281/zenodo.18524561
**Dataset (Figshare):**
https://doi.org/10.6084/m9.figshare.31742872
**Manuscript:** *(to be updated upon acceptance)*

Suggested citation template (edit with your publication details):

```text
Author(s). (Year). BYE BAC: AI-Powered Broken Access Control Detection Agent (Version x.y.z) [Software]. Repository URL
```

## License
This project is distributed under the MIT License.

## Contribution Guidelines
Contributions are welcome. Recommended process:
1. Fork the repository and create a feature branch.
2. Add or update tests/config samples when changing behavior.
3. Keep changes focused and document rationale in commit messages.
4. Open a pull request with a clear summary and validation steps.

For security-related findings, include reproducible steps and minimal sensitive data in reports.
