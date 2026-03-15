# BYE BAC - Implementation Guide

BYE BAC is an automated Broken Access Control (BAC) testing agent for RBAC-based REST APIs.
It runs role-based authorization tests from OpenAPI + policy config, then produces JSON/Markdown reports and request/response artifacts.

## Description

BYE BAC validates authorization behavior across roles and endpoints to detect BAC issues such as BOLA/IDOR, privilege escalation, and access bypass.  
It combines deterministic policy checks and optional LLM-assisted planning/triage for faster security validation.

## Dataset Information

The dataset is **self-curated** and **author-created** for this research. It is not from an internal ESS application, a real company backend, or any production system. It is a self-constructed experimental dataset used to evaluate the agent’s BAC/IDOR/BOLA detection.

Primary data sources are stored in `ai_agent/data/`:

- `openapi.json`: OpenAPI specification (authored for the experimental API) used for endpoint discovery and payload/schema extraction
- `roles.csv`: roles defined in the test environment
- `permissions.csv`: permission catalog for the access control model
- `role_permission.csv`: role-to-permission relationships
- `rbac_matrix.csv`: flattened RBAC matrix for planning context

Policy and auth config (also part of the self-curated dataset): `ai_agent/config/policy.yaml`, `ai_agent/config/auth.yaml`. Full description and Figshare/Methods text: see `docs/SELF_CURATED_DATASET_LEGEND.txt`.

## Code Information

Main runtime package is `ai_agent/`:

- `ai_agent/core/orchestrator.py`: end-to-end execution flow
- `ai_agent/core/tools_auth.py`: role authentication and token handling
- `ai_agent/core/tools_http.py`: HTTP execution + artifact persistence
- `ai_agent/core/evaluators.py`: expected-vs-actual classification (TP/TN/FP/FN)
- `ai_agent/core/reporters.py`: JSON/Markdown report generation

## What Is Included

- `byebac.py`: main CLI entrypoint
- `ai_agent/config/`: runtime configs (`agent.yaml`, `auth.yaml`, `policy.yaml`)
- `ai_agent/data/openapi.json`: target API specification
- `ai_agent/core/`: orchestrator, HTTP/auth tools, evaluators, reporters
- `ai_agent/runs/`: generated reports, logs, and artifacts

## Current Command Set (Verified)

Use from project root:

- `python byebac.py /check`
- `python byebac.py /runagent`
- `python byebac.py /status`
- `python byebac.py /report`
- `python byebac.py /config`
- `python byebac.py /clean`
- `python byebac.py /specification`
- `python byebac.py /information`

Aliases:

- `/runagent`: `run`, `start`
- `/information`: `/info`, `info`
- `/specification`: `/spec`, `spec`
- `/clean`: `clean`, `cleanup`

## Reviewer Quick Run

```bash
pip install -r requirements.txt
python byebac.py /check
python byebac.py /runagent
python byebac.py /status
python byebac.py /report
```

## Usage Instructions

1. Install dependencies (`pip install -r requirements.txt`).
2. Configure runtime files in `ai_agent/config/` and set credentials/API keys in `.env`.
3. Run `python byebac.py /check` to validate setup.
4. Run `python byebac.py /runagent` to execute BAC testing.
5. Inspect results via `python byebac.py /status` and `python byebac.py /report`.

PowerShell helper scripts are under `scripts/`:

- `.\scripts\setup_venv.ps1`
- `.\scripts\activate_venv.ps1`
- `. .\scripts\QUICK_SETUP.ps1`
- `.\scripts\SETUP_CLI.ps1`

Optional cleanup:

```bash
python byebac.py /clean
```

## Required Configuration

1. `ai_agent/config/agent.yaml`
   - `base_url`
   - `llm.summary_required` (recommended `false` for offline/restricted network test environments)
2. `ai_agent/config/auth.yaml`
   - role login settings and credential mapping
3. `ai_agent/config/policy.yaml`
   - authorization expectations (single canonical runtime policy file)
4. `ai_agent/data/openapi.json`
   - API endpoints and request schema source

And `.env` for credentials / API keys.

## Requirements

- Python 3.14+ (project target)
- `pip`
- Network access to target API
- Python dependencies in `requirements.txt` (e.g., `requests`, `pyyaml`, `python-dotenv`, `rich`, `openai`, `google-genai`, `pandas`)

## Output Structure

Reports:

- `ai_agent/runs/BAC_Security_Test_Report-*.json`
- `ai_agent/runs/BAC_Security_Test_Report-*.md`

Artifacts (organized by date/role/type/target/method/endpoint):

- `ai_agent/runs/artifacts/<YYYY_MM_DD>/<role>/<BAC_TYPE>/<target>/<METHOD>/<endpoint>/*.json`

Logs:

- `ai_agent/runs/logs/agent.log`

## Deployment and Run Notes

- If LLM provider is unreachable, run still completes when `llm.summary_required: false`.
- Artifact files already mask sensitive headers/tokens before persistence.
- BAC classification includes `TP/TN/FP/FN/ERR/NF/SKIP`; `SKIP` is excluded from core confusion decisions.
- Placeholder-based tests are skipped when required IDs cannot be resolved (safer than injecting synthetic IDs).

## Methodology

High-level execution flow:

1. Load OpenAPI/config/policy/auth inputs.
2. Build role-endpoint test plan (deterministic and/or LLM-assisted).
3. Authenticate per role and collect IDs/resources.
4. Execute baseline + mutation scenarios.
5. Evaluate observed responses against policy expectations.
6. Generate JSON/Markdown reports and artifacts.

## Recommended Final Check Before External Testing

1. Run `/check` and confirm all required files pass.
2. Confirm `base_url` points to intended test environment.
3. Validate auth roles/credentials in `.env` + `auth.yaml`.
4. Set `llm.summary_required: false` if environment has no stable outbound DNS/API access.
5. Run `/runagent`, then inspect:
   - `/status`
   - latest `.md` report
   - artifacts for key endpoints

## License

MIT License.

## Citations

If used in research/reporting, cite:

- BYE BAC software repository
- OWASP Top 10 A01:2021 (Broken Access Control)

## Contribution Guidelines

1. Create a focused feature/fix branch.
2. Keep changes scoped and documented.
3. Validate using `/check` and a sample `/runagent`.
4. Submit PR with reproducible test steps.
