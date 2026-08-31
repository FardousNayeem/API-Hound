# API HOUND

A Python CLI black-box testing agent for the Mini Social API.

The agent takes a base URL, OpenAPI specification, and credentials as input, sends live HTTP requests to the target API, detects issues across the required bug categories, generates `report.json`, and validates the output against the provided schema.

## What It Does

This is a black-box testing agent. It does not inspect server source code. It only uses:

- the supplied API base URL
- the supplied OpenAPI contract
- seeded-user credentials
- observed live HTTP responses

The agent:

- loads the provided OpenAPI spec
- authenticates with seeded users
- discovers live API state through GET requests
- creates isolated probe data where needed
- uses UUID-suffixed usernames for probe registrations
- runs targeted checks across the required bug categories
- records request/response evidence
- redacts sensitive values from evidence and logs
- generates `output/report.json`
- validates `report.json` against `resources/report.schema.json`

## Setup

PowerShell:

```powershell
python -m venv env
.\env\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run:
```powershell
python -m agent.main `
  --base-url https://backend-agent-test.onrender.com `
  --openapi resources/openapi.json `
  --credentials resources/credentials.example.json `
  --schema resources/report.schema.json `
  --output output/report.json `
  --log output/agent_log.txt
```
