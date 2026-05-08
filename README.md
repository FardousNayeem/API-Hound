# Backend Testing Agent

A Python CLI black box testing agent for the Mini Social API.

## What It Does

Parses provided inputs, authenticates with seeded users, discovers live API state,
runs targeted checks across 14 required bug categories, records full request/response
evidence, generates `report.json`, and validates the output against the provided schema.

## Setup

```bash
python -m venv env
env\Scripts\Activate.ps1 
pip install -r requirements.txt
```

## Run

```bash
python -m agent.main \
  --base-url https://backend-agent-test.onrender.com \
  --openapi  resources/openapi.json \
  --schema   resources/report.schema.json \
  --output   output/report.json
```

## Output

| File | Description |
|---|---|
| `output/report.json` | Schema-validated findings report |
| `output/agent_log.txt` | Full request/response log |

