# ArgusLoom

ArgusLoom is a backend MVP for interactive threat modeling over infrastructure graphs.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
```

## Development commands

```bash
argusloom --help
argusloom version
argusloom health
pytest
```

## Configuration

The project uses `pydantic-settings` and reads environment variables from `.env` by default.
The Phase 0 defaults are intentionally mock-first:

- `ARGUS_USE_MOCK_LLM=true`
- `ARGUS_USE_MOCK_NVD=true`
- `ARGUS_LOG_LEVEL=INFO`

## Notes

This repository is intentionally scoped to the Phase 0 MVP baseline. Later phases will add the graph ingestion, MITRE/CTI enrichment, and API layers.
