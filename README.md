# CTI Collector

Security technical intel pipeline:
RSS collection -> LLM summarize/tag/score/Sigma -> Jira Intel/Validation ticketing.

## Features
- RSS allowlist based collection
- Article body extraction with trafilatura fallback
- OpenAI-compatible local LLM integration (`/v1/chat/completions`)
- Strict output validation (required fields, tag allowlist, Sigma required keys)
- Jira Cloud REST v3 integration
- Idempotency with SQLite + URL normalization + optional Jira JQL fallback
- Structured JSON logs and run summary

## Project structure
- `src/cti_collector/config.py`: Config and tag dictionary loader
- `src/cti_collector/rss.py`: RSS fetch and content extraction
- `src/cti_collector/llm.py`: LLM client and JSON recovery
- `src/cti_collector/models.py`: Output validation and Sigma gate
- `src/cti_collector/jira.py`: Jira issue create/link/search
- `src/cti_collector/storage.py`: SQLite idempotency store
- `src/cti_collector/pipeline.py`: End-to-end orchestration
- `scripts/run_daily.py`: single-run batch entrypoint

## Setup
1. Install dependencies
```bash
pip install -r requirements.txt
```
2. Create runtime config
```bash
cp config.example.yaml config.yaml
```
3. Set environment variables
```bash
export JIRA_EMAIL="you@example.com"
export JIRA_API_TOKEN="..."
export LLM_API_KEY="..."
```
(Windows PowerShell)
```powershell
$env:JIRA_EMAIL="you@example.com"
$env:JIRA_API_TOKEN="..."
$env:LLM_API_KEY="..."
```

## Run
```bash
python scripts/run_daily.py --config config.yaml --tags tag_dictionary.yaml --prompt prompts/system_prompt.txt
```

## Notes
- Priority/Status update is intentionally excluded (Jira Automation responsibility).
- MISP integration is intentionally excluded from MVP.
- Sigma runtime validation checks required keys: `title`, `logsource`, `detection`, `condition`.
