# Public HTTPS Incident Agent (GA5 v2)

FastAPI service implementing the `/v2/incidents` create, receipt, and GET endpoints, with SQL persistence and OTLP trace output.

## Deploy on Render

1. Create a GitHub repository and upload these files at its root.
2. In Render, choose **New → Blueprint** and select the repository. Render reads `render.yaml`.
3. Set `OPENAI_API_KEY` in Render's environment settings. Do not put keys in GitHub.
4. For reliable persistence, create a Render PostgreSQL database and set `DATABASE_URL` to its internal connection URL. A local SQLite file may not persist across redeploys or multiple instances.
5. Deploy. Your public HTTPS base URL is the `onrender.com` service URL, e.g. `https://your-service.onrender.com` (use the actual URL Render assigns).
6. Submit that URL with no trailing path, credentials, query, or fragment.

## Local run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
set OPENAI_API_KEY=...  # PowerShell: $env:OPENAI_API_KEY="..."
uvicorn app:app --host 0.0.0.0 --port 8000
```

Health check: `GET /health`

## Important verification notes

- Model planning is called once for each first-seen `runId`; replay returns persisted state.
- Receipt processing and GET do not call the model.
- Sensitive request fields are excluded from model input and response state.
- The code is a starter implementation and must be validated against the grader's exact incidents before relying on it for marks. The model prompt cannot guarantee correct diagnosis or arguments; inspect the grader feedback and improve planner behavior accordingly.
- For public production use, configure PostgreSQL and an API access policy if the grader permits one. The requested grader-facing endpoints are intentionally unauthenticated.
