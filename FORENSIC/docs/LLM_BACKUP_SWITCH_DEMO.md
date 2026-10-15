# LLM Backup Switch Demo Runbook

This runbook validates manual provider switching between Local (LM Studio) and OpenRouter backup.

## 1) Configure environment

Set these variables before starting the app:

- `LLM_PROVIDER_DEFAULT=local`
- `OPENROUTER_API_KEY=<your_key>`
- `LLM_OPENROUTER_MODEL=<openrouter_model_id>`
- `LLM_OPENROUTER_URL=https://openrouter.ai/api/v1/chat/completions`

Optional:

- `OPENROUTER_REFERER=<your_site_url>`
- `OPENROUTER_TITLE=EVI`

## 2) Start and verify health

1. Start EVI.
2. Ensure LM Studio is reachable.
3. Check provider health endpoint:
   - `GET /api/llm-provider/status?provider=local`
   - `GET /api/llm-provider/status?provider=openrouter`

## 3) Validate manual switch (no auto fallback)

1. In Settings, choose `LLM Provider = Local (LM Studio)`.
2. Run one deterministic query and one analysis query.
3. Confirm response metadata chip shows `Provider: Local`.
4. Switch provider to `OpenRouter (Backup)`.
5. Run the same analysis query.
6. Confirm metadata chip now shows `Provider: OpenRouter`.

## 4) Validate manual-only behavior

1. Keep provider set to `Local`.
2. Stop LM Studio (or block access).
3. Run an analysis query.
4. Expected result: explicit connection error for Local, and no automatic switch.
5. Manually switch to OpenRouter and retry.

## 5) SSE completion checks

For streamed responses, ensure `done` payload includes:

- `provider_used`
- `model_used`
- `llm_used`

## 6) Demo script (quick sequence)

1. Query A (deterministic): `show whatsapp messages`
2. Query B (analysis, Local): `Analyze this result`
3. Toggle provider to OpenRouter
4. Query C (analysis, OpenRouter): `Analyze this result and summarize risks`
5. Mention provider badge and response-time difference.
