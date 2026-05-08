# FastAPI + React Dashboard Migration Plan

## Scope

- Backend: FastAPI service replacing the legacy `BaseHTTPRequestHandler` implementation.
- Frontend: React + Vite SPA for sessions, terminal stream, report designer, and playbook CRUD.
- Streaming: `/ws/events` websocket channel for near-real-time audit event delivery.

## Backend contract

- `GET /api/sessions`
- `GET /api/sessions/{id}`
- `GET /api/reports`
- `GET /api/output-files`
- `GET /api/playbooks`
- `GET /api/playbooks/{name}`
- `POST /api/playbooks`
- `PUT /api/playbooks/{name}`
- `DELETE /api/playbooks/{name}`
- `POST /api/playbooks/{name}/clone`
- `POST /api/playbooks/{name}/validate`
- `POST /api/playbooks/{name}/run`
- `GET /api/playbooks/{name}/runs`
- `GET /api/file`
- `WS /ws/events`

## Frontend phases

1. **Shell migration**: Keep existing HTML dashboard behavior through API compatibility.
2. **React foundation**: Build router + shared API client + auth middleware.
3. **Terminal view**: Live websocket stream + historical command logs with filters.
4. **Report designer**: Select sections/templates and export presets.
5. **Playbook manager**: CRUD/clone/validate/run and run history timeline.

## Non-functional targets

- API p95 latency < 300 ms for list endpoints at normal session load.
- Websocket event fan-out under 2s lag from audit write to dashboard display.
- Graceful degraded behavior when audit/report/playbook files are unavailable.
