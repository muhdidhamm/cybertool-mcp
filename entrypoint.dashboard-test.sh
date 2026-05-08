#!/bin/sh
set -eu

export PYTHONUNBUFFERED=1

APP_ROOT="/opt/uts-mcp"
TRANSPORT="${MCP_TRANSPORT:-stdio}"
PORT="${MCP_PORT:-8080}"

mkdir -p "$APP_ROOT/output" "$APP_ROOT/logs" "$APP_ROOT/reports" "$APP_ROOT/data"

if [ ! -f "$APP_ROOT/server.py" ]; then
  echo "[dashboard-test] Missing $APP_ROOT/server.py. Ensure source is bind-mounted to /opt/uts-mcp." >&2
  exit 1
fi

case "$TRANSPORT" in
  stdio)
    exec python "$APP_ROOT/server.py" --transport stdio
    ;;
  sse)
    exec python "$APP_ROOT/server.py" --transport sse --host 0.0.0.0 --port "$PORT"
    ;;
  streamable-http)
    exec python "$APP_ROOT/server.py" --transport streamable-http --host 0.0.0.0 --port "$PORT"
    ;;
  *)
    echo "[dashboard-test] Unknown MCP_TRANSPORT: $TRANSPORT" >&2
    exit 1
    ;;
esac
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              