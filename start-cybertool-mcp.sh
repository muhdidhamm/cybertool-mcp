#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="cybertool-mcp-stream"
IMAGE="ghcr.io/muhdidhamm/cybertool-mcp-server:latest"

if docker ps -aq --filter "name=^${CONTAINER_NAME}$" | grep -q .; then
  echo "Removing existing container: ${CONTAINER_NAME}"
  docker rm -f "${CONTAINER_NAME}" >/dev/null
fi

echo "Starting container from ${IMAGE} ..."
CONTAINER_ID="$(
  docker run -d \
    --name "${CONTAINER_NAME}" \
    --restart unless-stopped \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -p 8080:8080 \
    -p 8091:8090 \
    -v cybertool-mcp-output:/opt/uts-mcp/output \
    -v cybertool-mcp-logs:/opt/uts-mcp/logs \
    -v cybertool-mcp-data:/opt/uts-mcp/data \
    -v cybertool-mcp-reports:/opt/uts-mcp/reports \
    -e MCP_TRANSPORT=streamable-http \
    -e MCP_PORT=8080 \
    -e AUTO_UPDATE=first \
    -e REMOTE_SSH_KEY_PATH=/opt/uts-mcp/data/ssh-keys/mcp_remote_ed25519 \
    -e MCP_AUDIT_LOG_ENABLED=true \
    -e MCP_AUDIT_LOG_PATH=/opt/uts-mcp/logs/mcp_audit.jsonl \
    -e MCP_CHAT_HISTORY_DIR=/opt/uts-mcp/logs/chat_sessions \
    -e MCP_AUDIT_MAX_FIELD_CHARS=4000 \
    -e MCP_PLAYBOOKS_DIR=/opt/uts-mcp/data/playbooks \
    -e MCP_SUBSCRIPTION_LICENSE_PATH=/opt/uts-mcp/data/subscription.lic \
    -e MCP_SUBSCRIPTION_TRUST_MODE=prod \
    -e MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE=false \
    -e MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT=false \
    -e MCP_SUBSCRIPTION_KEYRING_PATH=/opt/uts-mcp/config/subscription-keys/keys.json \
    -e MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS=14 \
    -e MCP_DASHBOARD_ENABLED=true \
    -e MCP_DASHBOARD_BACKEND=fastapi \
    -e MCP_DASHBOARD_HOST=0.0.0.0 \
    -e MCP_DASHBOARD_PORT=8090 \
    -e MCP_DASHBOARD_USERNAME=secops \
    -e MCP_DASHBOARD_PASSWORD=secops \
    -e MCP_DASHBOARD_PASSWORD_HASH='pbkdf2_sha256$200000$6c9c3b64a42fab164b52716e81835335$4fa83944d1df1ddbca8b815ea9601f0d6a9f1ce3048186a73b073354163bfcc7' \
    -e MCP_DASHBOARD_LOGIN_MAX_ATTEMPTS=5 \
    -e MCP_DASHBOARD_LOGIN_WINDOW_SECONDS=300 \
    -e MCP_DASHBOARD_LOGIN_LOCKOUT_SECONDS=900 \
    -e MCP_DASHBOARD_COOKIE_SECURE=false \
    -e TIMEZONE=Asia/Kuala_Lumpur \
    -e TZ=Asia/Kuala_Lumpur \
    "${IMAGE}"
)"

echo "Started container: ${CONTAINER_ID}"
echo
docker ps --filter "name=^${CONTAINER_NAME}$" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
