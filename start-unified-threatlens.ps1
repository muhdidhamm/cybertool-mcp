$ErrorActionPreference = "Stop"

$containerName = "unified-threatlens-stream"
$image = "git.abyres.net/mcp/unified-threatlens-server:latest"

$envArgs = @(
    "-e", "MCP_TRANSPORT=streamable-http",
    "-e", "MCP_PORT=8080",
    "-e", "AUTO_UPDATE=first",
    "-e", "REMOTE_SSH_KEY_PATH=/opt/uts-mcp/data/ssh-keys/mcp_remote_ed25519",
    "-e", "MCP_AUDIT_LOG_ENABLED=true",
    "-e", "MCP_AUDIT_LOG_PATH=/opt/uts-mcp/logs/mcp_audit.jsonl",
    "-e", "MCP_CHAT_HISTORY_DIR=/opt/uts-mcp/logs/chat_sessions",
    "-e", "MCP_AUDIT_MAX_FIELD_CHARS=4000",
    "-e", "MCP_PLAYBOOKS_DIR=/opt/uts-mcp/data/playbooks",
    "-e", "MCP_SUBSCRIPTION_LICENSE_PATH=/opt/uts-mcp/data/subscription.lic",
    "-e", "MCP_SUBSCRIPTION_TRUST_MODE=prod",
    "-e", "MCP_SUBSCRIPTION_ALLOW_KEY_OVERRIDE=false",
    "-e", "MCP_SUBSCRIPTION_LEGACY_LICENSE_COMPAT=false",
    "-e", "MCP_SUBSCRIPTION_KEYRING_PATH=/opt/uts-mcp/config/subscription-keys/keys.json",
    "-e", "MCP_SUBSCRIPTION_EXPIRY_WARNING_DAYS=14",
    "-e", "MCP_DASHBOARD_ENABLED=true",
    "-e", "MCP_DASHBOARD_BACKEND=fastapi",
    "-e", "MCP_DASHBOARD_HOST=0.0.0.0",
    "-e", "MCP_DASHBOARD_PORT=8090",
    "-e", "MCP_DASHBOARD_AUTH_TOKEN=F-WGtCLuolLGl4-CAwl5NRCq99drfuy-d06ULSG6n-0",
    "-e", "MCP_DASHBOARD_USERNAME=secops",
    "-e", "MCP_DASHBOARD_PASSWORD=secops",
    "-e", "MCP_DASHBOARD_PASSWORD_HASH=",
    "-e", "MCP_DASHBOARD_LOGIN_MAX_ATTEMPTS=5",
    "-e", "MCP_DASHBOARD_LOGIN_WINDOW_SECONDS=300",
    "-e", "MCP_DASHBOARD_LOGIN_LOCKOUT_SECONDS=900",
    "-e", "MCP_DASHBOARD_COOKIE_SECURE=false",
    "-e", "TIMEZONE=Asia/Kuala_Lumpur",
    "-e", "TZ=Asia/Kuala_Lumpur"
)

$argsList = @(
    "run",
    "-d",
    "--name", $containerName,
    "--restart", "unless-stopped",
    "--cap-add", "NET_RAW",
    "--cap-add", "NET_ADMIN",
    "-p", "8080:8080",
    "-p", "8091:8090",
    "-v", "unified-threatlens-output:/opt/uts-mcp/output",
    "-v", "unified-threatlens-logs:/opt/uts-mcp/logs",
    "-v", "unified-threatlens-data:/opt/uts-mcp/data",
    "-v", "unified-threatlens-reports:/opt/uts-mcp/reports"
) + $envArgs + @($image)

$existing = docker ps -aq --filter "name=^${containerName}$"
if ($existing) {
    Write-Host "Removing existing container: $containerName"
    docker rm -f $containerName | Out-Null
}

Write-Host "Starting container from $image ..."
$containerId = (& docker @argsList).Trim()
Write-Host "Started container: $containerId"
Write-Host ""
docker ps --filter "name=^${containerName}$" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
