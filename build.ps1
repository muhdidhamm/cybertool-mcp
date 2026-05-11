# Unified ThreatLens MCP Server - Build Script for Windows (PowerShell)
# Run: .\build.ps1

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Unified ThreatLens MCP Server - Docker Build" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Building Docker image (this will take 10-20 minutes on first run)..." -ForegroundColor Yellow
docker build -t github.com/mcp/cybertool-mcp-server:latest .

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Verifying image..." -ForegroundColor Yellow
docker images github.com/mcp/cybertool-mcp-server:latest

Write-Host ""
Write-Host "[3/3] Testing quick startup..." -ForegroundColor Yellow
$testResult = docker run -e AUTO_UPDATE=never --rm github.com/mcp/cybertool-mcp-server:latest bash -c "python3 -c 'from tools import register_all_tools; print(\"All tool modules loaded OK\")'"
Write-Host $testResult

Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "  Build complete!" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy claude_desktop_config.json content to your Claude Desktop config"
Write-Host "     Location: %APPDATA%\Claude\claude_desktop_config.json"
Write-Host "  2. Restart Claude Desktop"
Write-Host "  3. The cybertool-mcp tools should appear in Claude Desktop"
Write-Host ""
