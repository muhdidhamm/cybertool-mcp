#!/bin/bash
# Unified ThreatLens MCP Server - Build Script for Linux/macOS
# Run: chmod +x build.sh && ./build.sh

set -e

echo "================================================="
echo "  Unified ThreatLens MCP Server - Docker Build"
echo "================================================="
echo ""

echo "[1/3] Building Docker image (this will take 10-20 minutes on first run)..."
docker build -t ghcr.io/muhdidhamm/cybertool-mcp-server:latest .

echo ""
echo "[2/3] Verifying image..."
docker images ghcr.io/muhdidhamm/cybertool-mcp-server:latest

echo ""
echo "[3/3] Testing quick startup..."
docker run --rm ghcr.io/muhdidhamm/cybertool-mcp-server:latest bash -c \
    "python3 -c 'from tools import register_all_tools; print(\"All tool modules loaded OK\")'"

echo ""
echo "================================================="
echo "  Build complete!"
echo "================================================="
echo ""
echo "Next steps:"
echo "  1. Copy claude_desktop_config.json content to your Claude Desktop config"
echo "     macOS:  ~/Library/Application Support/Claude/claude_desktop_config.json"
echo "     Linux:  ~/.config/Claude/claude_desktop_config.json"
echo "     Windows: %APPDATA%\\Claude\\claude_desktop_config.json"
echo "  2. Restart Claude Desktop"
echo "  3. The cybertool-mcp tools should appear in Claude Desktop"
echo ""
