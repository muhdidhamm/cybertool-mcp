#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="cybertool-mcp-stream"

if ! docker ps -aq --filter "name=^${CONTAINER_NAME}$" | grep -q .; then
  echo "Container not found: ${CONTAINER_NAME}"
  exit 0
fi

echo "Stopping and removing container: ${CONTAINER_NAME}"
docker rm -f "${CONTAINER_NAME}" >/dev/null
echo "Done."
