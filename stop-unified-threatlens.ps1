$ErrorActionPreference = "Stop"

$containerName = "unified-threatlens-stream"

$existing = docker ps -aq --filter "name=^${containerName}$"
if (-not $existing) {
    Write-Host "Container not found: $containerName"
    return
}

Write-Host "Stopping and removing container: $containerName"
docker rm -f $containerName | Out-Null
Write-Host "Done."
