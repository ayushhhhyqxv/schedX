#!/usr/bin/env bash
# MCP-Driven Linux Kernel Scheduler -- Service Launcher
# =====================================================
# Starts the Rust MCP Server and the Python AI Engine together.
#
# Usage:
#   ./launch.sh          # Start MCP server + AI engine in foreground
#   ./launch.sh status   # Check service health on port 8080

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_BIN="${PROJECT_DIR}/mcp-server/target/release/schedai-mcp"
AI_SCRIPT="${PROJECT_DIR}/ai-engine/main.py"

if [ "${1:-start}" = "status" ]; then
    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        echo "[STATUS] Rust MCP Server : ONLINE (http://localhost:8080)"
        curl -s http://localhost:8080/metrics | sed 's/^/  /'
    else
        echo "[STATUS] Rust MCP Server : OFFLINE"
    fi
    exit 0
fi

echo "=============================================================================="
echo "  MCP-DRIVEN LINUX KERNEL SCHEDULER -- SERVICE LAUNCHER"
echo "=============================================================================="

# Start the Rust MCP server if it is not already listening on port 8080
MCP_PID=""
if curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "[INFO] Rust MCP Server is already running on http://localhost:8080"
else
    echo "[INFO] Starting Rust MCP Server (${MCP_BIN})..."
    "${MCP_BIN}" > /tmp/schedai_mcp.log 2>&1 &
    MCP_PID=$!
    sleep 1.5
    echo "[OK]   Rust MCP Server listening on http://localhost:8080 (PID=${MCP_PID})"
fi

cleanup() {
    echo ""
    echo "[SHUTDOWN] Stopping services..."
    if [ -n "${MCP_PID}" ]; then
        kill "${MCP_PID}" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup INT TERM

echo "[INFO] Starting AI Scheduler Engine (${AI_SCRIPT})..."
python3 "${AI_SCRIPT}"
