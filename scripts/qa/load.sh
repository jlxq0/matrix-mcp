#!/usr/bin/env bash
# scripts/qa/load.sh — Phase 10.2 load-test scaffold
#
# PURPOSE
# -------
# Drive a sustained sequence of MCP tool calls against a matrix-mcp endpoint
# and print p50/p99 latency percentiles at the end. Results should be used to
# fill in the "Performance baseline" table in docs/operations.md.
#
# This script is a SKELETON. The actual load-generation logic has not been
# implemented. The comments below describe the intended approach and the
# prerequisites. Implement before the first production load test.
#
# PREREQUISITES
# -------------
#   - A running matrix-mcp endpoint reachable from this machine (staging or
#     a local ngrok tunnel). See INTEGRATION.md for the local bring-up
#     procedure.
#   - A valid bearer token issued by MAS for a test user (see INTEGRATION.md §
#     "Issue a test token").
#   - `oha` or `hey` for HTTP benchmarking, or `wrk` with a Lua script.
#     Install: brew install oha   (macOS)
#              cargo install oha  (cross-platform)
#   - `jq` for JSON extraction.
#
# USAGE
# -----
#   bash scripts/qa/load.sh \
#     --target  https://matrix-mcp-staging.example.com \
#     --token   <bearer-token> \
#     --users   10 \
#     --duration 60
#
# OUTPUTS
# -------
# Prints a summary table of p50 / p99 / p999 latencies (in ms) per tool call
# type. Expected columns:
#   tool | requests | p50_ms | p99_ms | p999_ms | errors
#
# IMPLEMENTATION NOTES
# --------------------
#
# 1. WARMUP PHASE (30 s)
#    Send requests at 10 % of target rate to warm up the MCP session,
#    prime the MAS introspection cache, and pre-load the E2EE key store.
#    Discard warmup results.
#
# 2. READ TOOLS (parallel, N=--users virtual users)
#    For each virtual user:
#      a. POST /mcp { method: "initialize" }   — once per user
#      b. Loop for --duration seconds:
#           POST /mcp { method: "tools/call", params: { name: "whoami" } }
#           POST /mcp { method: "tools/call", params: { name: "list_joined_rooms" } }
#           POST /mcp { method: "tools/call",
#                       params: { name: "read_recent_messages",
#                                 arguments: { room_id: "$TEST_ROOM" } } }
#
# 3. WRITE TOOLS (sequential, 1 virtual user)
#    Write tools must be tested at lower concurrency to avoid Synapse
#    per-device rate limits:
#      - send_text_message (one per 2 s)
#    Do NOT test write tools at high concurrency — they modify real room state.
#    Use a dedicated test room that can be cleared after the test.
#
# 4. RESULTS
#    Record raw latency samples from oha/hey JSON output, extract p50/p99,
#    and print the summary table.
#
# TODO: implement above using oha or hey + jq pipeline.
#
# EXAMPLE oha INVOCATION (reference, not wired up yet):
#
#   oha --no-tui -z "${DURATION}s" -c "${USERS}" \
#     -H "Authorization: Bearer ${TOKEN}" \
#     -H "Content-Type: application/json" \
#     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}' \
#     --json \
#     "${TARGET}/mcp" \
#   | jq '{p50: .latencyPercentiles.p50, p99: .latencyPercentiles.p99}'
#

set -euo pipefail

# ── argument parsing ────────────────────────────────────────────────────────

TARGET=""
TOKEN=""
USERS=5
DURATION=60

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)   TARGET="$2";   shift 2 ;;
        --token)    TOKEN="$2";    shift 2 ;;
        --users)    USERS="$2";    shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "ERROR: --target is required" >&2
    echo "Usage: $0 --target <url> [--token <bearer>] [--users N] [--duration S]" >&2
    exit 1
fi

# ── prerequisite checks ────────────────────────────────────────────────────

if ! command -v oha &>/dev/null && ! command -v hey &>/dev/null; then
    echo "ERROR: neither 'oha' nor 'hey' is installed." >&2
    echo "  Install: brew install oha   or   cargo install oha" >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: 'jq' is required." >&2
    exit 1
fi

# ── TODO: implement load generation ───────────────────────────────────────

echo "matrix-mcp load test scaffold"
echo "  target:   $TARGET"
echo "  users:    $USERS"
echo "  duration: ${DURATION}s"
echo ""
echo "TODO: load generation not implemented yet."
echo "See the comments in this script for the intended approach."
echo ""
echo "Manually run the oha example from the comments above to get"
echo "initial p50/p99 numbers and paste them into docs/operations.md."

exit 0
