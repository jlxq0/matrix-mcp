#!/usr/bin/env bash
# scripts/qa/chaos-pod-kill.sh — Phase 10.5 chaos-engineering scaffold
#
# PURPOSE
# -------
# Simulate an abrupt pod kill while matrix-mcp is serving active tool calls,
# then verify that:
#   1. The Deployment controller replaces the pod within the expected time
#      (default: < 30 s including readiness probe).
#   2. In-flight tool calls return a clear error (not a hang or silent failure)
#      to the MCP client.
#   3. After pod replacement, new tool calls succeed (no zombie sessions,
#      no corrupted SQLite stores).
#   4. The Prometheus counter `matrix_mcp_tool_calls_total{outcome="error"}`
#      increments appropriately (not "ok") for the killed-pod calls.
#
# This script is a SKELETON. The actual chaos loop has not been implemented.
# The comments below describe the intended approach. Implement before the
# first scheduled chaos drill.
#
# PREREQUISITES
# -------------
#   - kubectl configured for the target cluster (gruyere or local).
#   - A running matrix-mcp pod in the target namespace.
#   - An active load generator running in the background (see load.sh) so
#     there are in-flight tool calls at the moment of the kill.
#   - `jq` for JSON parsing.
#   - KUBECONFIG pointing at the target cluster.
#
# USAGE
# -----
#   # Against the staging/beta deployment:
#   NAMESPACE=matrix-mcp-beta bash scripts/qa/chaos-pod-kill.sh
#
#   # Against the production deployment (use with extreme caution):
#   NAMESPACE=matrix-mcp bash scripts/qa/chaos-pod-kill.sh --confirm-prod
#
# SAFETY GUARDS
# -------------
# This script MUST NOT be run against the production deployment without an
# explicit --confirm-prod flag AND a second operator confirming via the
# Slack/Matrix ops channel. Production traffic is real users.
#
# IMPLEMENTATION NOTES
# --------------------
#
# 1. BASELINE HEALTH CHECK
#    Verify the pod is Running and passes /health before starting.
#    Abort if the health check fails — we do not want to chaos an already-
#    degraded deployment.
#
# 2. START BACKGROUND LOAD (optional — caller may run load.sh separately)
#    If --with-load is passed, start load.sh in the background:
#      bash scripts/qa/load.sh --target "$TARGET" --users 3 --duration 120 &
#      LOAD_PID=$!
#
# 3. RECORD BASELINE METRICS
#    Capture the current value of matrix_mcp_tool_calls_total{outcome="ok"}
#    and {outcome="error"} from the Prometheus/VictoriaMetrics endpoint.
#
# 4. KILL THE POD
#    kubectl -n "$NAMESPACE" delete pod -l app=matrix-mcp --grace-period=0
#    Record the timestamp.
#
# 5. WAIT FOR REPLACEMENT
#    Poll until a new pod is Running and passes /health.
#    Fail if this takes > 60 s.
#    Record the actual recovery time.
#
# 6. VERIFY METRICS
#    After recovery:
#      - error counter should have incremented (killed-pod calls hit error path)
#      - ok counter should be increasing again (new pod is healthy)
#      - No goroutine/goroutine leak in the new pod's metrics
#
# 7. PRINT SUMMARY
#    Recovery time, error count delta, ok count delta.
#
# TODO: implement steps 2–7.

set -euo pipefail

# ── configuration ──────────────────────────────────────────────────────────

NAMESPACE="${NAMESPACE:-matrix-mcp-beta}"
CONFIRM_PROD=false
MAX_RECOVERY_SECONDS=60

while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm-prod) CONFIRM_PROD=true; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ── safety guard ───────────────────────────────────────────────────────────

if [[ "$NAMESPACE" == "matrix-mcp" && "$CONFIRM_PROD" != "true" ]]; then
    echo "ERROR: namespace is '$NAMESPACE' (production)." >&2
    echo "Pass --confirm-prod to acknowledge you are chaos-testing production." >&2
    echo "This requires second-operator sign-off in the ops channel." >&2
    exit 1
fi

# ── prerequisite checks ───────────────────────────────────────────────────

if ! command -v kubectl &>/dev/null; then
    echo "ERROR: kubectl is not installed or not in PATH." >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required." >&2
    exit 1
fi

# ── 1. baseline health check ──────────────────────────────────────────────

echo "==> Checking baseline pod health in namespace: $NAMESPACE"
kubectl -n "$NAMESPACE" get pods -l app=matrix-mcp

# TODO: extract pod name and verify /health returns 200.
echo ""
echo "TODO: chaos-pod-kill logic not implemented yet."
echo "See the implementation notes in this script."
echo ""
echo "Manual procedure:"
echo "  1. kubectl -n $NAMESPACE delete pod -l app=matrix-mcp --grace-period=0"
echo "  2. Watch: kubectl -n $NAMESPACE get pods -w"
echo "  3. Verify health: curl https://matrix-mcp.example.com/health"
echo "  4. Check error metrics in Grafana (matrix_mcp_tool_calls_total)."
echo "  Recovery target: < ${MAX_RECOVERY_SECONDS} s"

exit 0
