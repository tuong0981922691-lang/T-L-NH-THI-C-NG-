#!/usr/bin/env bash
set -euo pipefail
WORKER_ID="${WORKER_ID:-${HOSTNAME:-unknown-worker}}"
MANAGER_URL="${MANAGER_URL:-http://octopus-manager.default.svc.cluster.local:8080}"
MANAGER_TOKEN="${MANAGER_TOKEN:-}"
CURL_TIMEOUT="${CURL_TIMEOUT:-2}"
child_pid=0
_notify_manager() {
  rc="$1"
  reason="$2"
  ts="$(date +%s)"
  payload=$(printf '{"worker_id":"%s","reason":"%s","exit_code":%d,"ts":%d}' "$WORKER_ID" "$reason" "$rc" "$ts")
  if [ -n "${MANAGER_TOKEN}" ]; then
    curl --max-time "${CURL_TIMEOUT}" -sS -X POST "${MANAGER_URL%/}/worker_exit" \
      -H "Content-Type: application/json" \
      -H "X-Manager-Token: ${MANAGER_TOKEN}" \
      -d "${payload}" >/dev/null 2>&1 || true
  else
    curl --max-time "${CURL_TIMEOUT}" -sS -X POST "${MANAGER_URL%/}/worker_exit" \
      -H "Content-Type: application/json" \
      -d "${payload}" >/dev/null 2>&1 || true
  fi
}
_term_handler() {
  sig="$1"
  if [ "${child_pid}" -ne 0 ] && kill -0 "${child_pid}" >/dev/null 2>&1; then
    kill -s TERM "${child_pid}" >/dev/null 2>&1 || true
  fi
  wait "${child_pid}" 2>/dev/null || true
  rc=$?
  _notify_manager "${rc}" "signal_${sig}"
  exit "${rc}"
}
trap '_term_handler TERM' TERM
trap '_term_handler INT' INT
if [ "$#" -eq 0 ]; then
  echo "No command specified" >&2
  exit 1
fi
"$@" &
child_pid=$!
wait "${child_pid}"
rc=$?
if [ "${rc}" -ne 0 ]; then
  _notify_manager "${rc}" "exit_code_${rc}"
fi
exit "${rc}"
