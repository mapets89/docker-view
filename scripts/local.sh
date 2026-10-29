#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
state_dir=${DOCKERVIEW_LOCAL_STATE_DIR:-"$project_dir/.local"}

for command_name in go node npm openssl curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
done

if ! sh -c 'node --version; command_status=$?; exit $command_status' >/dev/null 2>&1 || \
   ! sh -c 'npm --version; command_status=$?; exit $command_status' >/dev/null 2>&1; then
  echo "Node.js or npm is installed but cannot run. Repair the local installation before continuing." >&2
  exit 1
fi

if [ ! -d "$project_dir/frontend/node_modules" ]; then
  echo "Frontend dependencies are missing. Run 'make local-setup' first." >&2
  exit 1
fi

mkdir -p "$state_dir"
gateway_secret=${DOCKERVIEW_GATEWAY_SECRET:-$(openssl rand -hex 32)}
pids=""

cleanup() {
  trap - EXIT INT TERM HUP
  for process_id in $pids; do
    kill "$process_id" >/dev/null 2>&1 || true
  done
  for process_id in $pids; do
    wait "$process_id" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

wait_for_ready() {
  process_id=$1
  ready_url=$2
  component_name=$3
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if ! kill -0 "$process_id" >/dev/null 2>&1; then
      echo "$component_name stopped before becoming ready. Review its output above." >&2
      return 1
    fi
    if curl --silent --fail --max-time 2 "$ready_url" >/dev/null; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "$component_name did not become ready at $ready_url." >&2
  return 1
}

(
  cd "$project_dir/backend"
  DOCKERVIEW_GATEWAY_LISTEN_ADDR=127.0.0.1:8081 \
  DOCKERVIEW_GATEWAY_SECRET="$gateway_secret" \
  go run ./cmd/gateway
) &
gateway_pid=$!
pids="$pids $gateway_pid"

if ! wait_for_ready "$gateway_pid" http://127.0.0.1:8081/ready Gateway; then
  echo "Confirm that Docker Engine is running and accessible." >&2
  exit 1
fi

(
  cd "$project_dir/backend"
  DOCKERVIEW_LISTEN_ADDR=127.0.0.1:8080 \
  DOCKERVIEW_DB_PATH="$state_dir/dockerview.db" \
  DOCKERVIEW_STATIC_DIR="$project_dir/frontend/dist" \
  DOCKERVIEW_GATEWAY_URL=http://127.0.0.1:8081 \
  DOCKERVIEW_GATEWAY_SECRET="$gateway_secret" \
  DOCKERVIEW_COOKIE_SECURE=false \
  DOCKERVIEW_ALLOWED_ORIGINS=http://localhost:4321,http://127.0.0.1:4321 \
  go run ./cmd/server
) &
server_pid=$!
pids="$pids $server_pid"

wait_for_ready "$server_pid" http://127.0.0.1:8080/ready Server

echo "DockerView development UI: http://localhost:4321"
echo "Server readiness:          http://127.0.0.1:8080/ready"
echo "Development data:          $state_dir"

(
  cd "$project_dir/frontend"
  DOCKERVIEW_LOCAL_SERVER_URL=http://127.0.0.1:8080 npm run dev
) &
frontend_pid=$!
pids="$pids $frontend_pid"
wait "$frontend_pid"
