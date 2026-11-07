#!/usr/bin/env bash
# ------------------------------------------------------------
# lab.sh – Bash equivalent of scripts/lab.ps1
# Supports: up, down, build, status, test
# Usage: ./lab.sh <action> [count]
#   action: up|down|build|status|test (default: up)
#   count: number of Kali participants (default: 2, max 244)
# ------------------------------------------------------------

set -euo pipefail

# Default values
ACTION="up"
COUNT=2

# Parse arguments (positional for simplicity, compatible with PowerShell script signature)
if [[ $# -ge 1 ]]; then
    ACTION="$1"
fi
if [[ $# -ge 2 ]]; then
    COUNT="$2"
fi

# Validate action
case "$ACTION" in
    up|down|build|status|test) ;;
    *) echo "Invalid action: $ACTION" >&2; exit 1;;
esac

# Validate count (must be integer and within limits)
if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
    echo "Count must be a positive integer" >&2; exit 1
fi
if (( COUNT < 2 || COUNT > 244 )); then
    echo "Count must be between 2 and 244 (available IPs in 10.77.0.0/24)" >&2; exit 1
fi

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/compose.yaml"
RUNTIME_FILE=$(mktemp -t cisf-kali.XXXXXX.yaml)
trap 'rm -f "$RUNTIME_FILE"' EXIT

# Generate temporary compose override with per‑participant services
generate_override() {
    cat > "$RUNTIME_FILE" <<EOF
services:
EOF
    for i in $(seq 1 "$COUNT"); do
        name=$(printf "kali-%02d" "$i")
        ip=$((10 + i))
        cat >> "$RUNTIME_FILE" <<EOP
  $name:
    extends:
      file: $COMPOSE_FILE
      service: kali-template
    container_name: $name
    profiles: [participants]
    networks:
      cisf-lab-net:
        ipv4_address: 10.77.0.$ip
EOP
    done
}

invoke_compose() {
    args=("--project-name" "cisf-kali" "-f" "$COMPOSE_FILE" "-f" "$RUNTIME_FILE" "$@")
    docker compose "${args[@]}"
}

generate_override

case "$ACTION" in
    build)
        invoke_compose --profile template build kali-template
        ;;
    up)
        invoke_compose --profile template build kali-template
        invoke_compose --profile participants up --detach --remove-orphans
        invoke_compose --profile participants ps
        ;;
    down)
        invoke_compose --profile participants down --remove-orphans
        ;;
    status)
        invoke_compose --profile participants ps
        for i in $(seq 1 "$COUNT"); do
            name=$(printf "kali-%02d" "$i")
            ip=$((10 + i))
            running=$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null || echo "false")
            actual_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null || true)
            echo "$name running=$running ip=${actual_ip:-unknown} expected_ip=10.77.0.$ip"
        done
        ;;
    test)
        invoke_compose --profile participants ps
        for i in $(seq 1 "$COUNT"); do
            name=$(printf "kali-%02d" "$i")
            ip=$((10 + i))
            running=$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null || true)
            actual_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null || true)
            if [[ "$running" != "true" || "$actual_ip" != "10.77.0.$ip" ]]; then
                echo "$name is not running with expected IP 10.77.0.$ip (running=$running ip=${actual_ip:-unknown})" >&2
                exit 1
            fi
        done

        for i in $(seq 1 "$COUNT"); do
            next=$((i % COUNT + 1))
            source=$(printf "kali-%02d" "$i")
            target=$(printf "kali-%02d" "$next")
            target_ip="10.77.0.$((10 + next))"
            if docker exec "$source" ping -c 2 -W 2 "$target_ip" > /dev/null 2>&1; then
                echo "PASS $source can reach $target ($target_ip)"
            else
                echo "FAIL $source cannot reach $target ($target_ip)" >&2
                exit 1
            fi
        done
        ;;
esac
