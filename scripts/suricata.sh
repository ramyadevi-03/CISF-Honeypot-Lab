#!/usr/bin/env bash
# ------------------------------------------------------------
# suricata.sh – Bash equivalent of scripts/suricata.ps1
# Supports: up, down, status, test
# Usage: ./suricata.sh <action>
#   action: up|down|status|test (default: up)
# ------------------------------------------------------------

set -euo pipefail

ACTION="up"

if [[ $# -ge 1 ]]; then
    ACTION="$1"
fi

case "$ACTION" in
    up|down|status|test) ;;
    *) echo "Invalid action: $ACTION" >&2; exit 1;;
esac

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/compose.suricata.yaml"
PROJECT="cisf-suricata"
EVE_FILE="$ROOT_DIR/suricata/logs/eve.json"
FAST_FILE="$ROOT_DIR/suricata/logs/fast.log"

invoke_compose() {
    docker compose --project-name "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

case "$ACTION" in
    up)
        invoke_compose up --detach
        invoke_compose ps
        ;;
    down)
        invoke_compose down
        ;;
    status)
        invoke_compose ps
        docker network inspect cisf-lab-net --format 'Network={{.Name}} Internal={{.Internal}} Subnet={{(index .IPAM.Config 0).Subnet}}'
        ;;
    test)
        # Verify required containers are running
        for c in kali-01 kali-02 cisf-lab-target cisf-suricata; do
            running=$(docker inspect --format '{{.State.Running}}' "$c" 2>/dev/null || echo "false")
            if [[ "$running" != "true" ]]; then
                echo "Container $c is not running. Start lab and suricata first." >&2
                exit 1
            fi
        done
        for participant in kali-01 kali-02; do
            if [[ "$participant" == "kali-01" ]]; then
                expected_ip="10.77.0.11"
            else
                expected_ip="10.77.0.12"
            fi
            actual_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$participant")
            if [[ "$actual_ip" != "$expected_ip" ]]; then
                echo "$participant IP mismatch: expected $expected_ip got $actual_ip" >&2
                exit 1
            fi
        done
        # Verify network configuration
        net=$(docker network inspect cisf-lab-net --format '{{.Internal}}|{{(index .IPAM.Config 0).Subnet}}')
        if [[ "$net" != "true|10.77.0.0/24" ]]; then
            echo "Unexpected network configuration: $net" >&2
            exit 1
        fi
        # Verify target IP
        target_ip=$(docker inspect cisf-lab-target --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
        if [[ "$target_ip" != "10.77.0.10" ]]; then
            echo "Target IP mismatch: expected 10.77.0.10 got $target_ip" >&2
            exit 1
        fi

        eve_baseline=0
        fast_baseline=0
        if [[ -f "$EVE_FILE" ]]; then
            eve_baseline=$(wc -l < "$EVE_FILE")
        fi
        if [[ -f "$FAST_FILE" ]]; then
            fast_baseline=$(wc -l < "$FAST_FILE")
        fi

        marker1="cisf-suricata-test-kali-01-${$}-${RANDOM}"
        marker2="cisf-suricata-test-kali-02-${$}-${RANDOM}"
        if ! curl_code=$(docker exec kali-01 curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 5 "http://10.77.0.10:8080/?$marker1"); then
            echo "HTTP test failed from kali-01 (curl status $curl_code)" >&2
            exit 1
        fi
        if [[ "$curl_code" != "200" ]]; then
            echo "HTTP test failed from kali-01, status $curl_code" >&2
            exit 1
        fi
        echo "PASS kali-01 (10.77.0.11) HTTP request returned $curl_code"

        if ! curl_code=$(docker exec kali-02 curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 5 "http://10.77.0.10:8080/?$marker2"); then
            echo "HTTP test failed from kali-02 (curl status $curl_code)" >&2
            exit 1
        fi
        if [[ "$curl_code" != "200" ]]; then
            echo "HTTP test failed, status $curl_code" >&2
            exit 1
        fi
        echo "PASS kali-02 (10.77.0.12) HTTP request returned $curl_code"

        has_eve_http() {
            local source_ip="$1"
            local marker="$2"
            [[ -f "$EVE_FILE" ]] &&
                tail -n "+$((eve_baseline + 1))" "$EVE_FILE" |
                    grep -F '"event_type":"http"' |
                    grep -F "$source_ip" |
                    grep -F "$marker" >/dev/null
        }

        has_eve_alert() {
            local source_ip="$1"
            [[ -f "$EVE_FILE" ]] &&
                tail -n "+$((eve_baseline + 1))" "$EVE_FILE" |
                    grep -F '"event_type":"alert"' |
                    grep -F '"signature_id":1000001' |
                    grep -F "$source_ip" >/dev/null
        }

        has_fast_alert() {
            local source_ip="$1"
            [[ -f "$FAST_FILE" ]] &&
                tail -n "+$((fast_baseline + 1))" "$FAST_FILE" |
                    grep -F "$source_ip" |
                    grep -F 'CISF lab HTTP test request' >/dev/null
        }

        deadline=$((SECONDS + 20))
        logs_ready=false
        while (( SECONDS < deadline )); do
            if has_eve_http 10.77.0.11 "$marker1" &&
                has_eve_alert 10.77.0.11 &&
                has_fast_alert 10.77.0.11 &&
                has_eve_http 10.77.0.12 "$marker2" &&
                has_eve_alert 10.77.0.12 &&
                has_fast_alert 10.77.0.12; then
                logs_ready=true
                break
            fi
            sleep 0.5
        done

        if [[ "$logs_ready" != true ]]; then
            echo "Suricata did not log HTTP and SID 1000001 alerts for both Kali source IPs." >&2
            for source_ip in 10.77.0.11 10.77.0.12; do
                if [[ "$source_ip" == "10.77.0.11" ]]; then
                    marker="$marker1"
                else
                    marker="$marker2"
                fi
                has_eve_http "$source_ip" "$marker" || echo "Missing eve.json HTTP event for $source_ip" >&2
                has_eve_alert "$source_ip" || echo "Missing eve.json SID 1000001 alert for $source_ip" >&2
                has_fast_alert "$source_ip" || echo "Missing fast.log alert for $source_ip" >&2
            done
            exit 1
        fi

        echo "PASS eve.json HTTP events and SID 1000001 alerts for 10.77.0.11 and 10.77.0.12"
        echo "PASS fast.log alerts for 10.77.0.11 and 10.77.0.12"
        ;;
esac
