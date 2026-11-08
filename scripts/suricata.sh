#!/usr/bin/env bash
# ------------------------------------------------------------
# suricata.sh – manage the Cowrie and Suricata overlay
# Supports: up, down, status, test
# Usage: ./suricata.sh <action>
# ------------------------------------------------------------

set -euo pipefail

ACTION="${1:-up}"

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

line_count() {
    if [[ -f "$1" ]]; then wc -l < "$1"; else echo 0; fi
}

cowrie_events() {
    docker exec cisf-cowrie /cowrie/cowrie-env/bin/python3 -c \
        'from pathlib import Path; print(Path("/cowrie/cowrie-git/var/log/cowrie/cowrie.json").read_text(), end="")'
}

case "$ACTION" in
    up)
        invoke_compose up --detach --remove-orphans
        invoke_compose ps
        ;;
    down)
        invoke_compose down --remove-orphans
        ;;
    status)
        invoke_compose ps
        docker network inspect cisf-lab-net --format 'Network={{.Name}} Internal={{.Internal}} Subnet={{(index .IPAM.Config 0).Subnet}}'
        ;;
    test)
        for container in kali-01 kali-02 cisf-cowrie cisf-suricata; do
            running=$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || echo "false")
            if [[ "$running" != "true" ]]; then
                echo "Container $container is not running. Start the Kali lab and Cowrie/Suricata first." >&2
                exit 1
            fi
        done

        network=$(docker network inspect cisf-lab-net --format '{{.Internal}}|{{(index .IPAM.Config 0).Subnet}}')
        if [[ "$network" != "true|10.77.0.0/24" ]]; then
            echo "Unexpected network configuration: $network" >&2
            exit 1
        fi

        for pair in "kali-01:10.77.0.11" "kali-02:10.77.0.12" "cisf-cowrie:10.77.0.10"; do
            name="${pair%%:*}"
            expected_ip="${pair#*:}"
            actual_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
            if [[ "$actual_ip" != "$expected_ip" ]]; then
                echo "$name IP mismatch: expected $expected_ip got $actual_ip" >&2
                exit 1
            fi
        done

        telnet_enabled=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' cisf-cowrie |
            grep -Fx 'COWRIE_TELNET_ENABLED=yes' || true)
        if [[ "$telnet_enabled" != "COWRIE_TELNET_ENABLED=yes" ]]; then
            echo "Cowrie Telnet is not explicitly enabled." >&2
            exit 1
        fi

        published_ports=$(docker inspect --format '{{json .HostConfig.PortBindings}}' cisf-cowrie)
        if [[ "$published_ports" != "null" && "$published_ports" != "{}" ]]; then
            echo "Cowrie must not publish host ports: $published_ports" >&2
            exit 1
        fi
        cowrie_id=$(docker inspect --format '{{.Id}}' cisf-cowrie)
        sensor_network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' cisf-suricata)
        if [[ "$sensor_network_mode" != "container:$cowrie_id" ]]; then
            echo "Suricata is not sharing Cowrie's network namespace: $sensor_network_mode" >&2
            exit 1
        fi

        cowrie_id=$(docker inspect --format '{{.Id}}' cisf-cowrie)
        sensor_network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' cisf-suricata)
        if [[ "$sensor_network_mode" != "container:$cowrie_id" ]]; then
            echo "Suricata is not sharing Cowrie's network namespace: $sensor_network_mode" >&2
            exit 1
        fi

        cowrie_baseline=$(cowrie_events | wc -l)
        eve_baseline=$(line_count "$EVE_FILE")
        fast_baseline=$(line_count "$FAST_FILE")

        for pair in "kali-01:10.77.0.11" "kali-02:10.77.0.12"; do
            participant="${pair%%:*}"
            source_ip="${pair#*:}"

            ssh_keys=$(docker exec "$participant" ssh-keyscan -T 5 -p 2222 10.77.0.10 2>/dev/null || true)
            if [[ -z "$ssh_keys" ]]; then
                echo "SSH handshake failed from $participant ($source_ip) to 10.77.0.10:2222." >&2
                exit 1
            fi
            echo "PASS SSH handshake from $participant ($source_ip) to 10.77.0.10:2222"

            if ! docker exec "$participant" bash -c \
                'exec 3<>/dev/tcp/10.77.0.10/2223; read -r -t 5 -N 1 -u 3 negotiation; [[ -n "$negotiation" ]]'; then
                echo "Telnet protocol test failed from $participant ($source_ip) to 10.77.0.10:2223." >&2
                exit 1
            fi
            echo "PASS Telnet negotiation from $participant ($source_ip) to 10.77.0.10:2223"
        done

        has_cowrie_session() {
            local source_ip="$1"
            local protocol="$2"
            local destination_port="$3"
            cowrie_events |
                tail -n "+$((cowrie_baseline + 1))" |
                grep -F '"eventid":"cowrie.session.connect"' |
                grep -F '"protocol":"'"$protocol"'"' |
                grep -F '"src_ip":"'"$source_ip"'"' |
                grep -F '"dst_port":'"$destination_port" >/dev/null
        }

        has_suricata_alert() {
            local source_ip="$1"
            local destination_port="$2"
            local signature_id="$3"
            [[ -f "$EVE_FILE" ]] &&
                tail -n "+$((eve_baseline + 1))" "$EVE_FILE" |
                    grep -E '"event_type"[[:space:]]*:[[:space:]]*"alert"' |
                    grep -E '"signature_id"[[:space:]]*:[[:space:]]*'"$signature_id" |
                    grep -E '"src_ip"[[:space:]]*:[[:space:]]*"'"$source_ip"'"' |
                    grep -E '"dest_port"[[:space:]]*:[[:space:]]*'"$destination_port" >/dev/null
        }

        has_fast_alert() {
            local source_ip="$1"
            local destination_port="$2"
            local signature="$3"
            [[ -f "$FAST_FILE" ]] &&
                tail -n "+$((fast_baseline + 1))" "$FAST_FILE" |
                    grep -F "$signature" |
                    grep -F "$source_ip" |
                    grep -F -- "-> 10.77.0.10:$destination_port" >/dev/null
        }

        deadline=$((SECONDS + 20))
        logs_ready=false
        while (( SECONDS < deadline )); do
            logs_ready=true
            for source_ip in 10.77.0.11 10.77.0.12; do
                if ! has_cowrie_session "$source_ip" ssh 2222 ||
                    ! has_cowrie_session "$source_ip" telnet 2223 ||
                    ! has_suricata_alert "$source_ip" 2222 1000002 ||
                    ! has_suricata_alert "$source_ip" 2223 1000003 ||
                    ! has_fast_alert "$source_ip" 2222 'CISF Cowrie SSH connection' ||
                    ! has_fast_alert "$source_ip" 2223 'CISF Cowrie Telnet connection'; then
                    logs_ready=false
                    break
                fi
            done
            if [[ "$logs_ready" == true ]]; then break; fi
            sleep 0.5
        done

        if [[ "$logs_ready" != true ]]; then
            echo "Missing Cowrie session or Suricata SSH/Telnet alert events for one or more participant IPs." >&2
            exit 1
        fi

        for source_ip in 10.77.0.11 10.77.0.12; do
            echo "PASS Cowrie logged SSH and Telnet sessions from $source_ip"
            echo "PASS Suricata logged SSH (SID 1000002) and Telnet (SID 1000003) alerts from $source_ip"
        done
        ;;
esac
