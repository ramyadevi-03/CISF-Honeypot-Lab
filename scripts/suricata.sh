#!/usr/bin/env bash
# Manage the shared Cowrie, OpenCanary, and Suricata overlay.
set -euo pipefail

ACTION="${1:-up}"
case "$ACTION" in
    up|down|status|test) ;;
    *) echo "Invalid action: $ACTION" >&2; exit 1 ;;
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

opencanary_events() {
    docker exec cisf-opencanary cat /var/tmp/opencanary.log
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
        for container in kali-01 kali-02 cisf-cowrie cisf-suricata cisf-opencanary; do
            running=$(docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null || echo "false")
            if [[ "$running" != "true" ]]; then
                echo "Container $container is not running. Start the Kali lab and honeypot overlay first." >&2
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

        cowrie_id=$(docker inspect --format '{{.Id}}' cisf-cowrie)
        for container in cisf-cowrie cisf-opencanary; do
            published_ports=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container")
            if [[ "$published_ports" != "null" && "$published_ports" != "{}" ]]; then
                echo "$container must not publish host ports: $published_ports" >&2
                exit 1
            fi
            network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$container")
            if [[ "$container" == "cisf-cowrie" ]]; then
                [[ "$network_mode" == "cisf-lab-net" ]] || {
                    echo "Cowrie is not attached directly to cisf-lab-net: $network_mode" >&2
                    exit 1
                }
            elif [[ "$network_mode" != "container:$cowrie_id" ]]; then
                echo "OpenCanary is not sharing Cowrie's network namespace: $network_mode" >&2
                exit 1
            fi
        done

        sensor_network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' cisf-suricata)
        if [[ "$sensor_network_mode" != "container:$cowrie_id" ]]; then
            echo "Suricata is not sharing Cowrie's network namespace: $sensor_network_mode" >&2
            exit 1
        fi

        cowrie_baseline=$(cowrie_events | wc -l)
        opencanary_baseline=$(opencanary_events | wc -l)
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

            if ! docker exec "$participant" bash -c '
                exec 3<>/dev/tcp/10.77.0.10/21
                IFS= read -r -t 5 -u 3 banner
                [[ "$banner" == 220* ]] || exit 1
                printf "USER cisf-user\r\n" >&3
                IFS= read -r -t 5 -u 3 user_reply
                [[ "$user_reply" == 331* ]] || exit 1
                printf "PASS incorrect-test-password\r\n" >&3
                IFS= read -r -t 5 -u 3 pass_reply
                [[ "$pass_reply" == 530* ]]
            '; then
                echo "FTP protocol/login test failed from $participant ($source_ip) to 10.77.0.10:21." >&2
                exit 1
            fi
            echo "PASS FTP banner and rejected login from $participant ($source_ip) to 10.77.0.10:21"

            http_result=$(docker exec "$participant" curl --fail --location --silent --show-error --max-time 5 \
                --output /dev/null --write-out '%{http_code}' http://10.77.0.10/)
            if [[ "$http_result" != "200" ]]; then
                echo "HTTP GET returned $http_result from $participant ($source_ip)." >&2
                exit 1
            fi
            echo "PASS HTTP GET returned 200 from $participant ($source_ip) to 10.77.0.10:80"

            mysql_probe='
                exec 3<>/dev/tcp/10.77.0.10/3306
                IFS= read -r -t 5 -N 1 -u 3 greeting
                [[ -n "$greeting" ]] || exit 1
                printf "\x30\x00\x00\x01\x85\xa2\x00\x00\x00\x00\x00\x00\x21" >&3
                printf "\0%.0s" {1..23} >&3
                printf "cisf-user\0\x05wrong" >&3
                read -r -t 5 -N 1 -u 3 response
                [[ -n "$response" ]]
            '
            if ! docker exec "$participant" bash -c "$mysql_probe"; then
                echo "MySQL handshake/authentication test failed from $participant ($source_ip) to 10.77.0.10:3306." >&2
                exit 1
            fi
            echo "PASS MySQL handshake and authentication attempt from $participant ($source_ip) to 10.77.0.10:3306"
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

        has_canary_event() {
            local source_ip="$1"
            local destination_port="$2"
            local logtype="$3"
            opencanary_events |
                tail -n "+$((opencanary_baseline + 1))" |
                grep -E "\"logtype\"[[:space:]]*:[[:space:]]*$logtype([,}])" |
                grep -E "\"src_host\"[[:space:]]*:[[:space:]]*\"$source_ip\"" |
                grep -E "\"dst_port\"[[:space:]]*:[[:space:]]*$destination_port([,}])" >/dev/null
        }

        has_suricata_alert() {
            local source_ip="$1"
            local destination_port="$2"
            local signature_id="$3"
            [[ -f "$EVE_FILE" ]] &&
                tail -n "+$((eve_baseline + 1))" "$EVE_FILE" |
                    grep -E '"event_type"[[:space:]]*:[[:space:]]*"alert"' |
                    grep -E "\"signature_id\"[[:space:]]*:[[:space:]]*$signature_id([,}])" |
                    grep -E "\"src_ip\"[[:space:]]*:[[:space:]]*\"$source_ip\"" |
                    grep -E "\"dest_port\"[[:space:]]*:[[:space:]]*$destination_port([,}])" >/dev/null
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

        deadline=$((SECONDS + 30))
        logs_ready=false
        while (( SECONDS < deadline )); do
            logs_ready=true
            for source_ip in 10.77.0.11 10.77.0.12; do
                for spec in "2222:1000002:2000:Cowrie SSH" "2223:1000003:2000:Cowrie Telnet" "21:1000004:2000:OpenCanary FTP" "80:1000005:3000:OpenCanary HTTP" "3306:1000006:8001:OpenCanary MySQL"; do
                    IFS=: read -r port sid logtype service <<< "$spec"
                    if ! has_suricata_alert "$source_ip" "$port" "$sid" ||
                        ! has_fast_alert "$source_ip" "$port" "CISF $service"; then
                        logs_ready=false
                        break
                    fi
                done
                if [[ "$logs_ready" != true ]] ||
                    ! has_cowrie_session "$source_ip" ssh 2222 ||
                    ! has_cowrie_session "$source_ip" telnet 2223 ||
                    ! has_canary_event "$source_ip" 21 2000 ||
                    ! has_canary_event "$source_ip" 80 3000 ||
                    ! has_canary_event "$source_ip" 3306 8001 ||
                    ! has_canary_event "$source_ip" 3306 9003; then
                    logs_ready=false
                    break
                fi
            done
            if [[ "$logs_ready" == true ]]; then break; fi
            sleep 0.5
        done

        if [[ "$logs_ready" != true ]]; then
            echo "Missing Cowrie, OpenCanary, or Suricata events for one or more participant IPs." >&2
            echo "OpenCanary baseline was $opencanary_baseline lines; inspect /var/tmp/opencanary.log in cisf-opencanary." >&2
            exit 1
        fi

        for source_ip in 10.77.0.11 10.77.0.12; do
            echo "PASS Cowrie logged SSH and Telnet sessions from $source_ip"
            echo "PASS OpenCanary logged FTP (2000), HTTP GET (3000), and MySQL login (8001) from $source_ip"
            echo "PASS Suricata logged SIDs 1000002-1000006 for the five services from $source_ip"
        done
        ;;
esac
