#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -lt 1 || $# -gt 3 ]]; then
    echo "Usage: $0 <exercise-start-utc> [exercise-end-utc-exclusive] [destination-filename]" >&2
    echo "Example: $0 2026-11-10T09:00:00Z 2026-11-10T09:30:00Z lab6-mixed-evidence.tsv" >&2
    exit 2
fi

EXERCISE_START_UTC="$1"
EXERCISE_END_UTC="${2:-}"
OUTPUT_FILENAME="${3:-lab6-mixed-evidence.tsv}"
if [[ ! "$OUTPUT_FILENAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "Destination filename must be a simple filename without a path." >&2
    exit 2
fi

IFS=':' read -ra PATH_SEGMENTS <<< "$PATH"
new_path=""
for segment in "${PATH_SEGMENTS[@]}"; do
    if [[ "$segment" != "/c/Users/Lenovo/AppData/Local/Microsoft/WindowsApps" ]]; then
        new_path="${new_path}${new_path:+:}$segment"
    fi
done
export PATH="$new_path"

PYTHON_BIN=""
for candidate in python py python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done
if [[ -z "$PYTHON_BIN" ]]; then
    for candidate in \
        "/c/Users/Lenovo/AppData/Local/Programs/Python/Python313/python.exe" \
        "/c/Users/Lenovo/AppData/Local/Microsoft/WindowsApps/python.exe" \
        "/c/Users/Lenovo/AppData/Local/Microsoft/WindowsApps/python3.exe"; do
        if [[ -x "$candidate" ]]; then
            PYTHON_BIN="$candidate"
            break
        fi
    done
fi
if [[ -z "$PYTHON_BIN" ]]; then
    echo "Python is required to export mixed Lab 6 evidence." >&2
    exit 1
fi

DOCKER_BIN="docker"
if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
    for candidate in \
        "/c/Program Files/Docker/Docker/resources/bin/docker.exe" \
        "/c/Program Files/Docker/Docker/docker.exe"; do
        if [[ -x "$candidate" ]]; then
            DOCKER_BIN="$candidate"
            break
        fi
    done
fi
if [[ "$DOCKER_BIN" == "docker" ]] && ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
    echo "Docker is required to export mixed Lab 6 evidence." >&2
    exit 1
fi
export DOCKER_BIN

umask 077
TMP_DIR=$(mktemp -d)
declare -a REMOTE_TEMPS=()
cleanup() {
    local remote_temp_entry container_name remote_temp
    for remote_temp_entry in "${REMOTE_TEMPS[@]}"; do
        container_name=${remote_temp_entry%%:*}
        remote_temp=${remote_temp_entry#*:}
        if ! "$DOCKER_BIN" exec "$container_name" rm -f "$remote_temp" >/dev/null 2>&1; then
            echo "Warning: could not remove temporary evidence file from ${container_name}." >&2
        fi
    done
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mapfile -t PARTICIPANTS < <(
    "$DOCKER_BIN" ps --filter network=cisf-lab-net --format '{{.Names}}' |
        grep -E '^kali-[0-9]+$' |
        sort -V
)
if (( ${#PARTICIPANTS[@]} < 2 )); then
    echo "At least two running Kali participants on cisf-lab-net are required." >&2
    exit 1
fi

declare -a PARTICIPANT_IPS=()
for container_name in "${PARTICIPANTS[@]}"; do
    participant_ip=$("$DOCKER_BIN" inspect --format \
        '{{with index .NetworkSettings.Networks "cisf-lab-net"}}{{.IPAddress}}{{end}}' \
        "$container_name")
    if [[ ! "$participant_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "${container_name} has no IPv4 address on cisf-lab-net." >&2
        exit 1
    fi
    PARTICIPANT_IPS+=("$participant_ip")
done

if [[ $(printf '%s\n' "${PARTICIPANT_IPS[@]}" | sort -u | wc -l) -ne ${#PARTICIPANT_IPS[@]} ]]; then
    echo "Multiple participant containers have the same cisf-lab-net IP." >&2
    exit 1
fi

DESTINATION_PATH="/tmp/${OUTPUT_FILENAME}"
for container_name in "${PARTICIPANTS[@]}"; do
    if "$DOCKER_BIN" exec "$container_name" test -e "$DESTINATION_PATH"; then
        echo "Refusing to overwrite existing ${container_name}:${DESTINATION_PATH}." >&2
        exit 1
    fi
done

if [[ ! -f "$ROOT_DIR/suricata/logs/eve.json" ]]; then
    echo "Suricata EVE log not found: $ROOT_DIR/suricata/logs/eve.json" >&2
    exit 1
fi
for container_name in cisf-cowrie cisf-opencanary; do
    running=$("$DOCKER_BIN" inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null || true)
    if [[ "$running" != "true" ]]; then
        echo "Required honeypot container is not running: $container_name" >&2
        exit 1
    fi
done

HOST_FILE="$TMP_DIR/$OUTPUT_FILENAME"
"$PYTHON_BIN" - "$ROOT_DIR" "$EXERCISE_START_UTC" "$EXERCISE_END_UTC" \
    "$HOST_FILE" "${PARTICIPANT_IPS[@]}" <<'PY'
import csv
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from pathlib import Path

root_dir = Path(sys.argv[1])
start_text = sys.argv[2]
end_text = sys.argv[3]
out_path = Path(sys.argv[4])
participant_ips = set(sys.argv[5:])
docker_bin = os.environ.get('DOCKER_BIN', 'docker')
target_ip = '10.77.0.10'

service_by_port = {
    21: 'ftp',
    80: 'http',
    2222: 'ssh',
    2223: 'telnet',
    3306: 'mysql',
}
signature_by_port = {
    21: 1000004,
    80: 1000005,
    2222: 1000002,
    2223: 1000003,
    3306: 1000006,
}
columns = [
    'dataset', 'timestamp', 'event_type', 'protocol', 'service',
    'src_ip', 'src_port', 'dest_ip', 'dest_port', 'signature_id',
    'signature', 'session', 'username', 'path', 'user_agent', 'outcome'
]

def parse_timestamp(value, assume_utc=False):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        if not assume_utc:
            return None
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def required_utc(value, label):
    parsed = parse_timestamp(value)
    if parsed is None:
        raise SystemExit(f'{label} must be an ISO-8601 timestamp with a timezone.')
    return parsed

start_time = required_utc(start_text, 'Exercise start')
end_time = required_utc(end_text, 'Exercise end') if end_text else None
if end_time and end_time <= start_time:
    raise SystemExit('Exercise end timestamp must be later than its start timestamp.')

def in_window(value, assume_utc=False):
    timestamp = parse_timestamp(value, assume_utc)
    return timestamp if timestamp and timestamp >= start_time and (
        end_time is None or timestamp < end_time
    ) else None

def safe_cell(value):
    if value is None:
        return ''
    return str(value).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')

def read_json_lines(text):
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj

def docker_log(container, *command):
    return subprocess.run(
        [docker_bin, 'exec', container, *command],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

def make_row(dataset, timestamp, event_type, protocol, service, source_ip,
             source_port, destination_ip, destination_port, signature_id='',
             signature='', session='', username='', path='', user_agent='',
             outcome=''):
    normalized = timestamp.astimezone(timezone.utc).isoformat(
        timespec='microseconds'
    ).replace('+00:00', 'Z')
    return {
        'dataset': dataset,
        'timestamp': normalized,
        'event_type': event_type,
        'protocol': protocol,
        'service': service,
        'src_ip': source_ip,
        'src_port': source_port,
        'dest_ip': destination_ip,
        'dest_port': destination_port,
        'signature_id': signature_id,
        'signature': signature,
        'session': session,
        'username': username,
        'path': path,
        'user_agent': user_agent,
        'outcome': outcome,
    }

rows = []
eve_path = root_dir / 'suricata' / 'logs' / 'eve.json'
for obj in read_json_lines(eve_path.read_text(encoding='utf-8')):
    source_ip = obj.get('src_ip')
    destination_ip = obj.get('dest_ip')
    destination_port = obj.get('dest_port')
    event_type = obj.get('event_type')
    if (
        source_ip not in participant_ips or destination_ip != target_ip or
        destination_port not in service_by_port or event_type not in {'alert', 'flow'}
    ):
        continue
    alert = obj.get('alert') or {}
    signature_id = alert.get('signature_id', '')
    if event_type == 'alert' and signature_id != signature_by_port[destination_port]:
        continue
    timestamp = in_window(obj.get('timestamp'))
    if timestamp is None:
        continue
    rows.append(make_row(
        'suricata', timestamp, event_type, obj.get('proto', ''),
        service_by_port[destination_port], source_ip, obj.get('src_port', ''),
        destination_ip, destination_port, signature_id,
        alert.get('signature', ''), outcome='alert' if event_type == 'alert' else 'flow',
    ))

opencanary_text = docker_log('cisf-opencanary', 'cat', '/var/tmp/opencanary.log')
allowed_canary_types = {2000, 2001, 3000, 8001, 9003}
canary_outcomes = {
    2000: 'authentication-attempt',
    2001: 'authentication-initiated',
    3000: 'request',
    8001: 'authentication-attempt',
    9003: 'connection',
}
for obj in read_json_lines(opencanary_text):
    source_ip = obj.get('src_host')
    destination_ip = obj.get('dst_host')
    destination_port = obj.get('dst_port')
    logtype = obj.get('logtype')
    if (
        source_ip not in participant_ips or destination_ip != target_ip or
        destination_port not in {21, 80, 3306} or logtype not in allowed_canary_types
    ):
        continue
    timestamp = in_window(obj.get('utc_time'), assume_utc=True)
    if timestamp is None:
        continue
    logdata = obj.get('logdata') or {}
    rows.append(make_row(
        'opencanary', timestamp, f'logtype_{logtype}',
        service_by_port[destination_port], service_by_port[destination_port],
        source_ip, obj.get('src_port', ''), destination_ip, destination_port,
        username=logdata.get('USERNAME', '') if logtype in {2000, 8001} else '',
        path=logdata.get('PATH', '') if logtype == 3000 else '',
        user_agent=logdata.get('USERAGENT', '') if logtype == 3000 else '',
        outcome=canary_outcomes[logtype],
    ))

cowrie_text = docker_log(
    'cisf-cowrie',
    '/cowrie/cowrie-env/bin/python3', '-c',
    'from pathlib import Path; print(Path("/cowrie/cowrie-git/var/log/cowrie/cowrie.json").read_text(), end="")',
)
allowed_cowrie_events = {
    'cowrie.session.connect',
    'cowrie.session.closed',
    'cowrie.login.success',
    'cowrie.login.failed',
}
cowrie_outcomes = {
    'cowrie.session.connect': 'connection',
    'cowrie.session.closed': 'disconnected',
    'cowrie.login.success': 'authentication-success',
    'cowrie.login.failed': 'authentication-failed',
}
for obj in read_json_lines(cowrie_text):
    source_ip = obj.get('src_ip')
    destination_ip = obj.get('dst_ip')
    destination_port = obj.get('dst_port')
    event_id = obj.get('eventid', '')
    if (
        source_ip not in participant_ips or destination_ip != target_ip or
        destination_port not in {2222, 2223} or event_id not in allowed_cowrie_events
    ):
        continue
    timestamp = in_window(obj.get('timestamp'))
    if timestamp is None:
        continue
    rows.append(make_row(
        'cowrie', timestamp, event_id, obj.get('protocol', ''),
        service_by_port[destination_port], source_ip, obj.get('src_port', ''),
        destination_ip, destination_port,
        session=obj.get('session', ''), username=obj.get('username', ''),
        outcome=cowrie_outcomes[event_id],
    ))

rows.sort(key=lambda row: (
    row['timestamp'], row['src_ip'], str(row['src_port']),
    row['dataset'], row['event_type'],
))
if not rows:
    raise SystemExit('No matching evidence found for the selected participants and time window.')
with out_path.open('w', encoding='utf-8', newline='') as output:
    writer = csv.writer(
        output, delimiter='\t', quoting=csv.QUOTE_NONE, escapechar='\\',
        lineterminator='\n',
    )
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(column, '')) for column in columns])

print(f'Generated {len(rows)} sanitized mixed records for {len(participant_ips)} participants.')
PY

for container_name in "${PARTICIPANTS[@]}"; do
    remote_temp="/tmp/.${OUTPUT_FILENAME}.tmp.$$.${RANDOM}"
    REMOTE_TEMPS+=("${container_name}:${remote_temp}")
    "$DOCKER_BIN" cp "$HOST_FILE" "${container_name}:${remote_temp}"
    if ! "$DOCKER_BIN" exec "$container_name" ln "$remote_temp" "$DESTINATION_PATH"; then
        echo "Could not install mixed evidence in ${container_name}; destination may already exist." >&2
        exit 1
    fi
    echo "Distributed combined sanitized evidence to ${container_name}:${DESTINATION_PATH}"
done
