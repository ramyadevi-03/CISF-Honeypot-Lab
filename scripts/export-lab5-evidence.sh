#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <exercise-start-utc>" >&2
    echo "Example: $0 2026-11-08T16:31:59Z" >&2
    exit 2
fi
EXERCISE_START_UTC="$1"
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
    echo "Python is required to export the Lab 5 evidence." >&2
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
    echo "Docker is required to export the Lab 5 evidence." >&2
    exit 1
fi
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if ! "$DOCKER_BIN" ps --format '{{.Names}}' | grep -qx 'kali-01'; then
    echo "Kali-01 is not running. Start the lab first." >&2
    exit 1
fi
if ! "$DOCKER_BIN" ps --format '{{.Names}}' | grep -qx 'kali-02'; then
    echo "Kali-02 is not running. Start the lab first." >&2
    exit 1
fi
export DOCKER_BIN

export_participant() {
    local src_ip="$1"
    local container_name="$2"
    local host_file="$TMP_DIR/${container_name}.tsv"

    "$PYTHON_BIN" - "$src_ip" "$host_file" "$ROOT_DIR" "$EXERCISE_START_UTC" <<'PY'
import csv
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from pathlib import Path

src_ip = sys.argv[1]
out_path = sys.argv[2]
root_dir = Path(sys.argv[3])
exercise_start_utc = sys.argv[4]
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

def normalized_timestamp(value):
    if not value:
        return ''
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')

since_timestamp = normalized_timestamp(exercise_start_utc)

def safe_cell(value):
    if value is None:
        return ''
    return str(value).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')

def read_json_lines(text):
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue

def base_row(dataset, timestamp, event_type, protocol, service, source_ip,
             source_port, destination_ip, destination_port, signature_id='',
             signature='', session='', username='', path='', user_agent='',
             outcome=''):
    return {
        'dataset': dataset,
        'timestamp': normalized_timestamp(timestamp),
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

with open(root_dir / 'suricata' / 'logs' / 'eve.json', 'r', encoding='utf-8') as fh:
    eve_text = fh.read()
eve_rows = []
for obj in read_json_lines(eve_text):
    dest_port = obj.get('dest_port')
    alert = obj.get('alert') or {}
    if (
        obj.get('event_type') != 'alert' or
        obj.get('src_ip') != src_ip or
        obj.get('dest_ip') != target_ip or
        dest_port not in service_by_port or
        alert.get('signature_id') != signature_by_port[dest_port]
    ):
        continue
    eve_rows.append(base_row(
        'suricata', obj.get('timestamp', ''), obj.get('event_type', ''),
        obj.get('proto', ''), service_by_port[dest_port], obj.get('src_ip', ''),
        obj.get('src_port', ''), obj.get('dest_ip', ''), dest_port,
        alert.get('signature_id', ''), alert.get('signature', ''), outcome='alert',
    ))

# Load OpenCanary JSON.
proc = subprocess.run(
    [docker_bin, 'exec', 'cisf-opencanary', 'cat', '/var/tmp/opencanary.log'],
    check=True,
    capture_output=True,
    text=True,
)
open_rows = []
for obj in read_json_lines(proc.stdout):
    dest_port = obj.get('dst_port')
    logtype = obj.get('logtype')
    if (
        obj.get('src_host') != src_ip or
        obj.get('dst_host') != target_ip or
        dest_port not in {21, 80, 3306} or
        logtype not in {2000, 2001, 3000, 8001, 9003}
    ):
        continue
    logdata = obj.get('logdata') or {}
    outcome_by_logtype = {
        2000: 'authentication-attempt',
        3000: 'request',
        8001: 'authentication-attempt',
        9003: 'connection',
    }
    open_rows.append(base_row(
        'opencanary', obj.get('utc_time', ''), f'logtype_{logtype}',
        service_by_port[dest_port], service_by_port[dest_port], obj.get('src_host', ''),
        obj.get('src_port', ''), obj.get('dst_host', ''), dest_port,
        username=logdata.get('USERNAME', '') if logtype in {2000, 8001} else '',
        path=logdata.get('PATH', '') if logtype == 3000 else '',
        user_agent=logdata.get('USERAGENT', '') if logtype == 3000 else '',
        outcome=outcome_by_logtype.get(logtype, 'application-event'),
    ))

# Load Cowrie JSON.
proc = subprocess.run(
    [
        docker_bin, 'exec', 'cisf-cowrie',
        '/cowrie/cowrie-env/bin/python3', '-c',
        'from pathlib import Path; print(Path("/cowrie/cowrie-git/var/log/cowrie/cowrie.json").read_text(), end="")'
    ],
    check=True,
    capture_output=True,
    text=True,
)
log_rows = []
for obj in read_json_lines(proc.stdout):
    dest_port = obj.get('dst_port')
    if (
        obj.get('src_ip') != src_ip or
        obj.get('dst_ip') != target_ip or
        dest_port not in {2222, 2223}
    ):
        continue
    eventid = obj.get('eventid', '')
    outcome_by_event = {
        'cowrie.session.connect': 'connection',
        'cowrie.session.closed': 'disconnected',
        'cowrie.login.success': 'authentication-success',
        'cowrie.login.failed': 'authentication-failed',
    }
    log_rows.append(base_row(
        'cowrie', obj.get('timestamp', ''), eventid, obj.get('protocol', ''),
        service_by_port[dest_port], obj.get('src_ip', ''), obj.get('src_port', ''),
        obj.get('dst_ip', ''), dest_port,
        session=obj.get('session', ''), username=obj.get('username', ''),
        outcome=outcome_by_event.get(eventid, 'application-event'),
    ))

rows = eve_rows + open_rows + log_rows
rows = [row for row in rows if row['timestamp'] and row['timestamp'] >= since_timestamp]
rows.sort(key=lambda row: row['timestamp'])

with open(out_path, 'w', encoding='utf-8', newline='') as fh:
    writer = csv.writer(fh, delimiter='\t', quoting=csv.QUOTE_NONE,
                        escapechar='\\',
                        lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(column, '')) for column in columns])
PY

    "$DOCKER_BIN" cp "$host_file" "${container_name}:/tmp/lab5-evidence.tsv"
    echo "Exported sanitized evidence for ${src_ip} into ${container_name}:/tmp/lab5-evidence.tsv"
}

export_participant '10.77.0.11' 'kali-01'
export_participant '10.77.0.12' 'kali-02'
