# Instructor Guide: Lab 5 Suricata Alert Analysis and Incident Reconstruction

## Purpose

This lab gives participants access to a sanitized evidence export rather than the raw Docker-host logs. They must manually correlate Suricata, Cowrie, and OpenCanary records for their assigned Kali participant and reconstruct the sequence of events across SSH, Telnet, FTP, HTTP, and MySQL.

No grading automation is used. The lab is intentionally manual and evidence-driven.

## Lab setup

From Ubuntu/WSL with Docker Desktop integration:

```bash
bash ./scripts/lab.sh up 2
bash ./scripts/lab.sh test 2
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh status
```

Verify the participant addresses:

```bash
docker exec kali-01 bash -lc 'ip -4 -o addr show dev eth0'
docker exec kali-02 bash -lc 'ip -4 -o addr show dev eth0'
```

Expected source IPs:

- Kali-01: `10.77.0.11`
- Kali-02: `10.77.0.12`

The shared target remains `10.77.0.10`.

## Generate fresh controlled activity

Run this before generating traffic. The timestamp is required by the exporter so old log rows do not get mixed into this exercise's evidence:

```bash
exercise_start_utc="$(docker exec kali-01 date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Exercise start (UTC): %s\n' "$exercise_start_utc"
```

Run each command once from `kali-01` and once from `kali-02`. All destinations are the isolated target `10.77.0.10`. The test interactions use no destructive actions and only the single dummy FTP/MySQL authentication attempt shown.

### SSH — port 2222

```bash
docker exec kali-01 bash -lc 'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o PreferredAuthentications=none -o PubkeyAuthentication=no -o ConnectTimeout=5 -p 2222 cisf-lab5@10.77.0.10 true >/dev/null 2>/dev/null; rc=$?; printf "ssh_exit=%s (no authentication result asserted)\n" "$rc"'
```

The client normally exits `255` because this test intentionally does not authenticate. Cowrie should still record the SSH session. This is not evidence that a password was tried.

### Telnet — port 2223

```bash
docker exec kali-01 bash -lc 'exec 3<>/dev/tcp/10.77.0.10/2223; IFS= read -r -t 3 -u 3 banner; [[ -n "$banner" ]] && echo "telnet_banner_received=yes"; exec 3>&-; exec 3<&-'
```

### FTP — port 21

```bash
docker exec kali-01 bash -lc 'exec 3<>/dev/tcp/10.77.0.10/21; IFS= read -r -t 3 -u 3 banner; printf "USER cisf-lab5\r\n" >&3; IFS= read -r -t 3 -u 3 user_reply; printf "PASS dummy-lab5\r\n" >&3; IFS= read -r -t 3 -u 3 auth_reply; printf "ftp_banner=%s\nftp_user_reply=%s\nftp_auth_reply=%s\n" "$banner" "$user_reply" "$auth_reply"; printf "QUIT\r\n" >&3; exec 3>&-; exec 3<&-'
```

The tested server response to this dummy login was `530 Sorry, Authentication failed.` The participant export contains the safe username and the event type, not the password or raw server dialogue.

### HTTP — port 80

```bash
docker exec kali-01 curl --silent --show-error --location --fail --max-time 8 --output /dev/null --write-out 'http_status=%{http_code} remote=%{remote_ip}:%{remote_port}\n' http://10.77.0.10/
```

The tested root request redirected to `/index.html` and finished with HTTP `200`. The final GET produced OpenCanary logtype `3000`.

### MySQL — port 3306

Run this minimal MySQL handshake and one dummy authentication packet. It sends no SQL:

```bash
docker exec -i kali-01 bash -s <<'BASH'
set -e
exec 3<>/dev/tcp/10.77.0.10/3306
IFS= read -r -t 5 -N 1 -u 3 greeting
[[ -n "$greeting" ]]
printf '\x30\x00\x00\x01\x85\xa2\x00\x00\x00\x00\x00\x00\x21' >&3
printf '\0%.0s' {1..23} >&3
printf 'cisf-lab5\0\x05wrong' >&3
IFS= read -r -t 5 -N 1 -u 3 response
[[ -n "$response" ]]
printf 'mysql_greeting_byte_received=yes auth_response_byte_received=yes\n'
exec 3>&-
exec 3<&-
BASH
```

The handshake and response bytes confirm protocol exchange only. OpenCanary's logtype `8001` records an authentication attempt; it does not prove a successful database login.

For Kali-02, replace `kali-01` with `kali-02` in each command. Allow a few seconds after the final interaction for Suricata EVE records to be written.

## Export sanitized evidence for participants

Run the provided exporter from the repository root, passing the UTC timestamp recorded before the activity:

```bash
bash ./scripts/export-lab5-evidence.sh "$exercise_start_utc"
```

This creates a sanitized TSV for each participant and copies it into the matching Kali container at `/tmp/lab5-evidence.tsv`.

The exporter filters on exact participant source IP, destination IP, service port, and the exercise start time. It exports only approved fields, normalizes timestamps to UTC with a `Z` suffix, removes tabs/newlines from field values, and does not read or export password, message, or raw authentication fields.

Expected output:

```text
Exported sanitized evidence for 10.77.0.11 into kali-01:/tmp/lab5-evidence.tsv
Exported sanitized evidence for 10.77.0.12 into kali-02:/tmp/lab5-evidence.tsv
```

Verify each export from the instructor host:

```bash
for spec in "kali-01 10.77.0.11" "kali-02 10.77.0.12"; do
  set -- $spec
  container=$1
  participant_ip=$2
  docker exec "$container" test -s /tmp/lab5-evidence.tsv
  docker exec "$container" awk -F '\t' -v ip="$participant_ip" 'NR > 1 && $6 != ip {bad=1} END {if (bad) exit 1; print "participant source filter: PASS"}' /tmp/lab5-evidence.tsv
  docker exec "$container" awk -F '\t' 'NR > 1 && NF != 16 {bad=1} END {if (bad) exit 1; print "16-column TSV: PASS"}' /tmp/lab5-evidence.tsv
  docker exec "$container" cut -f10 /tmp/lab5-evidence.tsv | sort -u
done
```

The SID list must include `1000002` through `1000006` for each participant.

## Commands participants use inside Kali

Participants are expected to use the file in their own container only. Replace the IP with the participant's address:

```bash
IP=10.77.0.11
ls -l /tmp/lab5-evidence.tsv
head -n 20 /tmp/lab5-evidence.tsv
grep -F "$IP" /tmp/lab5-evidence.tsv | head -n 40
awk -F '\t' -v ip="$IP" '$6 == ip {print}' /tmp/lab5-evidence.tsv | sort -k2,2
grep -E 'ssh|telnet|ftp|http|mysql' /tmp/lab5-evidence.tsv | sort -k2,2 | head -n 80
awk -F '\t' '$1 == "suricata" {print}' /tmp/lab5-evidence.tsv | sort -k2,2 | head -n 30
awk -F '\t' '$1 == "cowrie" || $1 == "opencanary" {print}' /tmp/lab5-evidence.tsv | sort -k2,2 | head -n 30
awk -F '\t' -v sid="1000004" '$1 == "suricata" && $10 == sid {print}' /tmp/lab5-evidence.tsv
awk -F '\t' -v ip="$IP" '$6 == ip && ($5 == "ssh" || $5 == "telnet" || $5 == "ftp" || $5 == "http" || $5 == "mysql") {print}' /tmp/lab5-evidence.tsv | sort -k2,2
```

The commands above are intentionally simple, minimal, and work without Docker access.

## Verified record types

The exporter preserves only safe fields and deliberately strips password content. Verified fields include:

- Suricata alert records: `timestamp`, `event_type`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `alert.signature_id`, `alert.signature`
- Cowrie records: `eventid`, `timestamp`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `session`, `username`
- OpenCanary records: `logtype`, `utc_time`, `src_host`, `src_port`, `dst_host`, `dst_port`, `logdata.PATH`, `logdata.USERAGENT`, `logdata.USERNAME`

The TSV maps those sources to its fixed 16-column schema. Cowrie authentication outcomes are populated only for explicit `cowrie.login.success` or `cowrie.login.failed` event IDs. Session connect/close events remain connection/disconnection records; they do not imply authentication. OpenCanary logtype `8001` is classified as an authentication attempt, not a successful login. `PASSWORD` and all unallowlisted fields are omitted.

The fresh test used an SSH handshake without credentials, so it produced Cowrie session events but no authentication outcome. A separate existing Cowrie record for `10.77.0.11` at `2026-11-08T12:58:24Z` had event ID `cowrie.login.success`; the exporter mapped that explicit event to `authentication-success` and retained its session and username without exporting password or message fields.

## Investigation answer key

Use this answer key only after participants have completed the exercise. The run below was generated on 2026-11-08; new runs will have different timestamps, sessions, and source ports.

### 1. Which alerts are associated with the participant?

Both participant exports contained these real Suricata alert signatures to `10.77.0.10`:

| Service | Destination port | SID |
|---|---:|---:|
| SSH | 2222 | 1000002 |
| Telnet | 2223 | 1000003 |
| FTP | 21 | 1000004 |
| HTTP | 80 | 1000005 |
| MySQL | 3306 | 1000006 |

### 2. Which services were contacted?

The exported records showed all five destination ports for both Kali IPs: `2222`, `2223`, `21`, `80`, and `3306`.

### 3. Which logs match each service?

- Cowrie recorded SSH `cowrie.session.connect`, client-version/KEX activity, and `cowrie.session.closed`; it recorded Telnet `cowrie.session.connect` and `cowrie.session.closed`.
- OpenCanary recorded FTP logtypes `2001` and `2000`; logtype `2000` included the attempted username.
- OpenCanary recorded HTTP logtype `3000` for `/index.html`.
- OpenCanary recorded MySQL logtype `9003` (connection) and `8001` (authentication attempt), with the attempted username.
- OpenCanary's raw MySQL event contained a `PASSWORD` key, but it was not present in the exported TSV.

### 4. How are the timeline and source ports correlated?

All TSV timestamps were normalized to timezone-aware UTC with a `Z` suffix. Suricata and application rows shared the same source IP, source port, destination IP, and destination port for each observed service. Example source ports:

| Service | Kali-01 `10.77.0.11` | Kali-02 `10.77.0.12` |
|---|---:|---:|
| SSH | 34550 | 51984 |
| Telnet | 46764 | 49826 |
| FTP | 47508 | 47716 |
| HTTP (`/index.html`) | 47324 | 32932 |
| MySQL | 59496 | 49412 |

For example, Kali-01's MySQL activity at approximately `2026-11-08T16:32:02.735Z` used source port `59496`; the OpenCanary `9003` and `8001` events and the SID `1000006` alerts shared that tuple. Kali-02's corresponding source port was `49412`.

The export contained, per participant, 1 SSH, 1 Telnet, and 1 FTP Suricata alert; 3 HTTP and 3 MySQL alert rows; 4 Cowrie SSH, 2 Cowrie Telnet, 2 OpenCanary FTP, 1 OpenCanary HTTP, and 2 OpenCanary MySQL rows. Repeated sensor alerts can represent multiple matching packets/requests in a connection; they are not necessarily separate logins. The three HTTP alerts include activity from the redirect-following HTTP request made after the initial service test.

### 5. Which events prove success and which do not?

- A TCP connection attempt does not prove login success.
- The tested SSH command deliberately performed no password authentication; Cowrie recorded a session, not a login outcome.
- The FTP server replied `530 Sorry, Authentication failed.` to the instructor's harmless dummy attempt, while the sanitized OpenCanary event records an authentication attempt but not the raw reply.
- The MySQL `8001` row indicates an authentication attempt and records a username; it is not proof of a successful database login.
- Suricata alerts identify matching network traffic and do not establish credential success.

## Cleanup and reset

After the lab, preserve the original logs and volumes. Remove only the participant copies of the export if the class is finished:

```bash
docker exec kali-01 rm -f /tmp/lab5-evidence.tsv
docker exec kali-02 rm -f /tmp/lab5-evidence.tsv
```

Leave the shared environment running for the next lab. If the lab must be stopped, use the normal lifecycle commands only; do not remove persistent log volumes.

## Security limitations

- Participants should not access Docker or the original logs.
- The instructor should not expose raw password-bearing records.
- Keep the exported evidence to the minimum necessary fields for incident reconstruction.
- Do not share raw Suricata EVE output with participants.

## Reuse for Lab 6

The same evidence export model is designed to support Lab 6, where mixed participant activity is to be investigated. Keep the participant-specific filtering pattern consistent and do not expand access beyond the lab participant's own evidence.
