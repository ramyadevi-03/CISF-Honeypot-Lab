# CISF Honeypot Workshop Instructor Runbook

This runbook consolidates the verified local workshop setup and instructor
workflow. Run commands from the repository root. It describes the local Docker
environment; it does not deploy to AWS or provide browser-based participant
access.

## 1. Workshop overview

The lab consists of **N Kali participant containers** and one shared honeypot
target on the internal Docker network `cisf-lab-net`:

| Component | Role |
|---|---|
| Kali-01 through Kali-N | Participant terminals, each with a distinct network IP |
| Cowrie | SSH on TCP 2222 and Telnet on TCP 2223 |
| OpenCanary | FTP on TCP 21, HTTP on TCP 80, and MySQL on TCP 3306 |
| Suricata | IDS observing the shared honeypot's network traffic |

The shared target address is `10.77.0.10`. OpenCanary and Suricata share
Cowrie's network namespace so they use the target address and Suricata can
observe participants' source IPs. The Docker network is internal and the
Compose configuration does not publish honeypot ports on the host, isolating
the lab network from external networks in this local configuration. This does
**not** isolate Kali participants from one another: they share a bridge and
participant-to-participant connectivity is enabled and verified by
`lab.sh test N`. Persistent Cowrie and OpenCanary logs use named volumes;
Suricata logs are stored under `suricata/logs/` in the repository.

Lab 5 evidence is generated separately for each discovered Kali participant.
The exporter filters events by that participant's actual source IP and writes
only an allowlisted, sanitized TSV to that participant's container.
The workshop contains six labs; Lab 6 provides one combined, sanitized
multi-participant dataset for forensic investigation.

## 2. Prerequisites

- Docker Desktop with Linux containers and Docker Compose, or a compatible
  Docker host.
- On Windows, Ubuntu WSL with Docker Desktop integration enabled is the
  documented environment for the Bash workflow.
- Repository access and a terminal at the repository root.
- Enough CPU, memory, and storage for the selected participant count and
  persistent logs. Each Kali container is configured for 1 CPU and 512 MiB;
  Cowrie and OpenCanary are each configured for 1 CPU and 512 MiB, and
  Suricata for 0.5 CPU and 384 MiB.
- Instructor access to Docker and the host-side logs. Participants should
  receive only a terminal in their assigned Kali container and, for Lab 5,
  their own sanitized evidence.

The Bash scripts require Bash, Docker, and Python for evidence export. Do not
give participants Docker access, mount the Docker socket or raw log directories
into participant containers, or use real credentials. The validated
configuration has no Suricata packet-drop statistics available; do not
interpret that absence as zero packet loss.

## 3. Starting the workshop

### Provision participants

Select the desired participant count before provisioning. `lab.sh` accepts
counts from **2 through 244**. The Bash `up N` action builds the Kali image if
needed, starts the requested participants, and removes obsolete participant
containers if scaling down. Choose the intended count carefully.

```bash
N=5
bash ./scripts/lab.sh up "$N"
bash ./scripts/lab.sh status "$N"
bash ./scripts/lab.sh test "$N"
```

`lab.sh test N` checks the expected assigned IP and running state for all N
participants, then checks participant-to-participant connectivity around the
participant set. It does not test honeypot services.

### Start the shared honeypot and sensor

Start the overlay after the Kali lab has created `cisf-lab-net`. This starts
Cowrie, OpenCanary, and Suricata together:

```bash
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh status
```

`suricata.sh status` reports Compose container state and the network's internal
setting/subnet. It is not an application-level health check. Container health
checks are not configured in the Compose files.

For an active end-to-end protocol and logging test, the repository provides:

```bash
bash ./scripts/suricata.sh test
```

This test generates protocol interactions and dummy authentication attempts
from Kali-01 and Kali-02, and checks their Cowrie, OpenCanary, and Suricata
records. Run it as a deliberate validation, not as a passive status command;
it does not exercise participants beyond Kali-02.

### Confirm participant assignments

For `N=5`, the expected assignments are Kali-01 `.11`, Kali-02 `.12`,
Kali-03 `.13`, Kali-04 `.14`, and Kali-05 `.15` on `10.77.0.0/24`. The
provisioner assigns addresses in order; always verify the actual address
before assigning a participant.

```bash
for container in $(docker ps --filter network=cisf-lab-net --format '{{.Names}}' |
  grep -E '^kali-[0-9]+$' | sort -V); do
  docker inspect --format '{{.Name}} {{with index .NetworkSettings.Networks "cisf-lab-net"}}{{.IPAddress}}{{end}}' "$container"
done
```

Confirm the lab's running containers and network:

```bash
docker ps --filter network=cisf-lab-net
docker network inspect cisf-lab-net
```

The shared target should be `10.77.0.10`, the network should be internal with
subnet `10.77.0.0/24`, and no honeypot ports should be published on the host.

## 4. Participant assignment and access

Assign one provisioned container per participant, in numerical order:
`kali-01`, `kali-02`, and so on. Confirm the container name and actual IP with
the assignment loop above. Participants should stop and ask the instructor if
their hostname or IP does not match their assignment.

Open each participant's terminal from an instructor-controlled terminal:

```bash
docker exec -it kali-01 bash
```

Use the corresponding container name for each participant and provide separate
terminal sessions. Keep Docker administration, raw logs, and the Docker socket
on the instructor side. The Compose network is isolated; these services are
not published for direct host access.

**Current access is through Docker terminal sessions. Browser-based Kali
desktops or participant browser access have not been implemented.** The HTTP
honeypot is a lab service, not a participant web portal.

## 5. Conducting Labs 1–6

Have participants follow the linked exercise instructions. The summaries
below identify the validated scope and the evidence instructors should check;
they do not replace the detailed participant steps.

### Lab 1 — Network reconnaissance

- **Objective/actions:** From the assigned Kali container, discover only the
  five authorized target ports with the documented TCP connect scan:
  `nmap -sT -Pn -n --reason -p 21,80,2222,2223,3306 10.77.0.10`.
- **Expected observations:** The five ports are open: FTP 21, HTTP 80, SSH
  2222, Telnet 2223, and MySQL 3306. Nmap's port-database service labels for
  2222/2223 may be misleading. A basic connect scan is not an authentication
  attempt.
- **Expected security evidence:** Suricata flow records can identify the
  source and destination endpoints. Suricata SIDs 1000002 (SSH to Cowrie) and
  1000003 (Telnet to Cowrie) detect initial connections; do not expect
  FTP/HTTP/MySQL application alerts from a connect-only scan.
- **Instructor verification:** Filter Suricata EVE rows to the participant IP,
  target `10.77.0.10`, five authorized ports, and the recorded UTC start time.
  Allow up to 30 seconds for flow records. Share only that participant's
  excerpt.
- **Common errors:** A plain scan's `SERVICE` label is not definitive
  application identification. Do not broaden the scan or interpret the scan
  as a login. See the [Lab 1 participant exercise](../exercises/01-network-reconnaissance/participant-exercise.md)
  and [Lab 1 instructor guide](../exercises/01-network-reconnaissance/instructor-guide.md).

### Lab 2 — SSH and Telnet investigation

- **Objective/actions:** Make one SSH and one Telnet dummy login attempt from
  the assigned participant container, using only the credentials in the
  participant guide. SSH uses port 2222; the tested Telnet client is
  `curl telnet://10.77.0.10:2223`.
- **Expected observations:** Cowrie records connection, login, and session
  events. A `cowrie.login.success` is Cowrie's emulated result, not access to
  a real host or account. Telnet may log the dummy password in raw Cowrie
  records.
- **Expected security evidence:** Suricata SIDs 1000002 and 1000003 detect
  SSH/Telnet TCP connections; they do not identify credentials. Correlate
  using source IP/port, destination IP/port, and nearby timestamps.
- **Instructor verification:** Check the participant's Cowrie events and
  corresponding Suricata alert only. Never display `password` or raw `message`
  fields.
- **Common errors:** If the Telnet curl client stays open after Cowrie records
  `cowrie.session.closed`, confirm closure and press Ctrl-C once; do not retry
  the login. See the [Lab 2 participant exercise](../exercises/02-ssh-telnet-investigation/participant-exercise.md)
  and [Lab 2 instructor guide](../exercises/02-ssh-telnet-investigation/instructor-guide.md).

### Lab 3 — FTP investigation

- **Objective/actions:** Make one dummy FTP attempt to `10.77.0.10:21` with
  the documented curl interaction. Enter only the exercise dummy password at
  the prompt; do not place it on the command line.
- **Expected observations:** The tested service replies `220` (ready), `331`
  (password required), and `530` (authentication rejected). Curl commonly
  exits 67 for that expected rejection; treat it as expected only if the `530`
  response was actually observed.
- **Expected security evidence:** OpenCanary logtypes 2001/2000 record
  authentication initiation/attempt; logtype 2000 contains credentials in
  raw logs. Suricata SID 1000004 detects the FTP `USER` command, not the
  password or authentication outcome.
- **Instructor verification:** Correlate filtered OpenCanary and Suricata
  records by source port and endpoint addresses/ports. Project only safe
  fields; do not share raw transcripts or raw log entries.
- **Common errors:** A `530` and curl exit 67 are the expected rejection, not
  a reason to retry. See the [Lab 3 participant exercise](../exercises/03-ftp-investigation/participant-exercise.md)
  and [Lab 3 instructor guide](../exercises/03-ftp-investigation/instructor-guide.md).

### Lab 4 — HTTP and MySQL investigation

- **Objective/actions:** Make one redirect-following HTTP request to
  `10.77.0.10:80`, then one dummy MySQL authentication attempt to
  `10.77.0.10:3306` using the provided Perl one-shot client. It sends no SQL;
  no MySQL CLI or package installation is required.
- **Expected observations:** HTTP finishes with status 200 after the root
  redirect (the recorded path may be `/index.html`). The MySQL server rejects
  the dummy login with error 1045 (access denied). This is not a successful
  database login.
- **Expected security evidence:** OpenCanary HTTP logtype 3000 records the
  request; MySQL logtype 9003 records a connection and 8001 an authentication
  attempt. Suricata SIDs are 1000005 (HTTP GET) and 1000006 (MySQL payload).
  Multiple alerts can represent packets or redirect requests, not separate
  successful logins.
- **Instructor verification:** Filter OpenCanary and Suricata to the
  participant's source IP, then correlate source port, target, destination
  port, and timestamp. Never expose raw MySQL credentials.
- **Common errors:** Use `--location` for the HTTP redirect. A 9003 without
  8001 proves a connection only; do not infer an authentication attempt or
  ask for a retry before investigating. See the [Lab 4 participant exercise](../exercises/04-http-mysql-investigation/participant-exercise.md)
  and [Lab 4 instructor guide](../exercises/04-http-mysql-investigation/instructor-guide.md).

### Lab 5 — Suricata alert analysis

- **Objective/actions:** Participants investigate only their own sanitized
  TSV, reconstructing a timeline across Suricata, Cowrie, and OpenCanary.
  They do not generate traffic as part of the evidence-review steps.
- **Expected observations:** Rows use the 16-column schema, normalized UTC
  timestamps, participant source IPs, source/destination ports, service names,
  and Suricata signature IDs. The expected service SIDs are 1000002–1000006.
- **Instructor verification:** Check the export before distribution for
  participant isolation, source coverage, event window, row structure, and
  expected signature coverage. Authentication success must come from explicit
  application evidence; connection alerts and authentication-attempt events
  alone do not prove success.
- **Common errors:** No records may mean the chosen time window does not
  include the activity or the selected participant did not generate matching
  events. Do not provide raw logs to fill gaps. See the [Lab 5 participant exercise](../exercises/05-suricata-alert-analysis/participant-exercise.md)
  and [Lab 5 instructor guide](../exercises/05-suricata-alert-analysis/instructor-guide.md).

### Lab 6 — Mixed-log forensic investigation

- **Objective/actions:** Participants use a combined sanitized evidence file
  to attribute activity by source IP, distinguish discovery, connections, and
  authentication attempts, and reconstruct the timeline across five roles.
- **Expected observations:** The 16-column TSV combines Suricata, Cowrie, and
  OpenCanary records from the selected window. Evidence supports the distinct
  role assignments only when live events show those activity patterns.
- **Instructor verification:** Follow the [Lab 6 instructor guide](../exercises/06-mixed-log-forensic-investigation/instructor-guide.md),
  retain the separate answer key, verify filtering and chronology, and
  correlate source ports and endpoint tuples. Cowrie login outcomes are
  emulated; connection records alone do not prove authentication.
- **Common errors:** Historical multi-service activity may not distinguish
  the planned roles. Do not fabricate missing records or infer the planned
  source-to-role mapping without verification. See the [Lab 6 participant exercise](../exercises/06-mixed-log-forensic-investigation/participant-exercise.md).

## 6. Evidence distribution

Run the exporter from Ubuntu/WSL at the repository root after the activity and
after allowing time for Suricata to write its records. Record the UTC start
time **before** participants begin:

```bash
exercise_start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Exercise start (UTC): %s\n' "$exercise_start_utc"
```

The exporter accepts a start timestamp, an optional exclusive end timestamp,
and an optional destination filename:

```text
bash ./scripts/export-lab5-evidence.sh <start-utc> [end-utc-exclusive] [destination-filename]
```

Default export for each participant:

```bash
bash ./scripts/export-lab5-evidence.sh "$exercise_start_utc"
```

The default destination is `/tmp/lab5-evidence.tsv`. To bound the window and
avoid touching an existing default export, provide both an exclusive end and a
new simple filename:

```bash
exercise_end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
bash ./scripts/export-lab5-evidence.sh \
  "$exercise_start_utc" "$exercise_end_utc" "lab5-evidence-workshop-01.tsv"
```

The file is then written to
`/tmp/lab5-evidence-workshop-01.tsv` in each participant container. The end
timestamp is excluded. To select a custom filename without an end time, pass
an empty second argument:

```bash
bash ./scripts/export-lab5-evidence.sh \
  "$exercise_start_utc" "" "lab5-evidence-workshop-01.tsv"
```

The exporter discovers running containers matching `kali-[0-9]+` on
`cisf-lab-net`, sorts them numerically, and reads each actual network IP. It
filters by exact source IP, target address `10.77.0.10`, relevant service
ports, and the requested time window. It retains a fixed 16-column
allowlist, including username and selected HTTP metadata, but excludes
passwords, messages, and raw authentication fields. It normalizes timestamps
to UTC with a `Z` suffix, sorts rows chronologically, and distributes one
participant-specific file to each matching container.

The exporter refuses to overwrite a destination that already exists in any
discovered participant container. Choose a new filename rather than deleting
or replacing prior evidence.

Verify every discovered participant's file. Set `EVIDENCE` to the same
filename used above:

```bash
EVIDENCE=/tmp/lab5-evidence-workshop-01.tsv
for container in $(docker ps --filter network=cisf-lab-net --format '{{.Names}}' |
  grep -E '^kali-[0-9]+$' | sort -V); do
  participant_ip=$(docker inspect --format '{{with index .NetworkSettings.Networks "cisf-lab-net"}}{{.IPAddress}}{{end}}' "$container")
  docker exec "$container" test -s "$EVIDENCE"
  docker exec "$container" awk -F '\t' -v ip="$participant_ip" \
    'NR > 1 && $6 != ip {bad=1} END {if (bad) exit 1; print "participant evidence IP filter: PASS"}' \
    "$EVIDENCE"
  docker exec "$container" awk -F '\t' \
    'NF != 16 {bad=1} END {if (bad) exit 1; print "16-column TSV: PASS"}' \
    "$EVIDENCE"
  docker exec "$container" cut -f10 "$EVIDENCE" | sort -u
done
```

Confirm the SID list against signatures expected for that participant's
activity and time window. An export can be structurally valid but have no
events if the time window does not cover activity. Participants may view only
the file in their own Kali container; they must not access the raw logs or
another participant's export.

Lab 6 uses a separate exporter that sends the same combined evidence to every
eligible participant. Use a new destination filename for each validation:

```bash
bash ./scripts/export-mixed-lab-evidence.sh \
  "$exercise_start_utc" "$exercise_end_utc" "lab6-mixed-evidence.tsv"
```

The file is `/tmp/lab6-mixed-evidence.tsv` in each discovered Kali container.
The exporter retains source IPs for investigation but omits participant names
and role assignments. It applies the same time-window, timestamp, schema,
sanitization, and no-overwrite safeguards; keep the answer key separate from
the distributed dataset.

## 7. Troubleshooting

- **Docker unavailable:** Start/verify Docker Desktop or the compatible
  Docker daemon. On Windows, use Ubuntu WSL with Docker Desktop integration.
  From the repository root, confirm `docker` and `docker compose` are
  available before proceeding.
- **Containers stopped:** Check `docker ps`. Start participants with
  `bash ./scripts/lab.sh up N`, then start the shared overlay with
  `bash ./scripts/suricata.sh up`. Use the same Compose/script family used
  for the deployment. Do not remove volumes or recreate unrelated containers.
- **Service ports unreachable:** Check participant addresses with
  `bash ./scripts/lab.sh status N` and validate participant connectivity with
  `bash ./scripts/lab.sh test N`. Check overlay state and network details with
  `bash ./scripts/suricata.sh status`. If an active service test is required,
  `bash ./scripts/suricata.sh test` exercises only Kali-01/02 and generates
  lab traffic; account for those records in the evidence window. Do not scan
  additional ports or targets.
- **SSH interaction timing or warning:** Confirm `10.77.0.10` and port 2222.
  Accept a host key only for that expected endpoint; investigate unexpected
  host-key changes with the instructor. Allow up to 30 seconds for logs.
  Cowrie's `cowrie.login.success` is an emulated outcome only.
- **Telnet curl remains open:** Cowrie may already have logged
  `cowrie.session.closed` while curl remains active locally. Confirm that
  event, then press Ctrl-C once. This is a client shutdown behavior; do not
  repeat the login. A client timeout is not the authentication outcome.
- **FTP returns 530 / curl exit 67:** This is the expected dummy-login
  rejection when the transcript shows `530`. Do not retry. Keep verbose
  output private because it may contain protocol data.
- **MySQL error 1045:** This is the expected access-denied response to the
  dummy attempt; it is not success. Do not retry or issue SQL.
- **Suricata alert missing:** Confirm participant source IP, target IP,
  destination port, SID, and UTC time filter. Allow up to 30 seconds for log
  delivery. A flow, a Suricata alert, and an application authentication event
  represent different evidence. Suricata packet-drop statistics are
  unavailable in the validated setup, so packet loss remains unverified.
- **Evidence export failure:** Confirm that Docker and Python are available
  to the Ubuntu/WSL shell, participants are running and attached to
  `cisf-lab-net`, and both honeypot log sources are available. Use a valid
  ISO-8601 start timestamp; the optional end must be later than the start.
  The filename must be a simple filename, not a path. If the destination
  exists, choose another filename; the exporter intentionally refuses to
  overwrite it. If events are absent, check the time window and participant
  source IP before considering any new authorized activity.

## 8. Safe shutdown and reset

When the workshop is finished, stop the shared overlay first, then the
participant lab:

```bash
bash ./scripts/suricata.sh down
bash ./scripts/lab.sh down
```

These are the documented Bash lifecycle commands. They stop/remove the
workshop containers without requesting volume deletion. Cowrie and OpenCanary
named volumes and existing host-side Suricata logs should be preserved. Do
not use `docker compose down -v`, `docker volume prune`, or manually delete
log files or evidence.

To restart with N participants, bring up the participants before the honeypot:

```bash
N=5
bash ./scripts/lab.sh up "$N"
bash ./scripts/lab.sh test "$N"
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh status
```

For a new exercise window, record a fresh UTC start time. Do not clear
historical logs to reset the workshop; use a time filter and a new export
filename when prior participant evidence must be retained.

## 9. Security and instructor responsibilities

- Use the environment only for the authorized workshop exercises and only
  against the isolated lab target. No external targets, broad scans, brute
  force, or high-volume traffic.
- Keep the honeypot on `cisf-lab-net`; do not publish its ports to the host or
  expose services through another network.
- Use only the dummy credentials in the participant guides. Cowrie Telnet,
  OpenCanary FTP, and OpenCanary MySQL raw records can contain credentials.
  Do not display or distribute raw logs, passwords, message fields, or raw
  transcripts.
- Do not give participants Docker access, access to the Docker socket, access
  to raw logs, or another participant's evidence. Distribute only the
  sanitized file filtered to their actual source IP.
- Treat Cowrie success as an emulated honeypot outcome. Treat OpenCanary
  authentication logtypes and Suricata alerts as observations, not proof of
  successful authentication.
- Preserve historical evidence and named volumes. Use unique export filenames
  rather than replacing evidence files.
- The validated environment does not provide Suricata packet-drop
  measurements. Report packet loss as unverified, not zero.
