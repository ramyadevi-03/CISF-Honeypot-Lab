# Instructor Guide: Lab 6 Mixed-Log Forensic Investigation

## Purpose and status

Participants receive one combined, sanitized evidence file and infer which
source IP performed each activity. The intended live challenge uses five
different activity profiles with overlapping execution times; participants
are not told the profile-to-IP mapping.

The preserved logs were inspected read-only during implementation. They
contain records from all five participant IPs across the five services, but
the historical participants performed broadly similar activities. Those
records do **not** establish the distinct five-role mystery described below.
The controlled live validation on 2026-11-10 confirmed the five distinct
profiles from their actual source IPs. The final sanitized export contained
36 records: 20 Suricata, 9 Cowrie, and 7 OpenCanary records, including all
five expected Suricata SIDs. Exact observations and limitations are in the
[instructor-answer-key.md](instructor-answer-key.md).

## Prerequisites and setup

- Use the approved supervised local lab; this guide does not authorize
  Cyber Range deployment.
- Five Kali containers are required for the five-role challenge.
- Confirm each participant's actual IP on `cisf-lab-net` and confirm the
  shared target at `10.77.0.10`.
- Start the honeypot overlay with `bash ./scripts/suricata.sh up` if it is not
  already running.
- Keep Docker access and raw Cowrie, OpenCanary, and Suricata logs with the
  instructor. Participants receive only the combined sanitized export.

Use the existing Lab 1–4 participant exercises as the source of validated
participant commands. Do not run `bash ./scripts/suricata.sh test` as part of
this challenge: it generates extra interactions from Kali-01 and Kali-02 and
would confound the role patterns.

If provisioning is necessary, provision the intended five participants and
inspect their addresses:

```bash
bash ./scripts/lab.sh up 5
bash ./scripts/lab.sh status 5
for container in $(docker ps --filter network=cisf-lab-net --format '{{.Names}}' |
  grep -E '^kali-[0-9]+$' | sort -V); do
  docker inspect --format '{{.Name}} {{with index .NetworkSettings.Networks "cisf-lab-net"}}{{.IPAddress}}{{end}}' "$container"
done
bash ./scripts/suricata.sh status
```

`lab.sh test 5` checks peer-to-peer ping as well as participant state; it is
not an isolation test. The internal bridge is isolated from external
networks, but participant-to-participant connectivity is enabled. Keep the
workshop supervised and do not describe the participants as mutually
isolated.

Open five separate instructor-controlled terminals, one for each Kali
container. Participants must not receive Docker access or raw-log access.

## Verified live validation

The five participant activities were launched concurrently in a supervised
local run. The UTC activity start was `2026-11-10T06:48:38Z`; the exclusive
evidence-window end was `2026-11-10T06:49:21Z`, after a 30-second log-settle
period. The restricted Nmap scan found the five authorized ports open; Kali-02
recorded Cowrie login events on SSH and Telnet; Kali-03 received FTP `530`;
Kali-04 made two HTTP requests that returned final status `200`; and Kali-05
received MySQL error `1045`. Cowrie login success is simulated.

The mixed export was distributed as
`/tmp/lab6-mixed-evidence-live-final.tsv` to all five Kali containers. The
copies were identical, had 16 columns, contained only the five participant
source IPs, were chronologically sorted in UTC, included SIDs `1000002`–
`1000006`, and contained no password, secret, payload, or authentication
message fields. For this noninteractive validation, Telnet used a controlled
client built from Kali's installed Perl socket modules; the participant
exercise continues to document the interactive curl command.

## Planned evidence-generation procedure

For the distinct challenge, privately assign one profile per participant as
listed in the instructor-only answer key. Do not disclose that mapping in the
participant handout or mixed TSV.

Record a UTC start time on the instructor host immediately before the
coordinated launch:

```bash
exercise_start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Lab 6 start (UTC): %s\n' "$exercise_start_utc"
```

Give all five participants a coordinated start cue. Launch their documented
single exercise interactions from their separate terminals during the same
short activity window so the event times overlap. Record each participant's
actual start and completion times. This is a controlled, low-volume exercise;
do not automate retries, broaden the scan, or use real credentials. Use only
the dummy values in the existing Lab 2–4 participant guides.

The planned profiles are:

1. One participant performs the Lab 1 TCP connect scan of only the five
   authorized ports.
2. One participant performs the documented single SSH and Telnet dummy
   interactions.
3. One participant performs one documented FTP dummy login attempt.
4. One participant performs the documented redirect-following HTTP request.
5. One participant performs one documented MySQL dummy authentication
   attempt.

Use the participant guide commands as written. Expected protocol behavior
from prior validation includes FTP 220/331/530 with curl exit 67 on the
expected rejection, HTTP final status 200 after redirect, MySQL error 1045,
and Cowrie login outcomes that are simulated honeypot results only. Confirm
what actually occurred from the current participant output and logs; do not
assume those outcomes if the live result differs.

After all interactions complete, allow up to 30 seconds for logs to arrive and
record the exclusive UTC end time:

```bash
exercise_end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Lab 6 end (UTC, exclusive): %s\n' "$exercise_end_utc"
```

The participant/IP mapping must be held separately from the evidence file.
Keep the instructor answer key private.

## Generate and distribute the combined evidence

From the repository root, run the separate Lab 6 exporter:

```bash
bash ./scripts/export-mixed-lab-evidence.sh \
  "$exercise_start_utc" "$exercise_end_utc" "lab6-mixed-evidence.tsv"
```

The start is inclusive and the end is exclusive. The exporter discovers
running containers named `kali-N` on `cisf-lab-net`, gets their actual IP
addresses, selects records for those source IPs and the shared target, then
combines the records into one chronologically sorted TSV. It copies that same
combined, sanitized file to each discovered participant at
`/tmp/lab6-mixed-evidence.tsv`. The TSV has no Kali container-name or role
column; source IP is retained for investigation. The exporter refuses to
overwrite the destination in any participant container. Choose a new simple
filename for a later run rather than deleting existing evidence.

If a destination file already exists in any participant container, the
exporter stops before reading or distributing the dataset. Confirm the
filename is unused by all participants before starting. The exporter reads
Suricata EVE from the instructor's `suricata/logs/eve.json` and fetches raw
Cowrie/OpenCanary logs from their containers. Raw logs are not copied into
Kali; temporary host output is created with restrictive permissions and
removed on exit.

## Verification steps

Verify the combined dataset in each participant container. These checks do
not print raw credentials:

```bash
for container in $(docker ps --filter network=cisf-lab-net --format '{{.Names}}' |
  grep -E '^kali-[0-9]+$' | sort -V); do
  docker exec "$container" test -s /tmp/lab6-mixed-evidence.tsv
  docker exec "$container" awk -F '\t' \
    'NF != 16 {bad=1} END {if (bad) exit 1; print "16-column TSV: PASS"}' \
    /tmp/lab6-mixed-evidence.tsv
done
```

On the instructor host, review the export for all expected participant source
IPs, sources (`suricata`, `cowrie`, `opencanary`), chronological ordering,
and expected activity within the chosen time window. For the planned
five-profile exercise, the combined data should contain Suricata signature
coverage appropriate to the interactions: 1000002/1000003 for SSH/Telnet,
1000004 for FTP, 1000005 for HTTP, and 1000006 for MySQL. A basic scan may
produce Suricata flows and SSH/Telnet connection alerts without producing
FTP/HTTP/MySQL application events.

Correlate by source IP, source port, destination IP, destination port, service,
and nearby UTC timestamps. Suricata alert timestamps can precede application
events. Suricata flows may show a connection without an alert; OpenCanary
MySQL type 9003 is a connection and type 8001 is an authentication attempt.
Neither alone establishes a successful database login. Cowrie
`cowrie.login.success` describes Cowrie's emulation, not real system access.

The exporter retains the Lab 5 16-column schema. It allowlists event
metadata, selected username/HTTP fields, Suricata signatures, and Cowrie
session IDs; it excludes passwords, secrets, raw payloads, and authentication
message fields. Check that participant names and the answer key are not in
the TSV. Never distribute raw logs or the key to participants.

## Answer-key methodology

Use the separate [instructor-only answer key](instructor-answer-key.md) for
the planned role mapping, verified historical-log limitations, expected
evidence, and rubric. Distinguish:

- **Observed:** fields and records present in the logs and participant
  responses for this run.
- **Inferred:** a conclusion supported by a combination of observations, such
  as likely port discovery from flows to several service ports in a short
  interval.
- **Not established:** facts not proved by the available events, such as
  authentication success based only on a connection or alert.

For future workshops, verify each run's actual participant source IPs and
correlate its events before treating the planned profile assignment as
observed.
