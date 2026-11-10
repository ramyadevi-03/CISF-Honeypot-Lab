# Lab 6 Instructor-Only Answer Key

**Do not distribute this file to participants.** It contains the planned
participant-to-activity mapping.

## Evidence status

The preserved logs were inspected read-only before Lab 6 implementation. They
contain Cowrie, OpenCanary, and Suricata evidence from all five participant
source IPs across the five services. All five IPs have prior SSH/Telnet
Cowrie activity, OpenCanary FTP/HTTP/MySQL records, and Suricata alerts for
SIDs `1000002`–`1000006`.

The historical Phase 3B run also generated similar multi-service activity
from each participant. Therefore the preserved records do **not** show the
unique one-role-per-IP pattern below. A separate controlled live validation
was completed on 2026-11-10 and verified the role mapping and outcomes below.

The live activity began at `2026-11-10T06:48:38Z`. The evidence window ended
exclusively at `2026-11-10T06:49:21Z`, after allowing Suricata time to write
flow records. The export contained 36 rows: 20 Suricata, 9 Cowrie, and 7
OpenCanary. Each of the five Kali containers received the same 16-column
sanitized TSV. Row counts by source were 12, 8, 4, 8, and 4 for
`10.77.0.11` through `10.77.0.15`, respectively. All expected SIDs
`1000002`–`1000006` were present.

## Verified participant-to-activity mapping

The actual IPs were verified with Docker inspection before the run:

| Activity profile | Verified source | Observed activity |
|---|---|---|
| A | Kali-01, `10.77.0.11` | Nmap TCP connect scan of only 21, 80, 2222, 2223, and 3306 |
| B | Kali-02, `10.77.0.12` | One SSH and one Telnet dummy interaction with Cowrie |
| C | Kali-03, `10.77.0.13` | One FTP dummy authentication attempt |
| D | Kali-04, `10.77.0.14` | Two redirect-following HTTP requests |
| E | Kali-05, `10.77.0.15` | One MySQL dummy authentication attempt |

This mapping is specific to the verified local run. If container addresses
differ in a future run, update this private table from `docker inspect`. Do
not add container names or this mapping to the participant TSV.

Coordinate all participants with one start cue and record their individual
start/end times. Validate overlap from the recorded times and event
timestamps; a shared time window alone is not proof that packets overlapped.

## Observed evidence and interpretation

| Source | Observed evidence | What it establishes / does not establish |
|---|---|---|
| `10.77.0.11` | Suricata flows to all five authorized ports; SIDs `1000002`/`1000003`; Cowrie connection/close events on ports 2222/2223; OpenCanary MySQL type `9003` | Nmap found all five ports open. The type `9003` record is a connection caused by the scan, not a MySQL authentication attempt. No login event was observed for this source. |
| `10.77.0.12` | Cowrie SSH and Telnet session/login events; Suricata SIDs `1000002` and `1000003` | Cowrie recorded `cowrie.login.success` for both protocols. These are simulated honeypot outcomes, not authentication to a real system. |
| `10.77.0.13` | OpenCanary FTP types `2001` and `2000`; Suricata SID `1000004` | The controlled client observed `220`, `331`, and `530` rejection. Type `2000` records the attempt but does not itself establish the server response. |
| `10.77.0.14` | Two OpenCanary HTTP type `3000` records; four Suricata alerts with SID `1000005` | Two requests returned final HTTP status `200`. The duplicate alerts correspond to packets/redirect requests, not authentication outcomes. |
| `10.77.0.15` | OpenCanary MySQL type `9003` (connection) and `8001` (authentication attempt); Suricata SID `1000006` | The one-shot client observed MySQL error `1045` (access denied). Type `9003` alone is only a connection; type `8001` records an attempt, not success. |

The source ports are preserved in the TSV and correlate across Suricata and
application events: Kali-02 SSH `48186` / Telnet `55132`, Kali-03 FTP
`38672`, Kali-04 HTTP `41722` and `41724`, and Kali-05 MySQL `41684`.
Kali-01's scan used source ports `42126`, `52690`, `41390`, `52726`, and
`36852` for FTP, HTTP, SSH, Telnet, and MySQL, respectively.

Observed activity is distinguished from inference: the Nmap result and
short-interval flows support port discovery; connection alerts do not prove
authentication; Cowrie's success is simulated; FTP and MySQL rejection were
confirmed by their client responses.

## Answer methodology

1. **Count participants:** Count unique, nonempty `src_ip` values in rows
   after the header. Check that they are lab participants confirmed by the
   instructor; do not infer container names from the TSV.
2. **Attribute services:** Group by `src_ip` and `service` or `dest_port`.
   The standard mapping is 21 FTP, 80 HTTP, 2222 SSH, 2223 Telnet, and
   3306 MySQL.
3. **Classify activity:** A Suricata `flow` indicates observed communication.
   An alert indicates a rule match. Cowrie session connect/close events show
   session activity; explicit Cowrie login events show its emulated outcome.
   OpenCanary 2000/8001 are authentication attempts; 2001 indicates
   authentication initiation; 9003 is a MySQL connection; 3000 is an HTTP
   request.
4. **Establish outcomes:** Use the participant-visible protocol response and
   the applicable application event together. FTP `530` and MySQL error
   `1045` indicate rejection in the validated interactions. Cowrie login
   success is simulated. Suricata alerts and connections alone never prove
   credential success. HTTP status 200 is a content response, not login
   success.
5. **Correlate timelines:** Match participant `src_ip`, ephemeral `src_port`,
   target `dest_ip`, and service `dest_port`. Compare normalized UTC
   timestamps with tolerance for sensor/logging delay. Do not require an
   application event for every scan flow or an authentication event for a
   connection-only record.
6. **Separate observation from inference:** A burst of flows to multiple
   authorized service ports in the scan window supports the inference of
   port discovery. State the supporting records and timing; do not describe
   the inference as an authentication or successful compromise.

## Verification checklist

- The mixed TSV contains rows from Suricata, Cowrie, and OpenCanary for the
  selected window, if those events were generated.
- Every row's source IP belongs to a discovered participant; no unexpected
  source or destination is present.
- The data has exactly 16 columns, UTC `Z` timestamps, and chronological
  ordering.
- The planned challenge has the expected distinct activity profiles and the
  actual participant start/end intervals overlap as intended.
- Service signatures appear only when their triggering traffic was actually
  observed. The combined profile should cover SIDs `1000002`–`1000006`.
- App records correlate by source port and destination tuple where applicable.
- No password, secret, raw payload, authentication message, participant
  container name, or role mapping appears in the TSV.
- The same sanitized file is present in each eligible participant container;
  the exporter does not replace an existing destination.
- The separate Lab 5 exporter and `/tmp/lab5-evidence.tsv` behavior remain
  unchanged.

## Assessment rubric (10 points)

| Criterion | Points |
|---|---:|
| Correctly identifies the distinct participant source IPs without claiming container names from the TSV | 0–2 |
| Maps source IPs to targeted services using destination ports and application evidence | 0–2 |
| Distinguishes scan/connection observations, authentication attempts, and Cowrie's simulated login result | 0–2 |
| States only outcomes supported by client/application evidence and identifies what remains unproven | 0–2 |
| Produces an ordered UTC timeline and correlates Suricata with honeypot rows using source ports and endpoint tuples | 0–2 |

Award partial credit for a correctly qualified inference. Do not award credit
for interpreting a Suricata alert or connection alone as successful
authentication, or for claiming the planned role mapping was observed when
the live validation did not confirm it.
