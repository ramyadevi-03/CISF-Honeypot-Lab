# Lab 6: Mixed-Log Forensic Investigation

## Scenario

The CISF monitoring team has collected a time-bounded set of sanitized
Suricata, Cowrie, and OpenCanary records from activity against the workshop's
shared honeypot. The events came from multiple lab participants, but the
evidence file does not label participants by container name or disclose the
instructor's activity assignments.

You are an analyst asked to reconstruct what happened from the combined
records. Attribute activity by source IP, identify the targeted services,
distinguish network discovery from application authentication, and build a
chronological account supported by the evidence.

## Scope and safety

- Investigate only the combined evidence file provided by the instructor.
- Do not access Docker, raw Cowrie/OpenCanary logs, Suricata EVE/fast logs, or
  another participant's container.
- Do not attempt to contact a source IP or target based on the evidence.
- Do not treat a Suricata alert, connection, authentication attempt, or
  Cowrie-emulated login as proof of real-system access.
- Do not share usernames or other participant-specific details outside the
  workshop investigation.

## Evidence file

The instructor provides `/tmp/lab6-mixed-evidence.tsv` inside your assigned
Kali container. The same combined dataset may be provided to multiple
participants. It contains source IPs for attribution, but does not contain
Kali container names or an answer key. It is not a raw log export.

The TSV retains the Lab 5 16-column schema:

```text
dataset	timestamp	event_type	protocol	service	src_ip	src_port	dest_ip	dest_port	signature_id	signature	session	username	path	user_agent	outcome
```

Timestamps are normalized to UTC and end with `Z`; rows are sorted
chronologically. Suricata `flow` rows can describe observed communication
without an alert signature. Suricata `alert` rows include a signature ID.
Cowrie and OpenCanary rows contain selected event metadata. Passwords, raw
payloads, and authentication message fields are excluded.

## Investigation commands

Set the evidence path and inspect its header and first records:

```bash
EVIDENCE=/tmp/lab6-mixed-evidence.tsv
head -n 1 "$EVIDENCE"
head -n 15 "$EVIDENCE"
```

Count distinct source IPs:

```bash
awk -F '\t' 'NR > 1 {print $6}' "$EVIDENCE" | sort -u
awk -F '\t' 'NR > 1 {seen[$6]=1} END {for (ip in seen) n++; print n+0}'
```

Summarize records by dataset and service:

```bash
awk -F '\t' 'NR > 1 {count[$1, $5]++} END {
  for (key in count) print key, count[key]
}' "$EVIDENCE" | sort
```

List source IPs and the services they contacted:

```bash
awk -F '\t' 'NR > 1 {print $6, $5, $9}' "$EVIDENCE" | sort -u
```

Inspect Suricata flows and alerts separately:

```bash
awk -F '\t' 'NR > 1 && $1 == "suricata" && $3 == "flow" {print}' "$EVIDENCE"
awk -F '\t' 'NR > 1 && $1 == "suricata" && $3 == "alert" {print}' "$EVIDENCE"
```

Inspect application events without printing raw messages:

```bash
awk -F '\t' 'NR > 1 && ($1 == "cowrie" || $1 == "opencanary") {
  print $2, $1, $3, $5, $6, $7, $8, $9, $12, $13, $16
}' "$EVIDENCE" | sort -k1,1
```

Filter one source IP across all evidence sources:

```bash
IP=10.77.0.11
awk -F '\t' -v ip="$IP" 'NR > 1 && $6 == ip {print}' "$EVIDENCE" | sort -k2,2
```

Filter Suricata signatures and correlate by the complete network tuple:

```bash
awk -F '\t' 'NR > 1 && $1 == "suricata" && $3 == "alert" {
  print $2, $6, $7, $8, $9, $10, $11
}' "$EVIDENCE" | sort -k1,1

awk -F '\t' -v ip="$IP" 'NR > 1 && $6 == ip {
  print $2, $1, $3, $5, $6, $7, $8, $9, $10, $12, $16
}' "$EVIDENCE" | sort -k1,1
```

The client source port can link an application event to a Suricata event for
the same source IP, destination IP, and destination service port. Timestamps
may differ slightly across sensors. Some events, such as a MySQL connection
record without a matching authentication record, are not proof that an
authentication attempt occurred.

## Investigation questions

Prepare a short report answering each question using specific evidence rows:

1. How many distinct participant source IPs appear in the evidence?
2. Which source IPs interacted with each of the five services?
3. Which observations indicate scanning or connection attempts, and which
   indicate application-level authentication attempts?
4. Which authentication outcomes can be established from application logs?
   Which outcomes remain unknown or are only simulated by Cowrie?
5. Reconstruct the event timeline in UTC. Which Suricata alerts correspond to
   Cowrie or OpenCanary records based on source IP/port, destination IP/port,
   service, and nearby timestamps?
6. Are any Suricata alerts duplicated or unpaired with application events?
   Give evidence-based explanations rather than assuming success or failure.

## Deliverable

Submit a concise incident timeline and answer the questions. Cite source IPs,
timestamps, service ports, event types, and signature IDs as applicable. Do
not include passwords, raw payloads, or conclusions unsupported by the
provided evidence.
