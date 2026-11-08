# Lab 5: Suricata Alert Analysis and Incident Reconstruction

## Scenario

Your assigned Kali container generated multiple network events against the shared honeypot at `10.77.0.10`. Your task is to investigate that activity without using Docker, without reading the original log files, and without receiving precomputed conclusions.

The instructor has exported a sanitized evidence file for your assigned source IP into your Kali container. Use only that file to reconstruct what happened.

## Objective

Determine which Suricata alerts, Cowrie events, and OpenCanary events belong to your session, identify the services contacted, correlate the activity by source IP, destination IP, source port, destination port, and timestamp, and prepare a short incident reconstruction summary.

## Scope and safety

- Use only the exported evidence file in your container.
- Do not access Docker.
- Do not read raw multi-participant logs or the original Suricata, Cowrie, or OpenCanary files.
- Do not share credential values or raw password fields.
- Limit your analysis to the isolated CISF lab network.
- Do not assume a login succeeded unless the actual evidence shows it.

## Required evidence location

The sanitized record file is available inside your Kali container at:

```bash
/tmp/lab5-evidence.tsv
```

## Step 1: Confirm your source IP

```bash
hostname
ip -4 -o addr show dev eth0
```

Record the IPv4 address. Expected values are:

- Kali-01: `10.77.0.11`
- Kali-02: `10.77.0.12`

## Step 2: Inspect the evidence file

List the exported file and review the first records:

```bash
ls -l /tmp/lab5-evidence.tsv
head -n 20 /tmp/lab5-evidence.tsv
```

The file is a TSV export with these columns:

```text
dataset	timestamp	event_type	protocol	service	src_ip	src_port	dest_ip	dest_port	signature_id	signature	session	username	path	user_agent	outcome
```

`dataset` identifies whether the row came from Suricata, Cowrie, or OpenCanary. Timestamps are normalized to UTC ISO 8601 and end in `Z`. Each record has exactly 16 tab-separated columns.

## Step 3: Identify your relevant records

Set your source IP and filter the evidence to exact source-IP matches:

```bash
IP=10.77.0.11
awk -F '\t' -v ip="$IP" '$6 == ip {print}' /tmp/lab5-evidence.tsv | head -n 30
```

For Kali-02, set `IP=10.77.0.12`.

View all rows for the five services:

```bash
grep -E 'ssh|telnet|ftp|http|mysql' /tmp/lab5-evidence.tsv | sort -k2,2 | head -n 80
```

To focus on the Suricata alert records:

```bash
awk -F '\t' '$1 == "suricata" {print}' /tmp/lab5-evidence.tsv | sort -k2,2 | head -n 80
```

To focus on host/application logs:

```bash
awk -F '\t' '$1 == "cowrie" || $1 == "opencanary" {print}' /tmp/lab5-evidence.tsv | sort -k2,2 | head -n 80
```

Filter the Suricata records by a signature ID:

```bash
awk -F '\t' -v sid="1000004" '$1 == "suricata" && $10 == sid {print}' /tmp/lab5-evidence.tsv
```

## Step 4: Reconstruct the timeline

Build a simple chronological view of events associated with your IP:

```bash
awk -F '\t' -v ip="$IP" '$6 == ip {print}' /tmp/lab5-evidence.tsv | sort -k2,2
```

Replace the IP with your own participant IP before running the command.

Look for these patterns:

- Suricata alert rows with `signature_id` values.
- Cowrie connection events for SSH/Telnet with `event_type` values such as `cowrie.session.connect`.
- OpenCanary records for HTTP, FTP, and MySQL events.
- Source ports and destination ports that match the same service flow.

## Step 5: Match each service to the right evidence

Use the exported rows to identify the activity for each service:

```bash
awk -F '\t' -v ip="$IP" '$6 == ip && ($5 == "ssh" || $5 == "telnet" || $5 == "ftp" || $5 == "http" || $5 == "mysql") {print}' /tmp/lab5-evidence.tsv | sort -k2,2
```

Look for:

- SSH and Telnet connections from your source IP to `10.77.0.10` on ports `2222` and `2223`.
- FTP login attempt evidence from `dst_port` `21`.
- HTTP GET request evidence on `dst_port` `80`.
- MySQL connection and authentication-attempt evidence on `dst_port` `3306`.

## Step 6: Distinguish connection events from authentication attempts

Do not assume that a login succeeded just because there is a connection or a service port.

Check the `event_type`, `service`, and `outcome` columns.

Examples:

- A Suricata alert indicates a network event, not necessarily a successful login.
- A Cowrie `session.connect` event shows a connection was opened.
- An OpenCanary 8001-type MySQL event shows an authentication attempt, not a confirmed database login.
- Only the actual application evidence can support an outcome assertion.

## Investigation questions

Answer the following in your own short written summary:

1. Which Suricata alerts are associated with your source IP and which services do they reference?
2. Which destination ports were contacted, and what do they indicate about the services in use?
3. Which Cowrie or OpenCanary rows correspond to the SSH/Telnet/FTP/HTTP/MySQL activity from your Kali host?
4. What is the approximate timeline of those events, and how do the timestamps and source ports correlate between Suricata and the honeypot logs?
5. Which events represent connection attempts, authentication attempts, or potential successful activity, and which do not prove success?

## Expected observations

- Your evidence file contains rows from at least the Suricata, Cowrie, and OpenCanary sources.
- The destination IP is `10.77.0.10`.
- The services appear on ports `2222`, `2223`, `21`, `80`, and `3306`.
- Source ports vary per event, but the destination IP and service ports remain consistent.
- The file intentionally removes password and other sensitive values.
- The evidence supports incident reconstruction but does not include the original raw logs.

## Troubleshooting

- If `ls /tmp/lab5-evidence.tsv` fails, ask the instructor to regenerate the export.
- If your IP is not present, confirm that you are using the correct Kali container.
- If your evidence file is empty, the instructor may need to generate fresh events for the current lab window.
- If a command returns no matches, reduce the filter or check the file header to confirm the fields.

## Deliverable

Prepare a brief incident summary of 5 to 8 sentences that answers the five questions above using only the sanitized evidence file. Focus on the actual evidence, the sequence of events, and the services involved.
