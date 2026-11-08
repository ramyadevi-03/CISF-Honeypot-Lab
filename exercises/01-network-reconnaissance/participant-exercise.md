# Exercise 1: Network Reconnaissance and Suricata Log Investigation

## Objective

Discover the shared honeypot's five authorized TCP services from your assigned
Kali container, then use a participant-specific Suricata log excerpt to
correlate your scan by source IP, destination IP, port, and timestamp.

## Scope and safety

This exercise is authorized only against the lab target `10.77.0.10` and these
TCP ports: `21`, `80`, `2222`, `2223`, and `3306`. Do not scan other hosts or
ports, or use broad scans such as `-p-`, `-A`, or vulnerability scripts. Do not
attempt to log in to any honeypot service.

The lab network is isolated. Your instructor opens your assigned Kali terminal
and provides only your own Suricata evidence. The Suricata files and Docker
control socket are not available inside participant containers.

## Prerequisites

- An instructor-provided terminal in your assigned Kali container.
- Your participant identity (Kali-01 or Kali-02) and assigned IP address.
- The target IP `10.77.0.10`.

Do not run Docker commands in the participant terminal. If your Kali identity or
IP does not match your assignment, stop and ask the instructor before scanning.

## Instructions

### 1. Confirm your assigned Kali identity

Run:

```bash
hostname
ip -4 -o addr show dev eth0
```

Kali-01 should have address `10.77.0.11`; Kali-02 should have
`10.77.0.12`. Record your assigned address as **source IP**.

### 2. Run a TCP connect scan of only the authorized ports

Run this unprivileged TCP connect scan:

```bash
nmap -sT -Pn -n --reason -p 21,80,2222,2223,3306 10.77.0.10
```

Record each port's state. The expected result is that all five specified ports
are open on the target.

Nmap's `SERVICE` column in this scan is based on its local port-number
database. For ports `2222` and `2223`, that label may name an unrelated,
well-known service. A port label alone does not prove which application is
listening.

### 3. Identify the services

Use the service allocations for this lab:

| TCP port | Lab service |
|---:|---|
| 21 | FTP (OpenCanary) |
| 80 | HTTP (OpenCanary) |
| 2222 | SSH (Cowrie) |
| 2223 | Telnet (Cowrie) |
| 3306 | MySQL (OpenCanary) |

If your instructor asks you to verify Nmap's service fingerprinting, run this
optional, more active probe once:

```bash
nmap -sT -sV -Pn -n --reason -p 21,80,2222,2223,3306 10.77.0.10
```

Version detection sends additional protocol probes and can take longer. Do not
repeat it unnecessarily. It does not submit login credentials, but it can
create application-layer events in addition to connection records.

Record both the Nmap service result and the lab service allocation. Note any
difference rather than assuming a port-number label is definitive.

### 4. Review your assigned Suricata evidence

After your scan, your instructor will provide only the Suricata event rows
matching your assigned source IP and the target. You will not receive the full
multi-participant log.

Suricata EVE JSON uses top-level fields such as `timestamp`, `event_type`,
`src_ip`, `src_port`, `dest_ip`, and `dest_port` for flow events. Alert details
such as `signature_id` and `signature` are nested under `alert`. A flow event
describes observed network communication; an alert is a match to a detection
rule. `app_proto` may be empty when the sensor cannot identify an application
from the packets it observed.

Use your assigned source IP to identify your own traffic. For each relevant
row, note the timestamp, source endpoint, destination endpoint, event type,
and (for alerts) signature ID/name. The destination port is the service port;
the source port is usually an ephemeral client port.

### 5. Answer the investigation questions

Write your answers using your Nmap output and the Suricata excerpt provided by
your instructor:

1. What source IP was assigned to your Kali container, and what destination IP
   did you scan?
2. Which of the five authorized ports were open, and which lab services use
   those ports?
3. Choose one Suricata flow row. Which fields show the initiating participant,
   the target, and the target service port? What does its source port represent?
4. What timestamp is recorded for that event? How does it relate to the time
   you ran Nmap? Is the log timestamp UTC or local time?
5. Which connection alerts, if any, did Suricata record for your scan? Why
   should a TCP connect scan not be assumed to create FTP, HTTP, or MySQL
   authentication events?

## Expected observations

- Nmap reports `10.77.0.10` up and all five requested TCP ports open.
- The lab service allocations are FTP, HTTP, SSH, Telnet, and MySQL as listed
  above. Nmap's default service label can be misleading on the non-standard
  SSH/Telnet ports.
- Suricata records TCP flows with your source IP and target `10.77.0.10`.
- The existing Cowrie rules can alert on initial TCP SYN packets to ports
  `2222` and `2223` (SIDs `1000002` and `1000003`).
- A basic `-sT` scan performs TCP connection checks; it does not log in. The
  FTP/HTTP/MySQL rules require application payloads, so do not expect their
  alerts or authentication events from a basic port scan.
- `-sV` sends service probes and may cause additional application-level
  telemetry, but it still does not imply a successful login.

## Troubleshooting

- **Wrong Kali IP or identity:** Stop and ask the instructor to verify your
  assigned container. Do not use another participant's identity.
- **Nmap missing or scan cannot reach the target:** Confirm the instructor
  started the Kali lab and honeypot overlay. Do not change container
  networking or broaden the scan.
- **A port is `filtered`, `closed`, or absent:** Confirm the exact target and
  authorized port list with the instructor. Report the observed result; do not
  scan additional ports.
- **No Suricata excerpt yet:** Flow records may appear after the connection
  closes and the sensor flushes the event; allow up to 30 seconds. Give the
  instructor your assigned source IP and approximate scan time so they can
  filter the correct evidence. Cowrie SYN alerts may appear sooner.
- **No FTP/HTTP/MySQL alert:** A connect-only scan may not send the payload
  required by those rules. This is expected and is not proof that the service
  or sensor is unavailable.
