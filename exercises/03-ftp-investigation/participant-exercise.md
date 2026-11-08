# Exercise 3: FTP Authentication Investigation

## Scenario

The lab monitoring team is reviewing an attempted FTP login to a legacy
file-transfer service. Make one controlled login attempt to the designated
FTP honeypot from your assigned Kali container. Then investigate your own
OpenCanary event and correlate it with Suricata's FTP alert.

## Objective

Observe the FTP service banner and authentication responses, identify what
OpenCanary recorded about the attempt, and correlate the event with Suricata
using participant IP, destination, client source port, and timestamp.

## Scope and safety

Only connect from your assigned Kali container to `10.77.0.10` on TCP port
`21`. Make one manual login attempt using only the dummy username and password
below. Never use a personal, reused, or operational password. Do not retry,
automate attempts, or connect to any other host or port.

FTP does not encrypt the session. OpenCanary records the submitted password
for this lab's FTP login event. Use only the dummy password, do not share raw
FTP transcripts or unfiltered events, and do not include password fields in
your investigation notes.

The instructor will provide only evidence filtered for your assigned source
IP. Do not access Docker, OpenCanary's raw logs, or the complete Suricata logs
from the participant container.

## Prerequisites

- An instructor-provided terminal in your assigned Kali container.
- Your participant identity and assigned IP address.
- The shared honeypot IP `10.77.0.10`.

If your identity or address does not match your assignment, stop and ask the
instructor before connecting.

## Instructions

### 1. Confirm your assigned identity and source IP

Run:

```bash
hostname
ip -4 -o addr show dev eth0
```

Kali-01 should have address `10.77.0.11`; Kali-02 should have
`10.77.0.12`. Record this as your **source IP**.

### 2. Connect and make one dummy FTP login attempt

The installed Kali image includes `curl` with FTP support. Run:

```bash
curl --verbose --max-time 10 --user 'cisf-ftp-lab' ftp://10.77.0.10/
```

At the password prompt, enter this exercise-only dummy password:

```text
CISF-Dummy-Password-2026
```

Do not put the password into the command line. In the verbose output, observe:

- The server banner: `220 FTP server ready`.
- The server asks for a password with response `331`.
- The dummy login is rejected with response `530`.

`curl` normally exits with code 67 for this expected rejected login. This is
not a client or network failure when the transcript shows the `530`
authentication response. Do not retry the login.

Verbose FTP output may contain protocol commands. Do not copy or share the raw
transcript; the instructor will provide a filtered record that excludes the
password.

### 3. Review your assigned evidence

The instructor will give you an excerpt filtered to your assigned source IP
and exercise time. In the observed OpenCanary JSON:

- `utc_time` is the event timestamp in UTC.
- `logtype` is the event type. Type `2000` records the FTP login attempt;
  type `2001` indicates authentication was initiated.
- `src_host` and `src_port` identify your Kali address and client-side port.
- `dst_host` and `dst_port` identify the target and service port.
- `logdata.USERNAME` contains the attempted username on type `2000`.
- `node_id` identifies the OpenCanary sensor.

The `logdata` object also contains `PASSWORD`. It is intentionally omitted
from the evidence shown to participants. OpenCanary's type `2000` event
records the submitted attempt, but does not include an explicit authentication
outcome field. The `530` response is observed in the FTP client transcript.

Suricata's FTP alert appears in EVE as `event_type` `alert`. Endpoint fields
(`src_ip`, `src_port`, `dest_ip`, `dest_port`) are top-level; signature
metadata is under `alert`. Existing signature SID `1000004` looks for the FTP
`USER` command on an established connection. It is an application-protocol
alert, not a generic connection-only alert. It does not record the password
or determine whether authentication succeeded.

### 4. Answer the investigation questions

Use your command output and only your assigned log excerpt:

1. What source IP initiated the FTP session, and what target IP and port did
   it reach?
2. What FTP banner did the server present, and which FTP response codes
   appeared during the login?
3. What username did OpenCanary record, and which `logtype` identifies the
   login attempt?
4. What UTC timestamp and client source port identify the OpenCanary login
   event?
5. Which Suricata alert corresponds to your attempt? Correlate source IP,
   source port, destination IP, destination port, and time. What does SID
   `1000004` detect, and what authentication information does it not prove?

## Expected observations

- Your source address is `10.77.0.11` (Kali-01) or `10.77.0.12` (Kali-02).
- The FTP endpoint is `10.77.0.10:21`.
- The banner is `220 FTP server ready`; the server responds `331` before
  password entry and `530 Sorry, Authentication failed.` after the dummy
  attempt.
- In the tested lab, OpenCanary records `logtype` 2000 with
  `logdata.USERNAME` `cisf-ftp-lab`. Its event includes `utc_time`,
  `src_host`, `src_port`, `dst_host`, and `dst_port`. It also stores the
  password; do not request, copy, or distribute it.
- The FTP connection may also generate OpenCanary `logtype` 2001. The
  authentication-attempt record is type 2000.
- Suricata generates SID `1000004` (`CISF OpenCanary FTP login`) for the
  FTP `USER` command. It identifies the same network flow, but does not show
  the password or prove the authentication outcome.

## Troubleshooting

- **Unexpected source IP:** Stop and ask the instructor to verify your
  assigned container.
- **`curl` reports FTP unsupported:** Stop and ask the instructor. Do not
  install a package or use another host.
- **No banner or connection timeout:** Confirm the target and port with the
  instructor. Do not try another port or target.
- **`530` response:** This is the expected rejection of the dummy login; do
  not retry.
- **No OpenCanary or Suricata evidence yet:** Ask the instructor to verify
  your source IP and allow up to 30 seconds for logs to appear. Do not repeat
  the login attempt.
- **Password visible in output:** Do not distribute that transcript. Ask the
  instructor for the sanitized, participant-specific evidence instead.
