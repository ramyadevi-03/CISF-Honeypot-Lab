# Exercise 2: SSH and Telnet Honeypot Investigation

## Scenario

The lab monitoring team has observed remote-access attempts against a shared
honeypot. As an authorized CISF investigator, make one controlled dummy login
attempt to each of the designated Cowrie services, then examine your own
filtered evidence and correlate Cowrie's session records with Suricata's
connection alerts.

## Objective

Generate and investigate one SSH and one Telnet session from your assigned
Kali container. Identify the source, attempted username, Cowrie-recorded
authentication outcome, timestamp, session identifier, and corresponding
Suricata alert.

## Scope and safety

Only connect from your assigned Kali container to `10.77.0.10` on SSH port
`2222` and Telnet port `2223`. Make one manual attempt per protocol. Use only
the dummy credentials supplied below; never enter a personal, reused, or
operational password. Do not automate attempts, retry credentials, scan other
ports, or connect to any other host.

Cowrie is a honeypot that emulates a login and shell. A Cowrie event reporting
`cowrie.login.success` does not mean that a real account or host was accessed.
Cowrie may log Telnet passwords in clear text. Use only the dummy value and do
not include password fields or message text containing credentials in evidence
you share.

The instructor will provide only records filtered for your assigned source IP.
Do not access Docker, Cowrie's raw logs, or Suricata's complete logs from the
participant container.

## Prerequisites

- An instructor-provided terminal in your assigned Kali container.
- Your participant identity and assigned IP address.
- The shared target IP `10.77.0.10`.

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

### 2. Make one SSH dummy login attempt

Connect to Cowrie on port 2222:

```bash
ssh -p 2222 cisf-ssh-lab@10.77.0.10
```

If OpenSSH asks whether to trust the host key, verify the target is
`10.77.0.10:2222`, then enter `yes`. At the password prompt, enter this
exercise-only dummy password (it will not be displayed):

```text
CISF-Dummy-Password-2026
```

If Cowrie presents a simulated shell, note that the login event was generated
and type `exit` to close the session. Do not run commands in the simulated
shell.

### 3. Make one Telnet dummy login attempt

The supplied Kali image does not include a `telnet` command. Its installed
`curl` supports the Telnet protocol; use it as the client:

```bash
curl telnet://10.77.0.10:2223
```

At the `login:` prompt, enter `cisf-telnet-lab`. At `Password:`, enter
`CISF-Dummy-Password-2026`. If Cowrie presents a simulated shell, type `exit`
to close the session. The password may be logged by Cowrie; never use a real
password.

If `curl` is unavailable or reports that Telnet is an unsupported protocol,
stop and ask the instructor rather than installing software or changing the
container.

### 4. Review your filtered evidence

The instructor will give you a source-IP-filtered excerpt from Cowrie and
Suricata. Cowrie JSON event fields observed in this lab include:

- `eventid`: `cowrie.session.connect`, `cowrie.login.success`, or
  `cowrie.session.closed`.
- `timestamp`: UTC event time, written with a trailing `Z`.
- `session`: Cowrie session identifier; related events in one session share
  this value.
- `protocol`: `ssh` or `telnet`.
- `src_ip` and `src_port`: participant address and client-side port.
- `dst_ip` and `dst_port`: target address and service port.
- `username`: username recorded on the login event.

Cowrie login events also have a `password` field. In the tested lab, the SSH
login event contained an empty password value, while the Telnet event included
the supplied dummy value. Do not expect passwords to be consistently
represented, and do not request or distribute that field.

Suricata EVE alert records have top-level `timestamp`, `src_ip`, `src_port`,
`dest_ip`, and `dest_port` fields. Alert details are nested under `alert`,
including `signature_id` and `signature`. The existing signatures are
connection alerts: they detect the initial TCP connection, not the username
or password inside an SSH or Telnet session.

### 5. Answer the investigation questions

Use your command output and only your assigned log excerpt:

1. Which IP address initiated your SSH connection, and which target IP and
   port did it reach?
2. What username did you attempt, and what username did Cowrie record?
3. What authentication outcome did Cowrie record? What does that outcome mean
   (and not mean) for this honeypot?
4. Which UTC timestamp and Cowrie session identifier identify the login
   activity?
5. Which Suricata alert corresponds to the Cowrie session? Correlate the
   source and destination IPs, ports, and approximate timestamps. Does the
   Suricata alert identify credentials?

## Expected observations

- Your source address is `10.77.0.11` (Kali-01) or `10.77.0.12` (Kali-02).
- SSH reaches `10.77.0.10:2222`; Telnet reaches `10.77.0.10:2223`.
- In the tested lab, Cowrie recorded each dummy login as
  `cowrie.login.success`. This is the honeypot's emulated outcome, not
  successful authentication to a real system.
- Cowrie's `cowrie.session.connect` and login event share a `session` value.
  Login events record the protocol, participant source, target destination,
  username, event ID, and timestamp.
- Suricata can alert on the connection using SID `1000002` for SSH and SID
  `1000003` for Telnet. The alert can precede Cowrie's login event and does
  not report the credentials.
- Cowrie and Suricata record the participant's actual lab source IP.

## Troubleshooting

- **Unexpected source IP:** Stop and ask the instructor to verify the assigned
  container. Do not use another participant's container.
- **SSH host-key prompt or error:** Confirm the command targets
  `10.77.0.10` on port `2222`. If the host key differs from a prior session,
  stop and ask the instructor; do not bypass the warning.
- **SSH or Telnet does not connect:** Check the target and port with the
  instructor. Do not retry credentials or try other hosts.
- **No Telnet client:** This is expected. Use the tested `curl` Telnet command
  above; do not install packages in the Kali image.
- **No Cowrie or Suricata excerpt yet:** Ask the instructor to verify your
  source IP and allow up to 30 seconds for log events to appear. Do not repeat
  the login attempt unless the instructor authorizes it.
- **No Suricata credential details:** This is expected. The current SSH and
  Telnet signatures detect TCP connection attempts only.
