# Instructor Guide: Exercise 2

## Exercise overview

Participants make one dummy login attempt against each Cowrie listener from
their own Kali container, then investigate Cowrie session/login events and
correlate them with Suricata's SSH/Telnet connection alerts. The workflow is
manual; there is no grading automation.

Cowrie emulates successful logins and a shell. A `cowrie.login.success` event
is a honeypot result, not authentication to a real host or account. Cowrie may
record Telnet passwords in clear text, including in event message text. Use
only the exercise dummy password and never distribute raw password fields,
unfiltered messages, or the complete multi-participant logs.

## Lab initialization

From Ubuntu/WSL with Docker Desktop integration, run from the repository root:

```bash
bash ./scripts/lab.sh up 2
bash ./scripts/lab.sh test 2
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh status
```

For native Windows PowerShell, use the matching scripts instead:

```powershell
.\scripts\lab.ps1 up -Count 2
.\scripts\lab.ps1 test -Count 2
.\scripts\suricata.ps1 up
.\scripts\suricata.ps1 status
```

Use the same script family for teardown.

Expected identities are Kali-01 at `10.77.0.11`, Kali-02 at `10.77.0.12`,
and the shared target at `10.77.0.10`. Open only the assigned participant
terminal from the instructor-controlled console:

```bash
docker exec -it kali-01 bash
docker exec -it kali-02 bash
```

Keep Docker access and the Cowrie/Suricata logs on the instructor host. Do not
mount logs or the Docker socket into participant containers.

In the host PowerShell session, record the UTC start time immediately before
participants begin. Keep this session open while collecting evidence:

```powershell
$exerciseStartUtc = [DateTimeOffset]::UtcNow
Write-Output "Filter evidence from $exerciseStartUtc onward"
```

Run the participants' steps in order. Their source addresses should be
`10.77.0.11` and `10.77.0.12`.

## Expected SSH and Telnet behavior

Before opening participant terminals, stage the tested Telnet helper into
each assigned Kali container. For the default two participants:

```bash
for container in kali-01 kali-02; do
  docker cp ./exercises/02-ssh-telnet-investigation/telnet-login.pl \
    "$container:/tmp/cisf-telnet-login.pl"
done
```

For another assignment, replace the container names with the participants'
actual Kali containers. Participants run only the staged script; they do not
need Docker access.

SSH command:

```bash
ssh -p 2222 cisf-ssh-lab@10.77.0.10
```

Telnet command (the client handles Telnet negotiation and closes after one
dummy attempt):

```bash
perl /tmp/cisf-telnet-login.pl
```

The helper uses Perl's core `IO::Socket::INET` and `IO::Select` modules, sends
the fixed dummy username and password once after the corresponding prompts,
and closes the connection. It prints a clear timeout or connection error if
the expected prompts do not arrive. In this tested Cowrie configuration, both
dummy SSH and Telnet login attempts generated `cowrie.login.success`. This
means Cowrie accepted the attempt for its emulated session; it does not mean
a real host account was authenticated.

The observed login event ID is `cowrie.login.success`. Its `timestamp`,
`session`, `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, and
`username` fields identify the event. In the tested records, SSH's `password`
field was empty, while Telnet's contained the submitted dummy value. Cowrie's
`message` may also contain credentials. Do not show participants either
password field or raw message text.

The Suricata rules currently alert on initial TCP SYN packets:

| Protocol | Destination port | SID | Signature |
|---|---:|---:|---|
| SSH | 2222 | 1000002 | `CISF Cowrie SSH connection` |
| Telnet | 2223 | 1000003 | `CISF Cowrie Telnet connection` |

These are connection detections. They do not parse or identify credentials
inside an SSH/Telnet authentication exchange. Suricata's alert timestamp will
usually be earlier than Cowrie's login timestamp because the alert matches
connection setup.

## Read and filter Cowrie JSON events

Cowrie stores its JSON at
`/cowrie/cowrie-git/var/log/cowrie/cowrie.json` inside `cisf-cowrie`. Run the
following in the instructor's Windows PowerShell session. It temporarily copies
the raw file to the instructor host, filters it there to one participant, the
target ports, relevant event types, and the exercise start time, and removes
the temporary file even if filtering fails. The displayed fields omit
passwords and message text:

```powershell
$participantIp = '10.77.0.11'
if ($participantIp -notin @('10.77.0.11', '10.77.0.12')) {
    throw "Not an assigned participant IP: $participantIp"
}
$cowrieTemp = Join-Path $env:TEMP "cisf-cowrie-$PID-$([guid]::NewGuid().ToString('N')).json"
try {
    & docker cp 'cisf-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json' $cowrieTemp | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy Cowrie JSON from the container."
    }
    Get-Content -LiteralPath $cowrieTemp |
        ForEach-Object { if ($_){ $_ | ConvertFrom-Json } } |
        Where-Object {
            $_.src_ip -eq $participantIp -and
            $_.dst_ip -eq '10.77.0.10' -and
            $_.dst_port -in @(2222, 2223) -and
            $_.eventid -in @('cowrie.session.connect', 'cowrie.login.success', 'cowrie.session.closed') -and
            [DateTimeOffset]::Parse($_.timestamp) -ge $exerciseStartUtc
        } |
        Sort-Object timestamp |
        Select-Object timestamp, eventid, protocol, src_ip, src_port, dst_ip, dst_port, session, username |
        Format-List
}
finally {
    if (Test-Path -LiteralPath $cowrieTemp) {
        Remove-Item -LiteralPath $cowrieTemp -Force -ErrorAction Stop
    }
}
```

Set `$participantIp` to `10.77.0.12` and run the command again for Kali-02. Share
only that participant's filtered output. The temporary raw log remains
instructor-only and is removed after the command; output deliberately excludes
`password` and `message`, even when they are present in Cowrie JSON.

## Inspect and filter Suricata evidence

Use `suricata\logs\eve.json` on the instructor host. Select one participant at
a time. The query below includes only alert records for that participant and
the two Cowrie ports, beginning at the recorded activity start:

```powershell
$participantIp = '10.77.0.11'
$suricataEvents = Get-Content .\suricata\logs\eve.json |
    ForEach-Object { if ($_){ $_ | ConvertFrom-Json } }
$suricataEvents |
    Where-Object {
        $_.event_type -eq 'alert' -and
        $_.src_ip -eq $participantIp -and
        $_.dest_ip -eq '10.77.0.10' -and
        $_.dest_port -in @(2222, 2223) -and
        $_.alert.signature_id -in @(1000002, 1000003) -and
        [DateTimeOffset]::Parse($_.timestamp) -ge $exerciseStartUtc
    } |
    Sort-Object timestamp |
    Select-Object timestamp, src_ip, src_port, dest_ip, dest_port,
        @{Name='signature_id'; Expression={$_.alert.signature_id}},
        @{Name='signature'; Expression={$_.alert.signature}} |
    Format-Table -AutoSize
```

Repeat with `$participantIp = '10.77.0.12'`. EVE alert endpoint fields
(`src_ip`, `src_port`, `dest_ip`, `dest_port`) are top-level; the signature
metadata is nested under `alert`. EVE timestamps end in `+0000`; Cowrie
timestamps end in `Z`. Both are UTC.

To inspect the text alert file for the selected participant:

```powershell
$participantIp = '10.77.0.11'
Get-Content .\suricata\logs\fast.log |
    Where-Object {
        $_.Contains($participantIp) -and
        ($_.Contains('-> 10.77.0.10:2222') -or
         $_.Contains('-> 10.77.0.10:2223'))
    } |
    Select-Object -Last 20
```

Check that each excerpt contains only the chosen participant's address before
sharing it. Never share complete EVE/fast logs or raw Cowrie JSON.

## Correlation and answer key

1. Kali-01 initiated from `10.77.0.11`; Kali-02 initiated from `10.77.0.12`.
   The shared target is `10.77.0.10`; SSH uses destination port 2222 and
   Telnet uses 2223.
2. Cowrie records the participant-supplied SSH or Telnet username in
   `username`. For this exercise, the expected names are `cisf-ssh-lab` and
   `cisf-telnet-lab`, respectively.
3. The tested attempts produced `cowrie.login.success`. This is Cowrie's
   emulated outcome only; no real authentication occurred. SSH's observed
   event had an empty `password` field; Telnet's event recorded the dummy
   password. Do not distribute either credential-bearing field or
   `message`.
4. `timestamp` is UTC and `session` is the Cowrie session identifier. The
   `cowrie.session.connect` and login events for a session share the same
   identifier.
5. Match Cowrie and Suricata by source IP, source port, target IP, destination
   port, and nearby timestamps. SSH matches SID 1000002 and Telnet SID
   1000003. The alert represents the TCP connection, may precede the Cowrie
   login event, and does not identify the attempted username or password.

## Troubleshooting

- **Unexpected source address:** Stop and verify the participant's container
  assignment before proceeding.
- **SSH key warning or connect error:** Confirm the exact target and port.
  Investigate unexpected host-key changes with the lab operator; do not
  disable host-key checks.
- **Telnet helper missing:** Stage `telnet-login.pl` with the `docker cp`
  command above. Do not ask participants to install packages or use curl's
  interactive Telnet mode; that client may remain open after Cowrie closes
  the session.
- **Telnet prompt timeout:** Check that Cowrie is running and reachable at
  `10.77.0.10:2223`. Inspect only sanitized event metadata before deciding
  whether any further attempt is appropriate.
- **Cowrie event absent:** Confirm the relevant container is running, the
  participant entered one dummy login, and the chosen source IP is correct.
  Allow up to 30 seconds for logs to appear. Do not encourage repeated
  attempts.
- **Suricata event absent:** Confirm the alert destination port and source IP
  and that the scan-time filter is correct. The current signature detects a
  TCP SYN, not authentication content.
- **Only a `cowrie.session.connect` event:** The connection was observed, but
  there is no recorded login event to report. Do not infer an authentication
  outcome; ask the instructor to check the session and follow up before any
  retry.

## Cleanup and reset

No participant evidence file or automated grading artifact is created. For a
new run, record a fresh `$exerciseStartUtc` and share only newly filtered
events. Do not erase persistent Cowrie volumes or Suricata logs to reset the
exercise.

When the lab is no longer needed, stop the overlay and Kali containers:

```bash
bash ./scripts/suricata.sh down
bash ./scripts/lab.sh down
```

These commands stop the lab without deleting persistent volumes or existing
logs. Do not use `docker compose down -v`, `docker volume prune`, or manually
delete log files.
