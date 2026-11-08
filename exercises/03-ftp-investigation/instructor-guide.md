# Instructor Guide: Exercise 3

## Exercise overview

Participants make one dummy FTP login attempt from their assigned Kali
container to OpenCanary at `10.77.0.10:21`. They investigate the OpenCanary
authentication event and correlate it with Suricata SID `1000004`. The activity
is manual; there is no grading automation.

FTP is unencrypted. OpenCanary records submitted FTP credentials in its JSON
log. Never distribute raw OpenCanary FTP events, the `PASSWORD` field, or a
raw verbose FTP transcript. Filter evidence to one participant and omit
passwords before sharing it.

## Lab initialization

From Ubuntu/WSL with Docker Desktop integration, run from the repository root:

```bash
bash ./scripts/lab.sh up 2
bash ./scripts/lab.sh test 2
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh status
```

For native Windows PowerShell, use:

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

Keep Docker administration and complete logs on the instructor host. Do not
mount logs or the Docker socket into participant containers.

Immediately before the attempts, record a UTC start time in the host
PowerShell session and keep that session open:

```powershell
$exerciseStartUtc = [DateTimeOffset]::UtcNow
Write-Output "Filter evidence from $exerciseStartUtc onward"
```

## Participant FTP procedure

The current Kali image includes `curl` with FTP support. Participants identify
their IP and make one attempt using this command:

```bash
hostname
ip -4 -o addr show dev eth0
curl --verbose --max-time 10 --user 'cisf-ftp-lab' ftp://10.77.0.10/
```

At the password prompt, have them enter only the dummy password
`CISF-Dummy-Password-2026`. Do not enter the password into the command line.
The expected interaction is:

```text
220 FTP server ready
331 Password required for cisf-ftp-lab.
530 Sorry, Authentication failed.
```

`curl` normally exits with code 67 because the server rejects the login. Treat
that as the expected outcome only when the `530` response appears. Do not ask
participants to retry.

Verbose FTP output can contain protocol commands and credentials. Do not
collect or share the raw transcript. Provide only sanitized, participant-IP
filtered logs.

## Verified OpenCanary event format

OpenCanary logs to `/var/tmp/opencanary.log` inside `cisf-opencanary`. The
following field names and FTP event semantics were inspected in the installed
OpenCanary handler and actual JSON:

- `logtype` 2001 is emitted when authentication is initiated.
- `logtype` 2000 records the FTP login attempt. Its `logdata.USERNAME` and
  `logdata.PASSWORD` contain the submitted credentials.
- `utc_time` is the event time in UTC (format observed:
  `yyyy-MM-dd HH:mm:ss.ffffff`, without a trailing timezone suffix).
- `src_host`, `src_port`, `dst_host`, and `dst_port` identify the endpoints.
- `node_id` identifies the sensor.

The type 2000 record has no explicit authentication-result field. The client
observed `530 Sorry, Authentication failed.`; do not describe the OpenCanary
record itself as carrying a separate success/failure outcome.

Suricata rule SID `1000004` is:

```text
alert tcp any any -> $HOME_NET 21 (msg:"CISF OpenCanary FTP login"; flow:established,to_server; content:"USER "; nocase; sid:1000004; rev:1;)
```

It alerts on the FTP `USER` command on an established flow. It is an
application-command detection, rather than a generic TCP connection alert. It
does not identify the password or authenticate/reject the login. In EVE,
endpoint fields are top-level and signature information is nested under
`alert`. EVE timestamps use UTC with `+0000`; OpenCanary's `utc_time` is also
UTC.

## Filter OpenCanary logs

Run this in the instructor's Windows PowerShell session, changing
`$participantIp` for each participant. It copies the raw file to a temporary
instructor-host file, filters by source, target, port, event type, and exercise
time, and displays only the username and non-secret event fields. The
temporary file is removed even if filtering fails:

```powershell
$participantIp = '10.77.0.11'
if ($participantIp -notin @('10.77.0.11', '10.77.0.12')) {
    throw "Not an assigned participant IP: $participantIp"
}
$canaryTemp = Join-Path $env:TEMP "cisf-opencanary-$PID-$([guid]::NewGuid().ToString('N')).json"
try {
    & docker cp 'cisf-opencanary:/var/tmp/opencanary.log' $canaryTemp | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not copy OpenCanary log from the container."
    }
    Get-Content -LiteralPath $canaryTemp |
        ForEach-Object { if ($_){ $_ | ConvertFrom-Json } } |
        Where-Object {
            $_.logtype -eq 2000 -and
            $_.src_host -eq $participantIp -and
            $_.dst_host -eq '10.77.0.10' -and
            $_.dst_port -eq 21 -and
            [DateTimeOffset]::Parse(
                $_.utc_time,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal
            ) -ge $exerciseStartUtc
        } |
        Sort-Object utc_time |
        Select-Object utc_time, logtype, src_host, src_port, dst_host, dst_port,
            @{Name='username'; Expression={$_.logdata.USERNAME}},
            node_id |
        Format-List
}
finally {
    if (Test-Path -LiteralPath $canaryTemp) {
        Remove-Item -LiteralPath $canaryTemp -Force -ErrorAction Stop
    }
}
```

Repeat with `$participantIp = '10.77.0.12'`. This output intentionally omits
`logdata.PASSWORD`, the complete `logdata` object, and any raw transcript.
Share only one participant's filtered output with that participant.

## Filter Suricata EVE alerts

Run this for the same participant. It selects only FTP SID 1000004 events from
the recorded exercise time:

```powershell
$participantIp = '10.77.0.11'
$suricataEvents = Get-Content .\suricata\logs\eve.json |
    ForEach-Object { if ($_){ $_ | ConvertFrom-Json } }
$suricataEvents |
    Where-Object {
        $_.event_type -eq 'alert' -and
        $_.src_ip -eq $participantIp -and
        $_.dest_ip -eq '10.77.0.10' -and
        $_.dest_port -eq 21 -and
        $_.alert.signature_id -eq 1000004 -and
        [DateTimeOffset]::Parse($_.timestamp) -ge $exerciseStartUtc
    } |
    Sort-Object timestamp |
    Select-Object timestamp, src_ip, src_port, dest_ip, dest_port,
        @{Name='signature_id'; Expression={$_.alert.signature_id}},
        @{Name='signature'; Expression={$_.alert.signature}} |
    Format-Table -AutoSize
```

Repeat with `$participantIp = '10.77.0.12'`. Share only that participant's
filtered rows. Never distribute the complete EVE file.

To correlate, match OpenCanary `src_host` to Suricata `src_ip`,
`src_port` to `src_port`, `dst_host` to `dest_ip`, and `dst_port` to
`dest_port`. The Suricata alert may precede the OpenCanary login record because
the rule matches the FTP `USER` command before the password exchange.

## Expected results and answer key

1. Kali-01 source: `10.77.0.11`; Kali-02 source: `10.77.0.12`. Destination:
   `10.77.0.10:21`.
2. Banner: `220 FTP server ready`; username command response:
   `331 Password required for cisf-ftp-lab.`; expected dummy-authentication
   response: `530 Sorry, Authentication failed.`. `curl` generally exits 67
   on this expected rejected login.
3. OpenCanary's login event has `logtype` 2000. It records
   `logdata.USERNAME` as `cisf-ftp-lab`. The record also stores the password,
   which must not be shared. The event has no separate authentication
   outcome field.
4. The UTC event timestamp is `utc_time`; the client ephemeral port is
   `src_port`. OpenCanary logs source/destination IP and port in
   `src_host`, `src_port`, `dst_host`, and `dst_port`.
5. Suricata SID 1000004 (`CISF OpenCanary FTP login`) matches an FTP `USER`
   command. Correlate source port and endpoint IPs/ports plus timestamps.
   The alert does not contain the password and does not prove the
   authentication result.

In the executed tests, Kali-01 (`10.77.0.11`) used source port `43762` and
Kali-02 (`10.77.0.12`) used source port `49466`. Both received FTP code 530.
OpenCanary recorded type 2000 with username `cisf-ftp-lab`; Suricata recorded
SID 1000004 for each matching source port. Use the filtered current exercise
records rather than treating these sample ports or timestamps as fixed values.

## Troubleshooting

- **Wrong participant IP:** Stop and verify the assigned Kali container.
- **FTP client missing or protocol unsupported:** The current Kali image has
  `curl` with FTP support. If it is unavailable, stop and ask the instructor;
  do not install packages or use another target.
- **Connection timeout or no `220` banner:** Verify the overlay and target
  service with the lab operator. Do not try another host or port.
- **`530` response:** This is the expected rejected dummy authentication.
  Do not repeat the attempt.
- **OpenCanary or Suricata evidence not present:** Verify the IP, source port,
  timestamp filter, and destination port; allow up to 30 seconds for log
  delivery. Do not ask for a retry unless the instructor determines one is
  necessary.
- **Credential-bearing output:** Do not distribute it. Repeat the filtering
  command and share only its sanitized output.

## Cleanup and reset

No evidence files or automated grading artifacts are created. To run a later
session, record a fresh `$exerciseStartUtc`; do not clear persistent logs or
volumes.

When the lab is no longer needed, stop the overlay and Kali participants:

```bash
bash ./scripts/suricata.sh down
bash ./scripts/lab.sh down
```

For a PowerShell deployment, use `.\scripts\suricata.ps1 down` and
`.\scripts\lab.ps1 down` instead. Do not use `docker compose down -v`,
`docker volume prune`, or manually delete persistent logs.
