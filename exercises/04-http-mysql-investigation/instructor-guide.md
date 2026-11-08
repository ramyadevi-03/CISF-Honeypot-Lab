# Instructor Guide: Exercise 4

## Exercise overview

Participants make one HTTP GET request and one dummy MySQL authentication
attempt from their assigned Kali container to OpenCanary at `10.77.0.10`.
They examine HTTP, MySQL connection, and MySQL login-attempt events and
correlate these with Suricata SIDs 1000005 and 1000006. The exercise is
manual; there is no grading automation.

OpenCanary's MySQL login event stores authentication data. Never distribute
raw MySQL JSON, password fields, or unfiltered events. Show only participant-
specific results with the username and non-secret metadata. Keep Docker access
and original logs on the instructor host.

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

Use the same script family for teardown. Expected participant addresses are
Kali-01 `10.77.0.11` and Kali-02 `10.77.0.12`; the shared target is
`10.77.0.10`. Open only the assigned terminal from the instructor-controlled
console:

```bash
docker exec -it kali-01 bash
docker exec -it kali-02 bash
```

Do not mount logs or the Docker socket into Kali. In the host PowerShell
session, record the UTC start time immediately before activity:

```powershell
$exerciseStartUtc = [DateTimeOffset]::UtcNow
Write-Output "Filter evidence from $exerciseStartUtc onward"
```

## Expected participant activity

### HTTP

The participant command is:

```bash
curl --verbose --location --max-redirs 3 --max-time 10 --output /dev/null \
  --write-out 'Final HTTP status: %{http_code}; redirects: %{num_redirects}\n' \
  http://10.77.0.10/
```

In the tested environment, both participants received final status `200` after
one redirect. OpenCanary logged HTTP GET as type 3000. The final request event
showed `logdata.PATH` `/index.html`, `HOSTNAME` `10.77.0.10`, `SKIN`
`nasLogin`, and `USERAGENT` `curl/8.22.0`. A redirect can produce multiple
Suricata HTTP alerts for one curl invocation; correlate by client source port
and timestamp rather than counting alerts as independent investigations.

### MySQL

The Kali image has no `mysql` client. Perl and `IO::Socket::INET` are already
installed. The participant guide includes a small Perl one-shot protocol
client. It reads the MySQL protocol v10 greeting, sends a single authentication
packet using dummy user `cisf-user` and dummy password `wrong`, reads the
server's response, and verifies MySQL error 1045 (access denied). It sends no
SQL and requires no package installation. Both Kali containers were tested
with this exact client.

Do not characterize the MySQL authentication as successful. The observed
server response is explicit rejection (error 1045), and the OpenCanary event
records an attempt rather than a success state.

## Verified OpenCanary event formats

OpenCanary writes JSON to `/var/tmp/opencanary.log` inside
`cisf-opencanary`. Actual records and the installed handlers confirm:

| Activity | `logtype` | Observed `logdata` |
|---|---:|---|
| HTTP GET | 3000 | `HOSTNAME`, `PATH`, `SKIN`, `USERAGENT` |
| MySQL connection made | 9003 | Empty object `{}` |
| MySQL authentication attempt | 8001 | `USERNAME` and `PASSWORD` |

Each event also observed `utc_time`, `src_host`, `src_port`, `dst_host`,
`dst_port`, and `node_id`. `utc_time` is UTC formatted as
`yyyy-MM-dd HH:mm:ss.ffffff` without a timezone suffix.

The type 9003 record proves a connection was made, but carries no credentials.
The type 8001 record proves an authentication packet was parsed; it does not
include a login-success outcome. OpenCanary's MySQL handler records the
password value, so filtering must project only the username and safe endpoint
fields before display.

## Suricata signatures

Existing lab rules:

```text
alert http any any -> $HOME_NET 80 (msg:"CISF OpenCanary HTTP GET"; flow:established,to_server; http.method; content:"GET"; sid:1000005; rev:1;)
alert tcp any any -> $HOME_NET 3306 (msg:"CISF OpenCanary MySQL login"; flow:established,to_server; dsize:>0; sid:1000006; rev:1;)
```

SID 1000005 detects an HTTP GET request. SID 1000006 detects payload on a
TCP flow to the MySQL service; it is not proof of a successful login or
necessarily a unique authentication attempt. One exchange can trigger several
SID 1000006 alerts. Suricata alerts have top-level endpoint fields and nested
`alert.signature_id`/`alert.signature`, but do not include OpenCanary request
metadata or credentials. EVE timestamps are UTC with `+0000`; OpenCanary
`utc_time` is also UTC.

## Filter OpenCanary events

Use this in the instructor's Windows PowerShell session, selecting one
participant at a time. It copies the original log to a temporary instructor-
host file, filters by source IP, destination, port, event type, and exercise
start time, and displays only safe selected fields. It omits `logdata.PASSWORD`
and removes the temporary file even if filtering fails:

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
            $_.src_host -eq $participantIp -and
            $_.dst_host -eq '10.77.0.10' -and
            $_.dst_port -in @(80, 3306) -and
            $_.logtype -in @(3000, 9003, 8001) -and
            [DateTimeOffset]::Parse(
                $_.utc_time,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal
            ) -ge $exerciseStartUtc
        } |
        Sort-Object utc_time |
        Select-Object utc_time, logtype, src_host, src_port, dst_host, dst_port,
            @{Name='path'; Expression={$_.logdata.PATH}},
            @{Name='user_agent'; Expression={$_.logdata.USERAGENT}},
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

Set `$participantIp` to `10.77.0.12` and run the command again for Kali-02.
The selected output deliberately omits the entire `logdata` object and
`PASSWORD`. Type 9003 events have no username or path; those fields will be
blank in the projected result. Share only one participant's output.

## Filter Suricata EVE alerts

This query displays only relevant HTTP and MySQL alerts for the selected
participant and recorded exercise time:

```powershell
$participantIp = '10.77.0.11'
$suricataEvents = Get-Content .\suricata\logs\eve.json |
    ForEach-Object { if ($_){ $_ | ConvertFrom-Json } }
$suricataEvents |
    Where-Object {
        $_.event_type -eq 'alert' -and
        $_.src_ip -eq $participantIp -and
        $_.dest_ip -eq '10.77.0.10' -and
        $_.dest_port -in @(80, 3306) -and
        $_.alert.signature_id -in @(1000005, 1000006) -and
        [DateTimeOffset]::Parse($_.timestamp) -ge $exerciseStartUtc
    } |
    Sort-Object timestamp |
    Select-Object timestamp, src_ip, src_port, dest_ip, dest_port,
        @{Name='signature_id'; Expression={$_.alert.signature_id}},
        @{Name='signature'; Expression={$_.alert.signature}} |
    Format-Table -AutoSize
```

Repeat with `$participantIp = '10.77.0.12'`. Correlate OpenCanary
`src_host`/`src_port`/`dst_host`/`dst_port` with Suricata
`src_ip`/`src_port`/`dest_ip`/`dest_port`. Expect the alert timestamp to be
close to, and often slightly before, OpenCanary's event timestamp.

## Answer key

1. Kali-01 source IP: `10.77.0.11`; Kali-02: `10.77.0.12`. HTTP destination
   is `10.77.0.10:80`; MySQL destination is `10.77.0.10:3306`.
2. In the tested OpenCanary configuration, the observed final HTTP request
   was `/index.html`, with user agent `curl/8.22.0`. The client requested `/`
   and followed one redirect.
3. OpenCanary `logtype` 9003 is the MySQL connection event;
   `logtype` 8001 is the parsed authentication attempt. The tested username
   is `cisf-user`. Neither OpenCanary record asserts successful login. The
   client received error 1045 (access denied).
4. `utc_time` gives OpenCanary's UTC event time. Correlate by source IP,
   source port, target IP, destination port, and nearby EVE `timestamp`.
5. SID 1000005 detects HTTP GET; SID 1000006 detects MySQL TCP payload.
   The alerts do not contain the HTTP path or MySQL credentials, and SID
   1000006 is not proof of login success. Multiple alerts can represent
   packets from a single exchange.

In the latest tests, Kali-01's MySQL authentication event was at
`14:10:29.050383Z` from source port `32836`; Kali-02's was at
`14:10:29.475531Z` from source port `60506`. Both were `logtype` 8001 with
username `cisf-user`; corresponding SID 1000006 alerts used the same source
ports. The server returned error 1045 to both. Use the current filtered events
during a workshop rather than relying on these sample ports or times.

## Troubleshooting

- **Wrong participant IP:** Stop and verify the Kali assignment before
  generating traffic.
- **HTTP response is 302:** The root redirects. Use `--location` to follow it;
  final status 200 is expected.
- **HTTP event path differs from `/`:** OpenCanary can record the redirected
  `/index.html` request. Correlate using source port and time.
- **No MySQL client:** Expected; use the tested preinstalled Perl command.
  Do not install packages or connect to a different target.
- **Unexpected MySQL response:** Do not claim success or retry. Ask the
  instructor to check service state and the returned MySQL error.
- **9003 without 8001:** The TCP connection occurred but no authentication
  packet was logged. Do not infer an authentication attempt or ask the
  participant to retry until you have investigated the probe.
- **No logs yet:** Confirm participant source IP and exercise start time and
  allow up to 30 seconds for events to appear.
- **Credential data shown:** Do not distribute the raw output. Use the
  filtered commands above and share only the participant-specific result.

## Cleanup and reset

No evidence files or automated grading artifacts are created. For another
session, record a fresh `$exerciseStartUtc`; do not clear persistent logs or
volumes.

When the lab is no longer needed, stop the overlay and Kali participants:

```bash
bash ./scripts/suricata.sh down
bash ./scripts/lab.sh down
```

For PowerShell deployment, use `.\scripts\suricata.ps1 down` and
`.\scripts\lab.ps1 down`. Do not use `docker compose down -v`,
`docker volume prune`, or manually delete persistent logs.
