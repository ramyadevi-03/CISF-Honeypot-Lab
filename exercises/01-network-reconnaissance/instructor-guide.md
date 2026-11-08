# Instructor Guide: Exercise 1

## Exercise overview

Participants use their assigned Kali container to discover the five authorized
TCP ports on `10.77.0.10` and correlate their traffic with Suricata EVE
records. The activity is manual: there is no grading script or generated
evidence. Give each participant only log rows filtered to that participant's
source IP.

## Lab setup

From Ubuntu/WSL with Docker Desktop integration, run these commands from the
repository root:

```bash
bash ./scripts/lab.sh up 2
bash ./scripts/lab.sh test 2
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh status
```

Use the same Bash lab lifecycle commands for setup and cleanup so Compose uses
the same project identity for the Kali containers.

Expected participant addresses are Kali-01 `10.77.0.11` and Kali-02
`10.77.0.12`; the shared target is `10.77.0.10`. The target network must be
internal (`cisf-lab-net`, `10.77.0.0/24`). Existing compose services do not
publish honeypot ports to the host.

Open the assigned participant terminal from the instructor's controlled
console, one container per participant. Run each command in its own terminal
window; exit the first shell before opening another in the same window:

```bash
docker exec -it kali-01 bash
docker exec -it kali-02 bash
```

Do not give participants Docker access, mount the Docker socket, or mount the
Suricata log directory into Kali. The participant containers have no mounts;
leave the complete logs on the instructor host.

Immediately before the scan, record the start time in the instructor's
PowerShell session and keep that session open while participants scan. Run the
following in the Windows host PowerShell terminal:

```powershell
$scanStartUtc = [DateTimeOffset]::UtcNow
Write-Output "Filter evidence from $scanStartUtc onward"
```

## Expected participant results

The basic scan command is:

```bash
nmap -sT -Pn -n --reason -p 21,80,2222,2223,3306 10.77.0.10
```

Expected states and lab service mapping:

| Port | Expected state | Lab service |
|---:|---|---|
| 21/tcp | open | FTP — OpenCanary |
| 80/tcp | open | HTTP — OpenCanary |
| 2222/tcp | open | SSH — Cowrie |
| 2223/tcp | open | Telnet — Cowrie |
| 3306/tcp | open | MySQL — OpenCanary |

Nmap's `SERVICE` column is a port-number database label on a plain connect
scan. For the tested Kali Nmap version, it labelled 2222 as `EtherNetIP-1` and
2223 as `rockwell-csp2`; these labels do not identify the actual listeners.
The optional participant `-sV` command identifies SSH, Telnet, and the
OpenCanary services by protocol probing, and can take around 40 seconds in
this environment. It creates more application-level traffic than the basic
scan; do not represent it as a login attempt.

## Inspect and filter Suricata logs

Use `suricata\logs\eve.json` on the instructor host. The following PowerShell
commands produce only the selected participant's records to the shared target
on the five exercise ports. Set the IP to the participant whose evidence you
are preparing; run it separately for each participant:

After the scan, allow up to 30 seconds for Suricata to write its flow events.
Cowrie SYN alerts may be available earlier.

```powershell
$participantIp = '10.77.0.11'
$exercisePorts = @(21, 80, 2222, 2223, 3306)
$events = Get-Content .\suricata\logs\eve.json |
    ForEach-Object { if ($_){ $_ | ConvertFrom-Json } }
$events |
    Where-Object {
        $_.src_ip -eq $participantIp -and
        $_.dest_ip -eq '10.77.0.10' -and
        $_.dest_port -in $exercisePorts -and
        $_.event_type -in @('flow', 'alert') -and
        [DateTimeOffset]::Parse($_.timestamp) -ge $scanStartUtc
    } |
    Sort-Object timestamp |
    Select-Object -Last 30 |
    Select-Object timestamp, event_type, src_ip, src_port, dest_ip, dest_port,
        app_proto,
        @{Name='signature_id'; Expression={$_.alert.signature_id}},
        @{Name='signature'; Expression={$_.alert.signature}},
        @{Name='flow_state'; Expression={$_.flow.state}} |
    Format-Table -AutoSize
```

Repeat with `$participantIp = '10.77.0.12'` for Kali-02. This limits the output
to events from the recorded scan start and the latest 30 matching rows. If
participants scan later, record a new `$scanStartUtc` before their scan. Share
only the resulting participant-specific rows with that participant; do not
send the unfiltered EVE file or another participant's output.

To find this participant's Cowrie SYN alerts in `fast.log`:

```powershell
$participantIp = '10.77.0.11'
Get-Content .\suricata\logs\fast.log |
    Where-Object {
        $_.Contains($participantIp) -and
        $_.Contains('-> 10.77.0.10:') -and
        ($_.Contains('CISF Cowrie SSH connection') -or
         $_.Contains('CISF Cowrie Telnet connection'))
    } |
    Select-Object -Last 20
```

The EVE query includes both `flow` and `alert` records. A flow's endpoint
fields are top-level. Alert metadata, including `signature_id` and
`signature`, is nested under `alert`. The existing Cowrie connection alerts
are SIDs `1000002` (SSH) and `1000003` (Telnet). The FTP/HTTP/MySQL rules match
application payloads; a basic `-sT` scan is not expected to create those
application alerts or login events. HTTP rules may alert if the optional `-sV`
probe sends an HTTP request.

## Answers to investigation questions

1. Kali-01's source IP is `10.77.0.11`; Kali-02's is `10.77.0.12`. The
   destination is the shared target `10.77.0.10`.
2. The requested ports are expected open: 21 FTP, 80 HTTP, 2222 SSH, 2223
   Telnet, and 3306 MySQL. Nmap may label 2222/2223 incorrectly on a plain
   connect scan because its `SERVICE` column can reflect the port database.
3. `src_ip` and `src_port` identify the initiating client endpoint;
   `dest_ip` and `dest_port` identify the target endpoint. The source port is
   generally an ephemeral port selected for that connection; the destination
   port is the honeypot service port.
4. Use the event's `timestamp` and compare it with the scan time. Suricata EVE
   writes UTC timestamps (the records end with `+0000`); account for timezone
   differences when comparing with a local terminal clock. Flow records can
   take up to 30 seconds to appear after the connection closes.
5. The current Cowrie SYN rules can alert on ports 2222 and 2223. A basic TCP
   connect scan may also produce `flow` records for all five ports. It does
   not submit FTP, HTTP, or MySQL credentials; application-level alerts or
   honeypot authentication events should not be assumed. Optional Nmap `-sV`
   sends additional service probes and may produce protocol-specific telemetry
   without being a login.

## Cleanup

The exercise itself creates no files, containers, or volumes. Leave the lab
running if another workshop activity will use it. When the instructor is
finished with the lab, stop only the honeypot overlay and Kali participants:

```bash
bash ./scripts/suricata.sh down
bash ./scripts/lab.sh down
```

Use the same Bash script family that started the lab. If your deployment was
started through another supported workflow, use that workflow's corresponding
down commands instead.

These commands do not remove persistent Cowrie/OpenCanary named volumes or
existing Suricata logs. Do not run `docker volume prune` or manually delete log
files as part of this exercise.
