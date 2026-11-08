# CISF-Honeypot-Lab

The lab uses isolated, Dockerized Kali participants on the internal
`cisf-lab-net` bridge. The Phase 2 overlay adds a temporary HTTP target and a
Suricata sensor that shares the target's network namespace.

## Requirements

- Docker Desktop with Docker Compose
- Windows PowerShell for the PowerShell scripts
- Bash on Linux or WSL2 for the Bash scripts

## Start the lab

From the repository root, build and start the two default participants:

```powershell
.\scripts\lab.ps1 up
```

Add more participants without editing Compose files by setting `-Count`. Addresses
are assigned in order from `10.77.0.11` through `10.77.0.254`:

```powershell
.\scripts\lab.ps1 up -Count 10
```

On Linux or WSL2 with Docker Desktop integration enabled, use the Bash scripts
for the same lab lifecycle:

```bash
bash ./scripts/lab.sh up 2
bash ./scripts/lab.sh status 2
bash ./scripts/lab.sh test 2
bash ./scripts/lab.sh up 3
bash ./scripts/lab.sh up 2
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh test
```

The Bash scripts use the existing Compose files, Kali image, and isolated
`cisf-lab-net` network. `lab.sh up N` removes obsolete participant containers
when scaling down to a smaller count.

Container names are `kali-01`, `kali-02`, and so on. The isolated `cisf-lab-net`
network uses `10.77.0.0/24`; do not configure another Docker network with an
overlapping subnet. Containers have a 1 CPU / 512 MiB limit and a 128-process
limit, drop all Linux capabilities, and run as the unprivileged `kali` user with
`no-new-privileges`.
Nmap is available for unprivileged connect scans; raw-socket scans are not enabled.
The image includes Nmap, the OpenSSH client, curl, ping, and common networking
utilities.

## Inspect and test

```powershell
.\scripts\lab.ps1 status
.\scripts\lab.ps1 test
docker network inspect cisf-lab-net
docker exec -it kali-01 bash
```

The test command checks the internal network, assigned IPs, running state, tool
availability, resource/security settings, and participant-to-participant ping.

## Start the Suricata sensor

Start the Kali lab first, then start the separate target and sensor project:

```powershell
.\scripts\suricata.ps1 up
.\scripts\suricata.ps1 test
```

The temporary Python HTTP target is `10.77.0.10:8080`. Suricata shares its
network namespace and captures its `eth0`; the Kali containers and their existing
network/security settings are unchanged. The sensor drops all capabilities
except `NET_RAW`, and only the target's traffic is visible to this sensor.

Logs persist on the host in `suricata\logs\`. Inspect them manually:

```powershell
Get-Content .\suricata\logs\eve.json -Wait
Get-Content .\suricata\logs\fast.log -Wait
```

The local rule in `suricata\rules\lab.rules` alerts on HTTP GET requests to the
target's root path on port 8080. The test script issues uniquely tagged requests
from both Kali containers and checks EVE HTTP events, SID `1000001` alerts, and
fast-log entries.

Stop only the temporary target and sensor with:

```powershell
.\scripts\suricata.ps1 down
```

This leaves both Kali containers and `cisf-lab-net` intact. The persistent log
files are excluded from Git.

## Stop the lab

```powershell
.\scripts\lab.ps1 down
```
