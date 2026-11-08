# CISF-Honeypot-Lab

The lab uses isolated, Dockerized Kali participants on the internal
`cisf-lab-net` bridge. The honeypot overlay places Cowrie and Suricata on the
isolated network. Suricata shares Cowrie's network namespace to retain
participant source IPs.

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

## Start Cowrie and Suricata

Start the Kali lab first, then start Cowrie and the Suricata sensor:

```powershell
.\scripts\suricata.ps1 up
.\scripts\suricata.ps1 test
```

Cowrie uses the shared target address `10.77.0.10`. SSH listens on `2222` and
Telnet on `2223`; Telnet is enabled explicitly. These ports are available only
on `cisf-lab-net` and are not published on the Docker host. Suricata shares
Cowrie's network namespace and captures its `eth0`, so it sees participant
source addresses rather than a proxy address. The sensor drops all capabilities
except `NET_RAW`.

Cowrie data persists in the named Docker volume `cisf-cowrie-var`; its JSON
session events are stored at `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`.
Suricata logs persist in `suricata\logs\`. Inspect the logs with:

```powershell
$cowrieLog = Join-Path $env:TEMP 'cisf-cowrie.json'
docker cp cisf-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json $cowrieLog
Get-Content $cowrieLog
Get-Content .\suricata\logs\eve.json -Wait
Get-Content .\suricata\logs\fast.log -Wait
```

The rules in `suricata\rules\lab.rules` separately alert on TCP connection
attempts to Cowrie's SSH port `2222` (SID `1000002`) and Telnet port `2223`
(SID `1000003`). The test script connects to both protocols from both Kali
participants and verifies Cowrie session events and Suricata EVE/fast-log alerts
for source IPs `10.77.0.11` and `10.77.0.12`.

On Linux or WSL2, use the matching Bash script:

```bash
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh test
```

The shared target network namespace can later host OpenCanary on additional
ports, allowing Cowrie, Suricata, and OpenCanary to use the same target IP
without publishing service ports on the host.

Stop Cowrie and Suricata with:

```powershell
.\scripts\suricata.ps1 down
```

This leaves both Kali containers and `cisf-lab-net` intact. The persistent log
files are excluded from Git.

## Stop the lab

```powershell
.\scripts\lab.ps1 down
```
