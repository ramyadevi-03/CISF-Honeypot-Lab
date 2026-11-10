# CISF-Honeypot-Lab

The lab uses Dockerized Kali participants on the internal `cisf-lab-net`
bridge. This isolates the lab network from external networks, but does not
isolate Kali participants from one another; the current bridge permits
participant-to-participant connectivity. The honeypot overlay places Cowrie
and Suricata on this network. Suricata shares Cowrie's network namespace to
retain participant source IPs.

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

The Bash scripts use the existing Compose files, Kali image, and internal
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

## Start the honeypot target

Start the Kali lab first, then start the shared Cowrie, OpenCanary, and Suricata
target:

```powershell
.\scripts\suricata.ps1 up
.\scripts\suricata.ps1 test
```

The shared target address is `10.77.0.10`. Cowrie provides SSH on `2222` and
Telnet on `2223`. Thinkst OpenCanary provides FTP on `21`, HTTP on `80`, and
MySQL on `3306`. OpenCanary and Suricata share Cowrie's network namespace, so
the services use the same target IP and Suricata captures participant source
addresses directly. Services are reachable only over the isolated
`cisf-lab-net`; no honeypot ports are published on the Docker host.

OpenCanary uses Thinkst's maintained 0.9.10 image pinned to its tested digest.
OpenCanary drops to its configured unprivileged user after starting listeners.
It receives only `NET_BIND_SERVICE` (to bind FTP and HTTP's privileged ports)
and `SETUID`/`SETGID` (to drop to that user); all other capabilities are
dropped. Its configuration is in
[opencanary/opencanary.conf](./opencanary/opencanary.conf). The Suricata rules
use SIDs `1000002`/`1000003` for Cowrie SSH/Telnet and
`1000004`/`1000005`/`1000006` for OpenCanary FTP/HTTP/MySQL, respectively.

Cowrie data persists in the named Docker volume `cisf-cowrie-var`; Cowrie JSON
session events are stored at `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`.
OpenCanary's JSON events persist in the named volume
`cisf-opencanary-logs` at `/var/tmp/opencanary.log`. Its event records use
`src_host` (and numeric `logtype`), while Cowrie uses `src_ip`. Suricata logs
persist in `suricata\logs\` on the host. The scripts validate protocol behavior
and check that events retain both participant source IPs.

Run the end-to-end protocol and logging tests from PowerShell or Linux/WSL:

```powershell
.\scripts\suricata.ps1 up
.\scripts\suricata.ps1 test
$cowrieLog = Join-Path $env:TEMP 'cisf-cowrie.json'
docker cp cisf-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json $cowrieLog
Get-Content $cowrieLog
docker exec cisf-opencanary cat /var/tmp/opencanary.log
Get-Content .\suricata\logs\eve.json -Wait
Get-Content .\suricata\logs\fast.log -Wait
```

The Bash equivalent on Linux or WSL2 with Docker Desktop integration enabled is:

```bash
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh test
```

The tests originate from Kali-01 (`10.77.0.11`) and Kali-02 (`10.77.0.12`),
exercise SSH, Telnet, FTP login, an HTTP GET, and a MySQL handshake/login
attempt, and verify Cowrie, OpenCanary, Suricata EVE, and `fast.log` records.
OpenCanary's MySQL connect event is logtype `9003`; its login event is
logtype `8001`.

Stop the honeypot overlay with:

```powershell
.\scripts\suricata.ps1 down
```

This leaves both Kali containers, `cisf-lab-net`, and named log volumes intact.
The persistent log files are excluded from Git.

## Stop the lab

```powershell
.\scripts\lab.ps1 down
```

## Workshop exercises

The workshop contains six exercises:

1. [Network reconnaissance](./exercises/01-network-reconnaissance/participant-exercise.md)
2. [SSH and Telnet investigation](./exercises/02-ssh-telnet-investigation/participant-exercise.md)
3. [FTP investigation](./exercises/03-ftp-investigation/participant-exercise.md)
4. [HTTP and MySQL investigation](./exercises/04-http-mysql-investigation/participant-exercise.md)
5. [Suricata alert analysis](./exercises/05-suricata-alert-analysis/participant-exercise.md)
6. [Mixed-log forensic investigation](./exercises/06-mixed-log-forensic-investigation/participant-exercise.md)
