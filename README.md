# CISF-Honeypot-Lab

Phase 1 provides isolated, Dockerized Kali participants. The shared `cisf-lab-net`
bridge has fixed participant addresses and no external network routing; a future
honeypot can join this network to communicate with the participants.

## Requirements

- Docker Desktop with Docker Compose
- Windows PowerShell

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

## Stop the lab

```powershell
.\scripts\lab.ps1 down
```
