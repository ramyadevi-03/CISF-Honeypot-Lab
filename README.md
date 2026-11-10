
# CISF-Honeypot-Lab

A Docker-based cybersecurity training environment developed for the **CISF hands-on workshop **.

The lab provides multiple Kali Linux participant containers, a centralized honeypot, network intrusion detection using Suricata, and practical security investigation exercises.

Participants interact with simulated services, generate security events, and analyze logs to understand how reconnaissance, authentication attempts, and suspicious network activity are detected.

The workshop consists of **six hands-on exercises**, progressing from network reconnaissance to mixed-log forensic investigation.

## 1. Lab Architecture

The environment uses Docker containers connected through an internal bridge network called `cisf-lab-net`.

### Components

| Component | Purpose |
|---|---|
| Kali Linux | Individual participant attack and investigation environments |
| Cowrie | Simulated SSH and Telnet honeypot |
| OpenCanary | Simulated FTP, HTTP, and MySQL services |
| Suricata | Network intrusion detection and alert generation |
| Docker Compose | Container deployment and orchestration |
| Evidence exporters | Preparation of security logs for investigation exercises |

### Network Topology

```text
                 CISF Participants
                        |
          Internal Docker Bridge Network
                 cisf-lab-net
                   10.77.0.0/24
                        |
       +----------------+----------------+
       |                |                |
   Kali-01          Kali-02          Kali-N
 10.77.0.11        10.77.0.12      10.77.0.x
       |                |                |
       +----------------+----------------+
                        |
                        v
              Shared Honeypot Target
                   10.77.0.10
                        |
          +-------------+-------------+
          |                           |
        Cowrie                    OpenCanary
          |                           |
     SSH / Telnet             FTP / HTTP / MySQL
          |                           |
          +-------------+-------------+
                        |
                     Suricata
                        |
                IDS Alerts and Logs
                        |
               Evidence Exporters
                        |
            Security Log Investigation
```

### Important Network Considerations

The internal Docker bridge limits exposure of the lab services to external networks.

However, **the current Docker bridge does not isolate participants from one another**.

Participants connected to `cisf-lab-net` can potentially communicate with other participant containers.

This architecture is suitable for the current controlled local prototype but must not be treated as a complete multi-user security isolation boundary.

Additional isolation and access controls must be evaluated before deployment into the Cyber Range.

## 2. Current Project Status

| Component | Status |
|---|---|
| Kali participant containers | Implemented and locally tested |
| Centralized Cowrie honeypot | Implemented and locally tested |
| OpenCanary services | Implemented and locally tested |
| Suricata IDS monitoring | Implemented and locally tested |
| Six participant exercises | Completed |
| Telnet participant helper | Implemented and manually tested |
| MySQL participant helper | Implemented and manually tested |
| Security log correlation | Validated locally |
| Evidence generation for Labs 5 and 6 | Implemented and validated locally |
| Cyber Range deployment | Pending infrastructure integration |

**Current status:** The six exercises and supporting services have been validated in the local Docker environment.

**Pending:** Deployment, participant access configuration, isolation review, and end-to-end testing in the Cyber Range infrastructure.

## 3. Requirements

### Software Requirements

- Docker Desktop with Docker Compose
- Windows PowerShell for PowerShell deployment scripts
- Linux or WSL2 with Bash for Bash deployment scripts
- Docker Desktop WSL2 integration when using Docker through WSL2
- Git for cloning and managing the repository

### Recommended Environment

- Windows with Docker Desktop and WSL2, or a compatible Linux Docker environment
- Sufficient CPU and memory for the intended number of participant containers
- Access to the Docker daemon for instructor deployment and administration

Participant containers are subject to resource limits, so the practical number of simultaneous participants depends on the available host resources.

## 4. Quick Start — Windows PowerShell

Open Windows PowerShell and navigate to the repository root.

### Step 1 — Start Kali Participants

Start the two default participant containers:

```powershell
.\scripts\lab.ps1 up
```

To create more participants:

```powershell
.\scripts\lab.ps1 up -Count 10
```

Participant containers are named sequentially:

- `kali-01`
- `kali-02`
- `kali-03`
- `kali-04`
- `kali-05`
- And so on, based on the requested count

IP addresses are assigned sequentially beginning at `10.77.0.11`.

The subnet is `10.77.0.0/24`. Avoid overlapping Docker network subnets.

### Step 2 — Start the Honeypot and IDS

```powershell
.\scripts\suricata.ps1 up
```

This starts the shared Cowrie, OpenCanary, and Suricata services.

### Step 3 — Verify the Environment

```powershell
.\scripts\lab.ps1 status
.\scripts\lab.ps1 test
.\scripts\suricata.ps1 test
```

These tests verify participant container configuration, network connectivity, service behavior, and expected security logging.

### Step 4 — Enter a Participant Container

For Kali-01:

```powershell
docker exec -it kali-01 bash
```

For Kali-02:

```powershell
docker exec -it kali-02 bash
```

Participants should receive access only to their assigned environment through the approved workshop access mechanism.

The `docker exec` commands above are intended for local instructor administration.

## 5. Linux and WSL2 Deployment

The repository includes Bash scripts for Linux and WSL2 environments.

### Start Participant Containers

```bash
bash ./scripts/lab.sh up 2
```

### Check Status

```bash
bash ./scripts/lab.sh status 2
```

### Test Participant Containers

```bash
bash ./scripts/lab.sh test 2
```

### Start and Test the Honeypot

```bash
bash ./scripts/suricata.sh up
bash ./scripts/suricata.sh test
```

### Scale Participant Containers

To increase the participant count:

```bash
bash ./scripts/lab.sh up 3
```

To reduce the participant count:

```bash
bash ./scripts/lab.sh up 2
```

When scaling down, the Bash deployment script removes obsolete participant containers.

**Note:** Persistent logs and participant container data should be reviewed or backed up before modifying an active workshop environment.

## 6. Participant Container Configuration

Each Kali container is configured with restricted privileges and resource limits.

### Security and Resource Controls

| Setting | Configuration |
|---|---|
| CPU limit | 1 CPU |
| Memory limit | 512 MiB |
| Process limit | 128 processes |
| Container user | Unprivileged `kali` user |
| Linux capabilities | Dropped |
| Privilege escalation | Restricted using `no-new-privileges` |
| Network | Internal Docker bridge |
| Raw-socket scanning | Not enabled |

### Available Tools

The Kali image includes tools used by the workshop exercises, including:

- Nmap
- OpenSSH client
- curl
- ping
- Common networking utilities
- Perl and its core socket modules

Nmap supports unprivileged TCP connect scans.

For example:

```bash
nmap -sT -Pn -n -p 21,80,2222,2223,3306 10.77.0.10
```

Raw-socket scanning techniques requiring elevated privileges are not enabled in the participant containers.

## 7. Centralized Honeypot Services

The shared honeypot uses the IP address:

**`10.77.0.10`**

### Available Services

| Service | Port | Honeypot | Description |
|---|---|---|---|
| FTP | 21 | OpenCanary | Simulated FTP authentication |
| HTTP | 80 | OpenCanary | Simulated web service |
| SSH | 2222 | Cowrie | Simulated SSH login and shell activity |
| Telnet | 2223 | Cowrie | Simulated Telnet login |
| MySQL | 3306 | OpenCanary | Simulated database authentication |

These services are designed to generate observable security events.

They do not provide unrestricted access to real production servers or databases.

### Cowrie

Cowrie records SSH and Telnet interactions, including:

- Session connections
- Authentication attempts
- Simulated authentication successes
- Client information
- Commands submitted to the emulated environment
- Session termination events

Successful authentication within Cowrie is simulated and does not indicate access to a real operating system.

### OpenCanary

OpenCanary records interactions involving:

- FTP authentication
- HTTP requests
- MySQL connections
- MySQL authentication attempts

OpenCanary uses the maintained 0.9.10 image pinned to the repository's tested image digest.

It drops to its configured unprivileged user after starting listeners and retains only the capabilities needed for its service setup and privilege drop.

Configuration:

[opencanary/opencanary.conf](./opencanary/opencanary.conf)

### Network Namespace

Cowrie, OpenCanary, and Suricata use a shared target networking arrangement.

OpenCanary and Suricata share Cowrie's network namespace, allowing the simulated services to be exposed through the common target address.

Suricata can inspect the traffic reaching the honeypot while retaining the originating participant source IP addresses.

No honeypot service ports are published directly to the Docker host.

## 8. Suricata Intrusion Detection

Suricata monitors network activity directed toward the shared honeypot.

The environment contains custom rules corresponding to the five simulated services.

### Suricata Signature IDs

| Signature ID | Service | Detection |
|---|---|---|
| `1000002` | SSH | Cowrie SSH connection |
| `1000003` | Telnet | Cowrie Telnet connection |
| `1000004` | FTP | OpenCanary FTP activity |
| `1000005` | HTTP | OpenCanary HTTP activity |
| `1000006` | MySQL | OpenCanary MySQL activity |

### Important Distinction

A Suricata alert indicates that matching network activity was detected.

It does not automatically establish:

- Successful authentication
- Successful exploitation
- Compromise of the target
- Execution of malicious commands

Participants must correlate Suricata alerts with the corresponding Cowrie and OpenCanary application logs.

## 9. Workshop Exercises

The CISF workshop contains **six hands-on exercises**.

The exercises progress from basic network discovery to analysis of security events from multiple participants.

### Lab 1 — Network Reconnaissance

[Participant Exercise](./exercises/01-network-reconnaissance/participant-exercise.md)

**Objective:** Identify accessible services on the shared honeypot.

Participants use Nmap to discover the available TCP ports.

Skills covered:

- TCP connect scanning
- Service identification
- Port interpretation
- Reconnaissance evidence collection

### Lab 2 — SSH and Telnet Investigation

[Participant Exercise](./exercises/02-ssh-telnet-investigation/participant-exercise.md)

**Objective:** Generate and investigate simulated remote-login activity.

Participants interact with Cowrie over SSH and Telnet.

Skills covered:

- Remote access protocols
- Authentication events
- Simulated successful logins
- Session investigation
- Cowrie event correlation

The lab includes a reusable Telnet helper script to avoid the earlier hanging `curl` interaction.

### Lab 3 — FTP Investigation

[Participant Exercise](./exercises/03-ftp-investigation/participant-exercise.md)

**Objective:** Investigate FTP authentication attempts captured by OpenCanary.

Skills covered:

- FTP authentication behavior
- Connection and login events
- OpenCanary event interpretation
- Source IP attribution

### Lab 4 — HTTP and MySQL Investigation

[Participant Exercise](./exercises/04-http-mysql-investigation/participant-exercise.md)

**Objective:** Investigate web requests and simulated database authentication.

Participants perform:

- HTTP requests against the simulated web service
- A dummy MySQL authentication attempt
- Review of the resulting security events

The lab includes a reusable MySQL helper script.

### Lab 5 — Suricata Alert Analysis

[Participant Exercise](./exercises/05-suricata-alert-analysis/participant-exercise.md)

**Objective:** Investigate the relationship between IDS alerts and honeypot application logs.

Participants analyze a sanitized evidence dataset containing records from:

- Suricata
- Cowrie
- OpenCanary

Skills covered:

- IDS signature interpretation
- Timestamp correlation
- Source IP identification
- Authentication event analysis
- Manual security-log investigation

### Lab 6 — Mixed-Log Forensic Investigation

[Participant Exercise](./exercises/06-mixed-log-forensic-investigation/participant-exercise.md)

**Objective:** Investigate mixed security records originating from multiple participant environments.

Participants receive a combined evidence dataset and determine:

- Which source IP accessed which services
- Which activities resemble network reconnaissance
- Which sources performed authentication attempts
- Which simulated logins succeeded
- Which IDS alerts correlate with the application events

This exercise focuses on manual forensic attribution using interleaved security logs.

**No additional exercises are required beyond these six labs.**

## 10. Telnet and MySQL Participant Helpers

Two reusable Perl helpers are provided to simplify the participant experience.

They use existing Perl core socket modules and do not require additional packages.

### Lab 2 — Telnet Helper

Source file:

`exercises/02-ssh-telnet-investigation/telnet-login.pl`

Before the exercise, the instructor stages the helper inside the assigned Kali container.

Example from the repository root in PowerShell:

```powershell
docker cp exercises/02-ssh-telnet-investigation/telnet-login.pl kali-01:/tmp/cisf-telnet-login.pl
```

The participant then executes:

```bash
perl /tmp/cisf-telnet-login.pl
```

The helper:

1. Connects to the designated Telnet honeypot.
2. Handles the simulated login prompts.
3. Submits the exercise's dummy authentication attempt.
4. Closes the connection cleanly.

The recorded authentication outcome is simulated by Cowrie.

### Lab 4 — MySQL Helper

Source file:

`exercises/04-http-mysql-investigation/mysql-login.pl`

Instructor staging command:

```powershell
docker cp exercises/04-http-mysql-investigation/mysql-login.pl kali-01:/tmp/cisf-mysql-login.pl
```

Participant command:

```bash
perl /tmp/cisf-mysql-login.pl
```

The helper:

1. Connects to the simulated MySQL service.
2. Processes the protocol handshake.
3. Submits a dummy authentication attempt.
4. Reports the server's response.

Expected result:

```text
Dummy MySQL authentication rejected (error 1045, access denied); no login established.
```

### Validation

Both helpers were manually tested from Kali-01.

- Telnet completed without hanging.
- Cowrie recorded simulated login activity.
- MySQL returned error `1045`.
- OpenCanary recorded the MySQL authentication attempt.
- Corresponding Suricata alerts were verified during automated validation.

**Note:** Scripts staged in `/tmp` must be copied again if a participant container is recreated.

For a workshop with multiple participants, instructors must stage the required helper scripts into each assigned container.

## 11. Security Logs and Evidence Collection

The environment maintains logs from the three monitoring components.

### Cowrie Logs

Docker volume:

`cisf-cowrie-var`

Container log location:

```text
/cowrie/cowrie-git/var/log/cowrie/cowrie.json
```

Cowrie uses the field `src_ip` to record the originating source address.

### OpenCanary Logs

Docker volume:

`cisf-opencanary-logs`

Container log location:

```text
/var/tmp/opencanary.log
```

OpenCanary uses:

- `src_host` for the source address
- Numeric `logtype` values for event classification

Relevant MySQL event types include:

| Logtype | Meaning |
|---|---|
| `9003` | MySQL connection event |
| `8001` | MySQL authentication attempt |

### Suricata Logs

Host directory:

```text
suricata/logs/
```

Important files:

- `eve.json` — Structured JSON events
- `fast.log` — Text-formatted alert records

Persistent Suricata logs are excluded from Git.

### Inspect Logs from PowerShell

```powershell
$cowrieLog = Join-Path $env:TEMP 'cisf-cowrie.json'

docker cp cisf-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json $cowrieLog

Get-Content $cowrieLog
```

OpenCanary:

```powershell
docker exec cisf-opencanary cat /var/tmp/opencanary.log
```

Suricata:

```powershell
Get-Content .\suricata\logs\eve.json -Wait
```

```powershell
Get-Content .\suricata\logs\fast.log -Wait
```

The `-Wait` option continuously displays new log entries until interrupted.

**Security note:** Raw logs may contain submitted usernames, passwords, commands, or other exercise data. Distribute sanitized evidence datasets rather than unrestricted raw logs.

## 12. Evidence Preparation for Labs 5 and 6

Labs 5 and 6 use exported security evidence rather than requiring participants to inspect unrestricted raw logging volumes.

The repository includes evidence-export scripts for this purpose.

### Lab 5 — Participant-Specific Evidence

Script:

```text
scripts/export-lab5-evidence.sh
```

The exporter combines relevant security events from Cowrie, OpenCanary, and Suricata.

The resulting dataset supports investigation of activity associated with an assigned participant source IP.

### Lab 6 — Mixed-Participant Evidence

Script:

```text
scripts/export-mixed-lab-evidence.sh
```

The exporter produces a combined dataset containing security activity originating from multiple participant containers.

Participants investigate the mixed evidence to determine which source performed each activity.

### Evidence Format

The exported TSV evidence uses fields including:

| Field | Description |
|---|---|
| `dataset` | Logging source |
| `timestamp` | Event timestamp |
| `event_type` | Recorded event |
| `protocol` | Network protocol |
| `service` | Target service |
| `src_ip` | Source IP |
| `src_port` | Source port |
| `dest_ip` | Destination IP |
| `dest_port` | Destination port |
| `signature_id` | Suricata signature ID |
| `signature` | Signature description |
| `session` | Cowrie session identifier |
| `username` | Recorded username, where applicable |
| `path` | HTTP request path, where applicable |
| `user_agent` | HTTP user agent, where applicable |
| `outcome` | Recorded event outcome |

### Instructor Workflow

1. Start the Kali participant containers and shared honeypot.
2. Verify Suricata, Cowrie, and OpenCanary logging.
3. Allow participants to perform the designated exercises.
4. Confirm that the required events have been recorded.
5. Run the appropriate evidence exporter using the parameters documented in the instructor runbook.
6. Validate the exported records and source attribution.
7. Distribute the sanitized datasets to participants.
8. Ask participants to correlate events and prepare investigation findings.

Lab 5 should use the appropriate participant-specific evidence.

Lab 6 should use combined evidence from multiple participant sources.

**Important:** Previously generated validation datasets are useful for testing, but the instructor should prepare the correct evidence files for each actual workshop session.

Detailed procedures are available in:

[Instructor Runbook](./docs/CISF-INSTRUCTOR-RUNBOOK.md)

## 13. Instructor and Participant Responsibilities

### Instructor Responsibilities

Instructors are responsible for:

- Deploying the lab environment
- Starting the centralized honeypot
- Assigning participant containers
- Verifying network connectivity
- Staging required helper scripts
- Monitoring service health
- Generating sanitized evidence datasets
- Distributing exercise instructions
- Reviewing investigation findings
- Shutting down the environment safely

### Participant Responsibilities

Participants are expected to:

- Access only their assigned Kali environment
- Follow the specified exercise instructions
- Interact only with designated lab targets
- Record observations and results
- Investigate security alerts and application logs
- Correlate source IPs, timestamps and event types
- Submit investigation findings where required

Participants do not require access to the Docker host or administrative Docker commands during the exercises.

## 14. Cyber Range Deployment

The current environment has been validated using a local Docker deployment.

The final Cyber Range deployment is a separate integration activity and requires infrastructure-specific testing.

### Required Capabilities

The Cyber Range environment must support:

1. Individual participant access to Kali environments.
2. Connectivity from assigned Kali environments to the shared honeypot.
3. Appropriate participant isolation or compensating controls.
4. Cowrie and OpenCanary service availability.
5. Suricata visibility into relevant participant-to-honeypot traffic.
6. Preservation of participant source attribution in security logs.
7. Instructor access to logging and evidence-generation tools.
8. Secure distribution of sanitized datasets.
9. Resource management for the expected participant count.
10. Controlled startup, shutdown, and reset procedures.

### Current Deployment Limitation

The existing Docker bridge permits participant-to-participant communication.

This must be reviewed before deploying the environment as a shared multi-user Cyber Range lab.

A dedicated Cyber Range lab configuration may be necessary to provide the required networking and isolation.

**Local validation does not imply that the environment has already been deployed or approved for the Cyber Range.**

For deployment planning, refer to:

[Cyber Range Deployment Readiness](./docs/CISF-CYBERRANGE-DEPLOYMENT-READINESS.md)

## 15. Troubleshooting

### Participant Container Not Running

Check the container status:

```powershell
docker ps -a
```

Check the lab:

```powershell
.\scripts\lab.ps1 status
```

### Honeypot Connection Failed

Confirm the target services are running:

```powershell
.\scripts\suricata.ps1 test
```

Inspect the internal network:

```powershell
docker network inspect cisf-lab-net
```

### Telnet Command Hangs

Avoid the earlier interactive `curl` Telnet workflow.

Use the staged helper:

```bash
perl /tmp/cisf-telnet-login.pl
```

If the helper is missing, the instructor must copy it into the participant container.

### MySQL Client Not Available

A native MySQL client is not required.

Use:

```bash
perl /tmp/cisf-mysql-login.pl
```

The expected result is an authentication rejection with error `1045`.

### Suricata Alerts Not Appearing

Check:

- Suricata container status
- Correct network attachment
- Honeypot connectivity
- Rule configuration
- `eve.json`
- `fast.log`

### Evidence File Not Found

Check that:

- The instructor generated the dataset.
- The correct evidence file was distributed.
- The file was copied into the intended participant container.
- The participant is using the correct filename and path.

### Logs Missing After Restart

Review the relevant persistent Docker volumes and host-mounted Suricata log directory.

Do not delete named volumes or historical logs during troubleshooting unless an intentional reset and retention decision has been made.

## 16. Stop the Environment

### Stop Honeypot Services

```powershell
.\scripts\suricata.ps1 down
```

### Stop Participant Lab

```powershell
.\scripts\lab.ps1 down
```

Stopping the honeypot overlay leaves participant containers and persistent logging volumes managed separately.

Before cleaning up a workshop environment, ensure required evidence and investigation records have been retained.

## 17. Project Documentation

### Instructor Documentation

[Instructor Runbook](./docs/CISF-INSTRUCTOR-RUNBOOK.md)

Contains operational guidance for running the six exercises, verifying the environment, preparing evidence, and handling workshop activities.

### Cyber Range Deployment

[Cyber Range Deployment Readiness](./docs/CISF-CYBERRANGE-DEPLOYMENT-READINESS.md)

Contains deployment considerations and requirements for integrating the local prototype into the Cyber Range.

### Participant Exercises

1. [Network Reconnaissance](./exercises/01-network-reconnaissance/participant-exercise.md)
2. [SSH and Telnet Investigation](./exercises/02-ssh-telnet-investigation/participant-exercise.md)
3. [FTP Investigation](./exercises/03-ftp-investigation/participant-exercise.md)
4. [HTTP and MySQL Investigation](./exercises/04-http-mysql-investigation/participant-exercise.md)
5. [Suricata Alert Analysis](./exercises/05-suricata-alert-analysis/participant-exercise.md)
6. [Mixed-Log Forensic Investigation](./exercises/06-mixed-log-forensic-investigation/participant-exercise.md)

## 18. Responsible Use

This environment is intended exclusively for authorized cybersecurity training, education, and controlled experimentation.

All simulated authentication and reconnaissance activities must be performed only against designated lab targets.

The honeypot services are intentionally simulated to provide observable security events without requiring access to real production systems.

**Do not expose the lab services to untrusted external networks or use the exercises against unauthorized targets.**

---

**Project:** CISF-Honeypot-Lab  
**Environment:** Docker, Kali Linux, Cowrie, OpenCanary, Suricata  
**Exercises:** 6  
**Local Implementation:** Completed and validated  
**Cyber Range Deployment:** Pending infrastructure integration and validation
