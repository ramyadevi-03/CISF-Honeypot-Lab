# CISF Cyber Range Deployment Readiness Assessment

**Assessment:** Phase 5A

**Repository branch:** `test/cisf-workshop-validation`

**Scope:** Documentation and readiness assessment only. No deployment, exercise,
or infrastructure change was performed.

## Executive assessment

The existing implementation is a working **single-Docker-host local lab**.
Its five-participant, low-volume workshop activity and Lab 5 participant-specific
evidence export were validated locally. That is not equivalent to Cyber Range
validation: the hosting platform, remote participant access, tenant isolation,
centralized logging, and multi-server networking remain unconfirmed or
unimplemented.

The current Docker bridge is internal to external networks but intentionally
allows participant-to-participant connectivity: `lab.sh test N` tests a ping
from each participant to the next. Therefore participant-to-participant
isolation is **not provided or verified**. Do not expose this shared network to
participants as a secure multi-tenant environment without an approved
isolation design.

### Readiness decision

| Target | Decision | Conditions |
|---|---|---|
| A. Local supervised demonstration | **READY, with supervision** | Use the validated local Docker environment; instructor controls `docker exec` access and filters evidence. Keep activity within the isolated lab target. |
| B. Limited Cyber Range deployment trial | **NOT READY YET** | Can be considered only after Uma/Cyber Range confirms hosting, network, access, resource, storage, and security requirements, and a deployment-specific pilot plan is approved. No Cyber Range trial has been validated. |
| C. Full multi-participant CISF workshop | **NOT READY** | Browser access is absent, inter-participant connectivity is allowed, capacity beyond five is untested, packet-drop telemetry is unavailable, and multi-server operation is unvalidated. Resolve these blockers and run a representative acceptance test. |

No maximum supported workshop capacity is inferred from the provisioner's
address limit.

## Current architecture

- `compose.yaml` defines a Kali template. `scripts/lab.sh` generates a
  temporary Compose override with one service per participant and provisions
  `kali-01` through `kali-N` on `cisf-lab-net`.
- The internal bridge is `10.77.0.0/24`, with target IP `10.77.0.10` and
  participant addresses assigned from `10.77.0.11`. It is isolated from
  external network routing, but participant containers on it can communicate
  with one another. The script accepts counts from 2 through 244 based on
  that address range.
- `compose.suricata.yaml` runs Cowrie at `10.77.0.10`; Cowrie provides SSH
  2222 and Telnet 2223. OpenCanary provides FTP 21, HTTP 80, and MySQL 3306.
  OpenCanary and Suricata share Cowrie's network namespace. The honeypot
  Compose file uses an external `cisf-lab-net`, which must exist first.
- The Compose configuration has no published honeypot host ports. Kali
  containers drop Linux capabilities, run with `no-new-privileges`, and have
  CPU, memory, and process limits. The honeypot services have corresponding
  limits; Suricata retains `NET_RAW`.
- The topology is a single Docker daemon and host. No overlay network,
  cross-host routing, central control plane, browser terminal, or Cyber Range
  integration is implemented.

## Validated capabilities

These are local validation results, not Cyber Range results:

| Capability | Status | Evidence / qualification |
|---|---|---|
| Local five-participant provisioning and assigned IPs | **VALIDATED** | Five Kali containers ran with distinct expected addresses on the local internal bridge; peer connectivity is enabled. |
| Shared honeypot services | **VALIDATED** | Cowrie SSH/Telnet, OpenCanary FTP/HTTP/MySQL, and Suricata were exercised locally. |
| Five-participant concurrent event generation and correlation | **VALIDATED** | Controlled Phase 3B activity generated application and Suricata events from all five participant IPs. |
| Five-participant Lab 5 export | **VALIDATED** | Dynamic exporter discovered the five local participants, filtered by their actual `cisf-lab-net` IPs, and generated separate 16-column sanitized TSV files. It refuses to overwrite an existing destination. |
| Low-volume five-participant HTTP resource check | **VALIDATED** | 40 curl invocations returned HTTP 200. Response times were min 4.524 ms, median 10.928 ms, mean 12.529 ms, max 43.786 ms. |
| Five-participant resource sample | **VALIDATED, LIMITED** | Baseline container memory was about 231.18 MiB and the highest sampled in-run aggregate was about 235.23 MiB. Only three in-run Docker stats samples were captured; sampled peaks are not reliable instantaneous peaks. |
| Container stability in that sample | **VALIDATED, LIMITED** | All eight CISF containers were running with zero restarts at inspection. Compose health checks are not configured. |
| Participant-to-participant isolation | **NOT VALIDATED; current configuration allows connectivity** | The provisioning test explicitly pings the next participant. The internal bridge is isolated from external routing, not from its peer containers. |
| Packet-drop visibility | **PENDING** | Suricata EVE had no stats events and the command socket was unavailable. Interface drop counters are not Suricata capture-drop measurements. Packet loss is **UNVERIFIED**, not zero. |

### Measured resource values

Configured limits are 1 CPU / 512 MiB for each Kali container, Cowrie, and
OpenCanary; Suricata is 0.5 CPU / 384 MiB. At five participants, the sum of
configured memory limits is 3.875 GiB. This is a configured ceiling sum, not
observed usage or a capacity recommendation.

During the limited HTTP sample, the host Docker engine reported 12 CPUs and
7.622 GiB RAM available. Sampled resource values:

| Container | Baseline CPU | Sampled peak CPU | Baseline RAM | Sampled peak RAM |
|---|---:|---:|---:|---:|
| Kali-01 | 0.01% | 5.93% | 23.30 MiB | 23.98 MiB |
| Kali-02 | 0.01% | 6.88% | 5.07 MiB | 6.04 MiB |
| Kali-03 | 0.01% | 6.71% | 0.81 MiB | 1.43 MiB |
| Kali-04 | 0.01% | 6.19% | 0.76 MiB | 1.60 MiB |
| Kali-05 | 0.01% | 5.80% | 0.76 MiB | 1.37 MiB |
| Cowrie | 0.01% | 0.01% | 107.40 MiB | 107.40 MiB |
| OpenCanary | 0.03% | 2.87% | 53.53 MiB | 53.56 MiB |
| Suricata | 0.86% | 1.25% | 39.55 MiB | 39.96 MiB |

The short measurement used three in-run stats samples and a bounded,
low-volume HTTP workload. These results do not establish peak demand, sustained
capacity, resource headroom, or support for any larger participant count.
Docker-wide disk accounting also included unrelated assets and is not a
per-workshop storage requirement.

## Deployment requirements and status

Status definitions: **IMPLEMENTED** means present in the repository;
**VALIDATED** means tested in the local setup; **PENDING** means not
implemented or not demonstrated; **REQUIRES CYBER RANGE CONFIRMATION** means
the platform owner must supply or approve the requirement before deployment.

| Requirement | Current Status | Gap | Action Needed | Responsible Team |
|---|---|---|---|---|
| Single-host Docker Compose deployment | **IMPLEMENTED** | Cyber Range Docker/Compose compatibility and permitted privilege/capability model are unknown. | Confirm supported runtime, Compose version, Linux host access, bind mounts, named volumes, and `NET_RAW` allowance. | Uma / Cyber Range platform |
| Hosting on Cyber Range server or AWS EC2 | **REQUIRES CYBER RANGE CONFIRMATION** | No hosting target or deployment authorization is confirmed; no cloud deployment has been tested. | Confirm whether Cyber Range provides a Linux Docker host or permits EC2, and define ownership, patching, and administrative boundaries. | Uma / Cyber Range platform / CISF |
| CPU and memory | **IMPLEMENTED** | Configured container limits are known, but five-person sample is not a capacity test and the Cyber Range host allocation is unknown. | Provide a host allocation and run a representative sustained trial at the approved workshop size; do not extrapolate current measurements. | Cyber Range platform / CISF operations |
| Storage and log retention | **IMPLEMENTED** | Cowrie/OpenCanary named volumes and a Suricata repository bind mount are local to the Docker host. Backup, quotas, retention, and central collection are not specified. | Approve persistent storage, capacity/quota, backups, retention, and log retrieval/rotation on the selected platform. | Cyber Range platform / CISF operations |
| Browser-based participant access | **PENDING** | The only implemented participant access is instructor-controlled `docker exec -it`; there is no browser terminal or per-user login gateway. | Select, secure, and validate an approved remote terminal/access broker with per-participant authorization and auditing. | Uma / Cyber Range platform / CISF |
| N participants to one shared honeypot | **VALIDATED** locally | All participant and target containers share one Docker bridge. Cross-host or multi-server routing has not been configured or tested. | Confirm single-host placement or design and test routing/network attachment for any multi-host placement. | Cyber Range networking / CISF |
| Participant-to-participant isolation | **PENDING; peer communication is enabled** | `lab.sh test N` expects a participant to ping the next participant. The internal bridge does not isolate bridge peers. | Define tenant boundary and test an approved design, such as per-participant networks with controlled target access or enforced network policy. | Uma / Cyber Range networking / Security |
| Suricata network namespace and packet capture | **VALIDATED** locally; Cyber Range compatibility **REQUIRES CYBER RANGE CONFIRMATION** | Local `network_mode: service:cowrie` observes local Docker-bridge traffic. Overlay/remote networking, host security policy, and capture visibility may differ. Packet drops remain unmeasured. | Confirm namespace and capture support, then run a Cyber Range packet/alert acceptance test with loss/drop telemetry enabled or approved alternative. | Cyber Range platform / Security monitoring |
| External exposure controls | **IMPLEMENTED** locally; perimeter policy **REQUIRES CYBER RANGE CONFIRMATION** | Compose publishes no honeypot ports and uses an internal bridge, but Cyber Range ingress, egress, and management-plane controls are unknown. | Deny unapproved ingress/egress at the platform boundary; define allowed instructor management path and test reachability from outside. | Cyber Range networking / Security |
| Evidence distribution to N participants | **VALIDATED** locally | Exporter discovers local running `kali-NN` containers attached to `cisf-lab-net`; it assumes logs are locally readable and uses `docker cp`. Remote/multi-server participants are not supported or validated. | Confirm all participants and logs are on one Docker daemon for the trial, or design/validate a secure remote distribution channel. | CISF operations / Cyber Range platform |
| Docker administration isolation | **PENDING** for participant access | Participants have not been provisioned via a Cyber Range identity/access system. Docker daemon access is highly privileged. | Restrict Docker API/socket and host administration to authorized operators; do not expose Docker control to participants. | Cyber Range platform / Security |
| Monitoring and operations | **IMPLEMENTED** locally; Cyber Range operations **PENDING** | Scripts provide `up`, `down`, `status`, and limited `test`; health checks are absent and no centralized multi-server monitoring is configured. | Define operator runbooks, alerting, health checks, incident response, maintenance, reset, and support ownership for the trial. | CISF operations / Cyber Range operations |
| Workshop scale | **PENDING** | Five participants were exercised; the script's 244-address ceiling is not a measured capacity. | Confirm expected attendance, then test only the approved target count and workload with monitoring. | Uma / CISF / Cyber Range platform |

## Security requirements

Before any Cyber Range deployment:

1. Keep the honeypot ports private to the lab network. Compose currently
   publishes none; confirm platform firewalls/security groups also deny
   unsolicited external access.
2. Keep participant Docker access, host access, raw logs, and the Docker API
   restricted to approved instructors/operators. The current system has no
   participant authentication or browser gateway.
3. Address peer reachability before multi-tenant use. The current participants
   can communicate on the shared bridge; this is not participant isolation.
4. Use only dummy training credentials. Raw Cowrie Telnet and OpenCanary FTP
   and MySQL records can include credential material. Keep raw logs
   instructor-only and distribute only each participant's filtered,
   allowlisted evidence.
5. Define approved participant-to-target and instructor-to-management flows,
   deny other network paths, and have Cyber Range security approve the
   boundary and test it.
6. Define log access control, retention, backup, incident handling, and
   evidence handling before collecting data on the Cyber Range.

These are deployment requirements; their presence here does not mean they have
been implemented or approved by the Cyber Range.

## Deployment dependencies

The following must be confirmed before a trial:

- The Cyber Range provides or approves a Linux host with Docker Engine and
  Compose, or explicitly approves another deployment model.
- The host permits the Compose features in use: bridge networks with the
  requested subnet, `internal: true`, fixed container/network names,
  `network_mode: service:cowrie`, bind mounts, named volumes, resource limits,
  and Suricata's `NET_RAW` capability.
- The selected address range does not overlap Cyber Range, VPN, host, or
  participant networks. If multiple Docker hosts are involved, routed access
  to the shared honeypot and Suricata visibility must be designed and tested.
- Participant identity, authentication, browser/terminal delivery, session
  audit, and disconnection controls are selected.
- Resource quotas, persistent storage, backup/retention, monitoring, log
  retrieval, and operator ownership are approved.
- Network ingress/egress, peer isolation, and management access rules are
  approved and verified.

## Known limitations

- Browser-based Kali terminal access is not implemented.
- Kali peers share a bridge and can reach one another; participant isolation
  is not provided by the current network configuration.
- Only five participants were used for the reported concurrency and resource
  checks. The provisioner's address maximum does not imply capacity.
- The resource sample was short and coarse; sampled peaks are not reliable
  instantaneous or sustained peaks.
- Suricata packet-drop statistics were unavailable. Packet-loss status is
  **UNVERIFIED**, not zero.
- Multi-server Docker networking, shared target routing, and sensor visibility
  have not been validated.
- The Lab 5 exporter operates on the local Docker engine, local Suricata
  `eve.json`, and local Cowrie/OpenCanary containers. Multi-host log reading
  or evidence delivery is not implemented.
- Container health checks are not configured. Existing `status` commands
  report container state, not comprehensive application health.
- The platform, Cyber Range policies, expected full workshop size, and
  hosting ownership have not been confirmed.

## Questions requiring confirmation from Uma

1. What is the approved hosting target: a Cyber Range-managed Linux Docker
   server, a VM, AWS EC2, or another platform? Is external cloud hosting
   allowed for this exercise?
2. What is the expected participant count and concurrent session schedule?
   Are all participants expected to share one host?
3. Which participant access method is supported (browser terminal, VPN plus
   SSH, managed bastion, or another approved gateway), and what identity,
   MFA, and session-audit controls are required?
4. What network boundaries apply? Can the range provide per-participant
   isolation while allowing each participant to reach only the shared
   honeypot? What ingress and egress are allowed?
5. Are Docker bridge networks, fixed private subnets, Compose service
   namespace sharing, bind mounts, named volumes, and Suricata `NET_RAW`
   capture permitted?
6. Will all Kali containers and the shared target run on one Docker host? If
   not, what routing/overlay service is approved and how will true participant
   source IPs and Suricata visibility be preserved?
7. What CPU, RAM, disk quota, persistent storage, backup, log-retention, and
   centralized monitoring requirements apply?
8. What telemetry is required for Suricata packet drops, and which operator
   team owns sensor health and incident response?
9. Who provisions, monitors, resets, and supports the workshop, and what is
   the approval process for a limited trial?

## Recommended next steps

1. Obtain Uma's answers and Cyber Range platform/security approval; record the
   hosting, access, network, identity, resource, and operational constraints.
2. Agree on participant isolation and remote access before exposing the lab to
   participants. Keep the current shared bridge confined to supervised local
   use until peer access is addressed.
3. Prepare a deployment design and a limited-trial acceptance plan, including
   external exposure checks, participant-to-participant denial, allowed
   participant-to-honeypot traffic, real source-IP preservation, Suricata
   alert/drop telemetry, persistence, evidence isolation, and safe shutdown.
4. Provision only an approved test environment; validate Compose compatibility
   and the design there without assuming local test results transfer.
5. Conduct a measured trial at the explicitly approved participant count.
   Record CPU, memory, storage growth, restart/health status, and sensor
   telemetry. Do not extrapolate from the five-participant sample.
6. Review results with Uma, CISF, Cyber Range operations, and security. Proceed
   to a full workshop only after all blocking requirements are validated and
   ownership is clear.
