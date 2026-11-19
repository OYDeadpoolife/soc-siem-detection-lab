# Architecture

## The lab

This repository describes a small SOC lab and ships synthetic data as if that lab had produced it. **No virtual machine was built or
captured for this repository**; the data comes from the generator. The firewall part of the lab is built and documented in the pfSense
lab project.

```mermaid
flowchart LR
    subgraph WAN["WAN 203.0.113.0/24 (simulated Internet)"]
        K["kali01 203.0.113.45<br/>(attacker)"]
    end
    FW["pfsense-lab<br/>WAN 203.0.113.10<br/>LAN 10.10.10.1 / DMZ 10.10.20.1 / MGMT 10.10.30.1"]
    subgraph DMZ["DMZ 10.10.20.0/24"]
        W["web01 (Ubuntu) 10.10.20.10<br/>sshd, sudo, auditd"]
    end
    subgraph LAN["LAN 10.10.10.0/24"]
        WS["WS01 (Windows) 10.10.10.20<br/>Sysmon"]
    end
    subgraph MGMT["MGMT 10.10.30.0/24"]
        J["jump01 10.10.30.5<br/>(administrators)"]
        B["backup01 10.10.30.40"]
        SC["scanner01 10.10.30.60"]
        S[("siem01 10.10.30.50<br/>Splunk or Elastic")]
    end
    K -->|SSH via NAT| FW
    FW --> W
    FW --> WS
    J --> W
    B --> W
    SC --> W
    W -->|"Universal Forwarder / Filebeat"| S
    WS -->|"Universal Forwarder / Winlogbeat"| S
    FW -->|"remote syslog"| S
```

## How data moves

```mermaid
flowchart LR
    A["Log sources<br/>auth.log, auditd, Sysmon"] --> B["Collection<br/>forwarder or beat"]
    B --> C["Parsing and normalization<br/>sourcetype / ECS fields"]
    C --> D[("Index<br/>soc_lab / soc-lab-*")]
    D --> E["Detection<br/>SPL, KQL, EQL"]
    E --> F["Alert"]
    F --> G["Triage by an analyst"]
    G --> H{"Incident?"}
    H -->|yes| I["Investigation and response"]
    H -->|no| J["Close and tune the detection"]
```

| Stage | In this repository | Tested? |
|---|---|---|
| Log sources | `datasets/` (synthetic) | Yes (generator and format tests) |
| Collection | `splunk/inputs.conf.example`, `elastic/beats/*.example` | No (configuration examples) |
| Parsing / normalization | `splunk/props.conf.example`, `docs/log-normalization.md` | No for Splunk; the field mapping is documented |
| Detection | `splunk/spl/`, `elastic/` and `detections/` | Logic yes (Python); syntax no |
| Alert | `splunk/savedsearches.conf.example`, `alerts/alert-examples.md` | No |
| Triage / investigation | `docs/triage-workflow.md`, `docs/investigation-walkthrough.md` | Walkthrough numbers come from the Python reference |

## Log sources and what they can and cannot show

| Source | Shows | Does not show |
|---|---|---|
| `auth.log` | SSH logins (success and failure, method, source), sudo, su, account tools | What a root shell did afterwards; who ran `useradd` |
| auditd | Commands and file access with the original login `auid` | Anything not covered by a rule; needs tuning to avoid noise |
| Sysmon 1 | Process creation with command line and parent | Script content; activity before Sysmon started |
| Sysmon 3 | Network connections with process | Packet content; DNS names (needs Sysmon 22) |
| Sysmon 11 | File creation | File content |

## Design decisions

* **One scenario across all sources**, so a pivot (an IP address, an account) leads somewhere, as it would in a real investigation.
* **Deliberate false positives** (scanner, administrator typos, management agent, legitimate `visudo`) so tuning is visible.
* **Two field layouts for the same events** (Sysmon native for Splunk, ECS for Elastic) so normalization can be shown, not just described.
* **Python reference implementation** for every detection, so the logic is tested even without a SIEM.
