# Glossary (plain language)

If you are new to security-monitoring terms, this page explains the words used in this repository.

| Term | Meaning |
|---|---|
| SOC | Security Operations Centre: the team that monitors systems for attacks. |
| Triage | Sorting alerts by urgency and deciding which ones are real. |
| Log / event | A log is a file in which a computer records what happened. One entry in it is an event. |
| SIEM | Security Information and Event Management: a central system that collects logs from many computers, lets you search them and raises alerts. Splunk and Elastic are two common examples. |
| Splunk / SPL | A SIEM product and its search language (SPL, Search Processing Language). |
| Elastic / KQL / EQL / Query DSL | Another SIEM stack (Elasticsearch and Kibana) and its query languages. |
| Detection | A saved search or rule that flags suspicious activity. This repository has 12, named DET-01 and so on. |
| Reference implementation | The same detection written in Python, so its logic can be tested without Splunk or Elastic. |
| False positive / tuning | A false positive is an alert about something harmless. Tuning means adjusting a detection to produce fewer of them. |
| MITRE ATT&CK | A public catalogue of attacker techniques. Detections carry tags such as T1110.001 so the technique can be looked up. |
| SSH brute force | Guessing passwords for a remote login again and again. In a log it looks like many failed logins from one address. |
| Sysmon | A free Microsoft tool that records detailed Windows activity, such as new processes and network connections. |
| auditd | The Linux auditing system. It can record events such as who read a sensitive file. |
| Beaconing | A computer contacting an outside server again and again at regular intervals, which is typical of malware checking in. |
| Encoded PowerShell | A PowerShell command hidden as base64 text, which attackers use to hide what they run. |
| IOC (indicator of compromise) | A detail linked to an attack, such as an IP address, used to look for related activity. |
| Dataset | The made-up log files in `datasets/`. |
| Synthetic data | Made-up data. Nothing here comes from a real organisation or a real attack. |
| NOT TESTED | The label used in this repository for anything that has not been run in the real product (Splunk or Elastic). |
