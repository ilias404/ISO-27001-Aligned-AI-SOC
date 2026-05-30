# Technical Report: AI-Augmented SOC Lab

## PFA M2 — Cybersecurity Engineering

---

## 1\. Introduction

### 1.1 Project Context

This project was carried out as part of the Final Year Project (PFA) for the M2 Cybersecurity Engineering program. The objective was to design, implement, and document a Security Operations Center (SOC) laboratory that integrates artificial intelligence for automated alert triage, aligned with the ISO 27001 and ISO 27005 international standards.

### 1.2 Objectives

The main objectives of this project are:

- Build a functional SOC lab using exclusively open-source tools  
- Implement real-time threat detection using Wazuh SIEM and Sysmon  
- Integrate an AI layer (Groq LLaMA 3.1) for automated alert analysis  
- Automate incident response using n8n SOAR  
- Create automatic incident cases in IRIS IRP  
- Enrich alerts with threat intelligence (AbuseIPDB, VirusTotal)  
- Align the entire implementation with ISO 27001 Annex A controls and ISO 27005 risk management framework

### 1.3 Scope

The lab covers the following security domains:

- Endpoint Detection and Response (EDR)  
- Security Information and Event Management (SIEM)  
- Security Orchestration, Automation and Response (SOAR)  
- Incident Response Platform (IRP)  
- Threat Intelligence (TI)  
- AI-powered Security Analytics

---

## 2\. Architecture

### 2.1 Overall Design

The lab is built on a virtualized infrastructure using VirtualBox, divided into three logical zones:

**Attack Zone:** Contains the Kali Linux machine used to simulate real-world cyber attacks against the victim endpoint.

**Victim Zone:** Contains a Windows 10 workstation with Sysmon installed using the olafhartong modular configuration, providing deep endpoint telemetry. A Wazuh agent runs on this machine to forward logs to the SIEM.

**SOC Zone:** Contains all defensive and analysis tools including Wazuh SIEM, n8n SOAR, IRIS IRP, and the AI integration layer.

### 2.2 Network Design

All virtual machines are connected via a VirtualBox NAT Network (192.168.1.0/24), allowing inter-VM communication while maintaining isolation from the host production network.

| VM | Operating System | IP Address | Role |
| :---- | :---- | :---- | :---- |
| Wazuh | OVA (Amazon Linux) | 192.168.1.3 | SIEM Server |
| Windows 10 | Windows 10 Pro | 192.168.1.5 | Victim Endpoint |
| Ubuntu SOC | Ubuntu 22.04 LTS | 192.168.1.4 | SOAR \+ IRP |
| Kali Linux | Kali Linux | 192.168.1.x | Attack Simulation |

### 2.3 Component Interaction

Windows 10 (Sysmon \+ Wazuh Agent)

         │

         │ Wazuh Agent Protocol (TCP 1514\)

         ▼

    Wazuh Server

    (SOCFortress Rules \+ Custom Rules)

         │

         │ HTTP POST (shuffle.py integration)

         ▼

    n8n Webhook

         │

    ┌────┴────────────────────┐

    │   Extract Indicators     │

    │   (normalize \+ dedupe)   │

    └────┬────────────────────┘

         │

    ┌────┴────────────────────┐

    │     Parallel Enrichment  │

    ├──▶ AbuseIPDB (has IP)   │

    ├──▶ VirusTotal (has hash) │

    └──▶ Pass-through (other)  │

    └────┬────────────────────┘

         │

    ┌────┴────────────────────┐

    │   Groq AI Analysis       │

    │   (LLaMA 3.1-8b-instant) │

    └────┬────────────────────┘

         │

    ┌────┴────────────────────┐

    │   IRIS Case Creation     │

    └────┬────────────────────┘

         │

    IF level \>= 10

         │

    Telegram Notification 📱

---

## 3\. Technology Stack

### 3.1 Wazuh SIEM

Wazuh is an open-source security platform that provides SIEM, XDR, and compliance management capabilities. In this project, Wazuh serves as the central log collection and correlation engine.

**Key configurations:**

- Deployed as a pre-built OVA virtual appliance  
- Collects Windows Security Event logs and Sysmon operational logs  
- Uses SOCFortress community rules for enhanced detection  
- Integration configured to forward alerts to n8n via HTTP POST

**Wazuh Integration Configuration:**

\<integration\>

  \<name\>shuffle\</name\>

  \<hook\_url\>http://192.168.1.4:5678/webhook/wazuh\</hook\_url\>

  \<level\>5\</level\>

  \<alert\_format\>json\</alert\_format\>

  \<agent\_id\>001\</agent\_id\>

\</integration\>

### 3.2 Sysmon (System Monitor)

Sysmon is a Windows system service that monitors and logs system activity to the Windows Event Log. This project uses the **olafhartong modular configuration**, which provides comprehensive detection coverage.

**Monitored event types:**

- Event ID 1: Process Creation (with hashes)  
- Event ID 3: Network Connection  
- Event ID 7: Image/DLL Loaded  
- Event ID 11: File Creation  
- Event ID 12/13: Registry Events  
- Event ID 17/18: Named Pipe Events

### 3.3 SOCFortress Community Rules

The SOCFortress rule set was installed on the Wazuh manager, adding over 50 detection rule files covering:

- MITRE ATT\&CK technique-mapped Sysmon rules  
- Windows Sigma rules  
- Active Directory attack detection  
- PowerShell abuse detection  
- Lateral movement detection  
- Credential access detection

### 3.4 n8n SOAR

n8n is an open-source workflow automation platform. It serves as the SOAR layer in this project, orchestrating the entire alert-to-case pipeline.

**Deployment:** Docker container on Ubuntu 22.04 **Port:** 5678 **Workflow name:** Wazuh-Optimal-Workflow

### 3.5 Groq AI (LLaMA 3.1)

Groq provides ultra-fast inference for open-source LLMs via API. This project uses the `llama-3.1-8b-instant` model for real-time alert triage.

**Advantages over alternatives:**

- Free tier with no credit card required  
- 300-1000 tokens/second (vs \~80 for OpenAI)  
- Sufficient quality for SOC alert analysis  
- No data residency concerns for lab environment

**SOC Playbook Prompt Design:**

The AI prompt follows a structured SOC playbook covering 10 sections:

1. Input validation  
2. Threat classification  
3. Risk scoring model (0-100)  
4. MITRE ATT\&CK mapping  
5. SOC analyst action plan  
6. Escalation logic  
7. Executive summary  
8. Output format (structured plain text)  
9. Confidence level  
10. Guardrails (defensive analysis only)

### 3.6 IRIS IRP

IRIS (Incident Response Information System) is an open-source incident response platform. It provides case management, evidence tracking, and timeline visualization.

**Deployment:** Docker Compose on Ubuntu 22.04 **Port:** 443 (HTTPS) **Integration:** REST API with Bearer token authentication

### 3.7 Threat Intelligence

**AbuseIPDB:** Checks source IP addresses against a database of reported malicious IPs. Returns an abuse confidence score (0-100%).

**VirusTotal:** Scans file hashes against 70+ antivirus engines. Returns the number of malicious detections.

---

## 4\. n8n Workflow — Detailed Description

### 4.1 Node 1: Wazuh Webhook

Receives HTTP POST requests from the Wazuh integration script (shuffle.py). The webhook listens permanently on `/webhook/wazuh` when the workflow is published.

**Input:** Raw Wazuh alert JSON **Output:** Alert data passed to the next node

### 4.2 Node 2: Extract Indicators

A JavaScript Code node that performs three critical functions:

**Normalization:** Extracts and standardizes fields from different alert types (Windows events, Sysmon events, Linux logs).

**Indicator Extraction:**

const src\_ip \= winData?.sourceIp || log?.all\_fields?.srcip || null;

const dst\_ip \= winData?.destinationIp || log?.all\_fields?.dstip || null;

const sha256\_match \= raw\_hashes.match(/SHA256=(\[a-fA-F0-9\]{64})/);

const file\_hash \= sha256\_match ? sha256\_match\[1\] : null;

**Deduplication:** Uses a persistent cache with TTL-based expiry to prevent duplicate alerts from flooding the pipeline:

- Critical: 5 minute TTL  
- High: 3 minute TTL  
- Medium: 2 minute TTL  
- Low: 1 minute TTL

### 4.3 Nodes 3-4: Has IP? / Has Hash?

Two parallel IF nodes that route alerts based on available indicators:

- **Has IP?** — True if src\_ip or dst\_ip is non-empty → AbuseIPDB branch  
- **Has Hash?** — True if file\_hash is non-empty → VirusTotal branch  
- **False outputs** → Converge to AI directly

### 4.4 Nodes 5-6: AbuseIPDB / VirusTotal

**AbuseIPDB:** GET request to `https://api.abuseipdb.com/api/v2/check` with IP address and 90-day lookback. Returns abuse confidence score.

**VirusTotal:** GET request to `https://www.virustotal.com/api/v3/files/{hash}`. Returns last analysis statistics including malicious detection count.

### 4.5 Node 7: Converge to AI

A No-Operation node that acts as a convergence point for all three branches before passing data to the AI analysis node.

### 4.6 Node 8: AI Analysis via Groq

POST request to `https://api.groq.com/openai/v1/chat/completions` with:

- **System message:** Full SOC playbook instructions  
- **User message:** Serialized alert JSON including enrichment data

**Output format:**

ALERT ID: \[id\]

THREAT CLASSIFICATION: \[type\]

RISK SCORE: \[0-100\]

RISK LEVEL: \[Low/Medium/High/Critical\]

CONFIDENCE LEVEL: \[Low/Medium/High\]

MITRE ATT\&CK MAPPING: Tactic/Technique ID/Name

ANALYSIS REASONING: \[detailed\]

RECOMMENDED ACTIONS: \[tier 1 actions\]

ESCALATION REQUIRED: \[Yes/No\]

EXECUTIVE SUMMARY: \[2-3 sentences\]

### 4.7 Node 9: IRIS Case Creation

POST request to `https://192.168.1.4/manage/cases/add` creating a structured incident case with:

- Case name: Alert title with SOC-ALERT prefix  
- Case description: Full Groq AI analysis  
- Severity ID: Dynamic based on Wazuh alert level  
- SOC ID: Wazuh rule ID for traceability  
- TLP: Amber (internal use)

**Dynamic severity mapping:** | Wazuh Level | IRIS Severity | |-------------|---------------| | 12+ | 5 — Critical | | 8-11 | 4 — High | | 5-7 | 3 — Medium | | 3-4 | 2 — Low |

### 4.8 Nodes 10-11: IF \+ Telegram

An IF node checks if the alert level is \>= 10\. If true, a Telegram message is sent to the SOC analyst's Telegram chat with the full AI analysis formatted in Markdown.

---

## 5\. Detection Rules

### 5.1 Custom Local Rules

\<group name="local,attack,"\>

  \<rule id="100001" level="10" frequency="5" timeframe="60"\>

    \<if\_matched\_sid\>60122\</if\_matched\_sid\>

    \<description\>Brute force attack \- multiple failed logins\</description\>

    \<mitre\>\<id\>T1110\</id\>\</mitre\>

  \</rule\>

  \<rule id="100002" level="15"\>

    \<if\_group\>syscheck\</if\_group\>

    \<match\>mimikatz\</match\>

    \<description\>Mimikatz detected \- credential dumping\</description\>

    \<mitre\>\<id\>T1003\</id\>\</mitre\>

  \</rule\>

  \<rule id="100003" level="10"\>

    \<if\_group\>windows\</if\_group\>

    \<match\>-enc\</match\>

    \<description\>Encoded PowerShell command detected\</description\>

    \<mitre\>\<id\>T1059.001\</id\>\</mitre\>

  \</rule\>

\</group\>

### 5.2 SOCFortress Rules Coverage

The installed SOCFortress rules cover:

| Category | Rule Files |
| :---- | :---- |
| Sysmon Event 1 (Process) | 100100-MITRE\_TECHNIQUES\_FROM\_SYSMON\_EVENT1.xml |
| Sysmon Event 3 (Network) | 102101-MITRE\_TECHNIQUES\_FROM\_SYSMON\_EVENT3.xml |
| Sysmon Event 7 (DLL) | 106101-MITRE\_TECHNIQUES\_FROM\_SYSMON\_EVENT7.xml |
| Sysmon Event 11 (File) | 110101-MITRE\_TECHNIQUES\_FROM\_SYSMON\_EVENT11.xml |
| Sysmon Event 13 (Registry) | 112101-MITRE\_TECHNIQUES\_FROM\_SYSMON\_EVENT13.xml |
| Windows Sigma Rules | 300001-win\_sigma\_rules\_builtin.xml |
| PowerShell | 100535-win\_powershell\_rules.xml |

---

## 6\. ISO 27001 / ISO 27005 Compliance

### 6.1 ISO 27001 Annex A Mapping

**A.5.24 — Information security incident management planning and preparation** The n8n SOAR workflows define automated response playbooks for each alert category. These playbooks are documented and versioned in the workflow JSON.

**A.5.25 — Assessment and decision on information security events** The Groq AI analysis provides systematic assessment of every security event including threat classification, risk scoring, and MITRE ATT\&CK mapping. This ensures consistent, documented decision-making.

**A.5.26 — Response to information security incidents** IRIS automatically creates a case for every alert that passes through the pipeline. Each case contains the full AI analysis, recommended actions, and escalation decision.

**A.5.28 — Collection of evidence** Wazuh maintains complete audit logs of all security events. IRIS cases serve as the official evidence repository for each incident.

**A.8.15 — Logging** Wazuh collects logs from all monitored systems. Sysmon provides deep endpoint telemetry including process hashes, network connections, and file system changes.

**A.8.16 — Monitoring activities** The Wazuh dashboard provides real-time monitoring with alerting. The n8n pipeline ensures no alert goes unprocessed.

**A.8.20 — Networks security** VirtualBox network segmentation separates the attack zone, victim zone, and SOC zone. Each zone has controlled access.

### 6.2 ISO 27005 Risk Management Framework

**Risk Identification:** Wazuh SIEM with SOCFortress rules identifies threats across endpoint, network, and authentication layers. Each alert represents an identified risk.

**Risk Analysis:** The Groq AI model performs qualitative and quantitative risk analysis for each alert, calculating a risk score from 0-100 based on packet count, behavior patterns, and known threat intelligence.

**Risk Evaluation:** The risk score determines prioritization. Alerts scored 80-100 (Critical) trigger immediate escalation. Alerts scored 60-79 (High) trigger analyst review.

**Risk Treatment:** The automated pipeline implements the risk treatment:

- All alerts → IRIS case (documentation)  
- High/Critical → Telegram notification (escalation)  
- AI recommendations → immediate action guidance

---

## 7\. Attack Simulations and Results

### 7.1 Mimikatz Simulation

**Attack:** Creation of a file named mimikatz.exe on the victim endpoint.

**Detection chain:**

1. Sysmon Event 11 (File Created) fired  
2. SOCFortress rule 100606 matched — Level 10  
3. Alert forwarded to n8n  
4. Groq AI classified as: Possible Malware Communication  
5. Risk Score: 90 — Critical  
6. MITRE T1036 (Masquerading) mapped  
7. IRIS case created automatically  
8. Telegram notification sent

**AI Analysis excerpt:**

THREAT CLASSIFICATION: Possible Malware Communication RISK SCORE: 90 — RISK LEVEL: High ESCALATION REQUIRED: Yes EXECUTIVE SUMMARY: A potential malware communication threat has been identified with the possible presence of the mimikatz tool. Immediate attention required to prevent credential compromise.

### 7.2 Encoded PowerShell

**Attack:** Execution of Base64-encoded PowerShell command.

**Detection:** Sysmon Event 1 (Process Create) \+ PowerShell rules **Level:** 10 **MITRE:** T1059.001 — PowerShell

### 7.3 Suspicious Account Creation

**Attack:** Creation of a new administrator account.

**Detection:** Windows Security Event 4720 \+ 4732 **Level:** 8+ **MITRE:** T1136 — Create Account

### 7.4 DLL Side-Loading

**Detection by Sysmon Event 7:**

RuleName: technique\_id=T1574.002, technique\_name=DLL Side-Loading Image: powershell.exe loaded MpOAV.dll

**Level:** 7 **MITRE:** T1574.002 — DLL Side-Loading

---

## 8\. Challenges and Solutions

### 8.1 Wazuh → n8n SSL Certificate Issue

**Problem:** Wazuh's shuffle.py integration script rejected n8n's self-signed SSL certificate, blocking all alerts.

**Solution:** Modified the shuffle.py script to disable SSL verification:

\# Before

res \= requests.post(url, data=msg, headers=headers, timeout=10)

\# After

res \= requests.post(url, data=msg, headers=headers, timeout=10, verify=False)

### 8.2 RAM Constraints

**Problem:** 16GB RAM host running 4 VMs simultaneously caused Ollama (local LLM) to be too slow.

**Solution:** Replaced Ollama with Groq API (free tier), which provides instant inference without consuming local RAM.

### 8.3 n8n Webhook Not Triggering

**Problem:** n8n test webhook only receives one request and requires manual activation.

**Solution:** Published the workflow to activate the production webhook URL (`/webhook/wazuh` instead of `/webhook-test/wazuh`).

### 8.4 Alert Deduplication

**Problem:** High-frequency Sysmon events flooded the pipeline with duplicate alerts.

**Solution:** Implemented a JavaScript deduplication cache in the Extract Indicators node with severity-based TTL windows.

### 8.5 n8n Expression Syntax

**Problem:** n8n's HTTP Request node rejected JSON bodies containing `={{ }}` expressions.

**Solution:** Switched to "Using Fields Below" body mode with individual field entries, using expression mode per field.

---

## 9\. Results and Metrics

### 9.1 Detection Coverage

| Attack Category | Detected | MITRE Coverage |
| :---- | :---- | :---- |
| Credential Access | ✅ | T1003, T1110 |
| Execution | ✅ | T1059.001, T1204 |
| Defense Evasion | ✅ | T1036, T1574.002 |
| Persistence | ✅ | T1547.001 |
| Lateral Movement | ✅ | T1570 |
| Discovery | ⚠️ Partial | T1046 |

### 9.2 Pipeline Performance

| Metric | Value |
| :---- | :---- |
| Alert to IRIS case time | \~3-5 seconds |
| Groq AI response time | \~0.2 seconds |
| Telegram notification delay | \~1 second after IRIS |
| Deduplication window | 1-5 minutes by severity |

### 9.3 ISO Compliance Coverage

| Standard | Controls Covered | Total Relevant |
| :---- | :---- | :---- |
| ISO 27001 Annex A | 7 | \~15 relevant |
| ISO 27005 | 4 phases | 4 phases |

---

## 10\. Conclusion

This project successfully demonstrates the design and implementation of an AI-augmented SOC laboratory aligned with ISO 27001 and ISO 27005 standards. The key achievement is the complete automation of the alert-to-case pipeline:

**Wazuh** detects threats using SOCFortress community rules and Sysmon telemetry. **n8n** orchestrates the response workflow including threat intelligence enrichment via AbuseIPDB and VirusTotal. **Groq AI** provides instant, structured triage analysis following a formal SOC playbook. **IRIS** maintains the official incident record. **Telegram** ensures analysts are notified immediately for high-severity events.

The implementation covers 7 ISO 27001 Annex A controls and all 4 phases of the ISO 27005 risk management framework, providing documented evidence of compliance for each processed alert.

### Future Improvements

- Add Kali Linux for systematic attack simulations  
- Integrate MISP for threat intelligence platform  
- Add Suricata for network-level detection  
- Implement pfSense for network segmentation (ISO 27001 A.8.20)  
- Add email notifications as secondary channel  
- Develop custom Wazuh decoders for richer alert parsing

---

## Appendix A — Tool Versions

| Tool | Version |
| :---- | :---- |
| Wazuh | 4.14.x |
| n8n | 2.17.7 |
| IRIS | 2.4.27 |
| Sysmon | Latest |
| VirtualBox | 7.x |
| Ubuntu | 22.04 LTS |

## Appendix B — API Services Used

| Service | Purpose | Tier |
| :---- | :---- | :---- |
| Groq | AI inference | Free |
| AbuseIPDB | IP reputation | Free (1000/day) |
| VirusTotal | Hash scanning | Free (500/day) |
| Telegram Bot API | Notifications | Free |

## Appendix C — References

- Wazuh Documentation: [https://documentation.wazuh.com](https://documentation.wazuh.com)  
- IRIS Documentation: [https://docs.dfir-iris.org](https://docs.dfir-iris.org)  
- n8n Documentation: [https://docs.n8n.io](https://docs.n8n.io)  
- SOCFortress Rules: [https://github.com/socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules)  
- Sysmon Modular (olafhartong): [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)  
- MITRE ATT\&CK: [https://attack.mitre.org](https://attack.mitre.org)  
- ISO 27001:2022: [https://www.iso.org/standard/27001](https://www.iso.org/standard/27001)  
- ISO 27005:2022: [https://www.iso.org/standard/27005](https://www.iso.org/standard/27005)

