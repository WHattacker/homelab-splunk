# Scenario 02: Nmap Reconnaissance Detection

**Date:** 2026-03-17
**MITRE ATT&CK:** T1046 — Network Service Discovery
**Severity:** Medium

## Lab Setup
- Attacker: Kali Linux (ATTACKER_IP)
- Victim: Ubuntu Server (VICTIM_IP)
- SIEM: Splunk Enterprise (Free)

## Attack Executed
```bash
nmap -sV -A VICTIM_IP
```

## Detection SPL Query
```splunk
index=main sourcetype=syslog
| timechart count span=10s
| where count > 50
```

## Findings
- 3000+ events generated during scan
- Massive spike in syslog events visible in Splunk
- Scan completed full service version detection

## MITRE ATT&CK Mapping
- Tactic: Reconnaissance
- Technique: T1046 — Network Service Discovery

## Response Steps
1. Identify source IP of scan
2. Block source IP at firewall
3. Review what services were discovered
4. Check for follow-on exploitation attempts

## Screenshot
![Nmap Recon Detection](../../screenshots/02-nmap-recon.png)
