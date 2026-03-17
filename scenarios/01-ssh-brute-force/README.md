# Scenario 01: SSH Brute Force Detection

**Date:** 2026-03-17
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
**Severity:** High

## Lab Setup
- Attacker: Kali Linux ATTACKER_IP
- Victim: Ubuntu Server VICTIM_IP
- SIEM: Splunk Enterprise (Free)

## Attack Executed
```bash
hydra -l victim -P /usr/share/wordlists/rockyou.txt -t 4 ssh://VICTIM_IP
```

## Detection SPL Query
```splunk
index=main sourcetype=linux_secure failed
| stats count by src_ip, user
| where count > 5
| sort -count
```

## Findings
- 1100+ failed login attempts detected in Splunk
- sourcetype: linux_secure
- Tool used: Hydra

## MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: T1110.001 Brute Force

## Response Steps
1. Block source IP at firewall
2. Lock targeted account
3. Check for successful login after brute force
4. Investigate for persistence if login succeeded

## Screenshot
![SSH Brute Force Detection](../../screenshots/01-ssh-bruteforce.png)
