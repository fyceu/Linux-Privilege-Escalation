# Linux-Privilege-Escalation

## Background and Overview
Leadership was notified that sensitive employee data had been discovered on the dark web. Early indicators suggested that the leak originated from inside the organization. HR also reported that an employee within the same department as the exposed information had a history of leaving their workstation unlocked and unattended, raising concerns about potential misuse of their account. Leadership has classified this as a potential insider threat incident and tasked the security team with determining how the data was leaked online and whether the employee played a role in the security incident.

You can read the full investigation walkthrough [here](). <br>
You can read the Investigation Report sent to leadership [here](). <br>
You can access the exfiltration script [here](). <br>

## Tech Stack
<img width="50" height="50" alt="azure" src="https://github.com/user-attachments/assets/fd2866b6-d2fa-4e61-bf55-0b20d63fca5e" />
<img width="50" height="50" alt="ubuntu logo" src="https://github.com/user-attachments/assets/277aafa4-bf60-49dc-9d59-edfed17d17d3" />
<img width="50" height="50" alt="icons8-windows-defender-48" src="https://github.com/user-attachments/assets/41507be1-eadc-440c-b577-ccbf835e91e3" />
<img width="50" height="50" alt="azure blob storage" src="https://github.com/user-attachments/assets/35e2af4f-8da1-4948-bafe-53eff2fe8660" />
<img width="50" height="50" alt="MaterialIconThemeKusto" src="https://github.com/user-attachments/assets/7e9d871a-0391-43be-a826-08486ef1d562" />

- Microsoft Azure
- Ubuntu Linux Server
- Microsoft Defender for Endpoint
- Azure Blob Storage 
- Kusto Query Language (KQL)

## Executive Summary

To get a full understanding of these findings, you can read the full investigation walkthrough [here](). 
## Recommendations
**Disable Unauthorized Accounts**
- Immediately remove the unauthorized `guest` account
- Reset credentials for `labuser123` as their account was used to carry out malicious activities

**Data Loss Prevention (DLP) controls**
- Review and update current DLP controls

**Revoke Cloud Credentials**
- Rotate Azure Storage account keys as the current keys were compromised and used in the attack

**Implement Privileged Access Controls**
- Review `labuser123`'s role responsibilities to determine if they need administrative privileges
   - If admin privileges are needed, consider Just-In-Time privileges

**Strengthen Endpoint Monitoring**
- File Integrity Monitoring for sensitive Linux files such as  `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` for modification
- Monitor for hidden file and directory creation ( begins with `'.'`)
- Monitor for decoding commands (such as `base64 -d`)
- Monitor for execution of scripts
- Periodic monitoring of accounts and groups with privileged access
- Review bash and audit logs are properly forwarded to SIEM

**Training**
- Mandatory security awareness training on Insider Threats and business impact of security incidents
