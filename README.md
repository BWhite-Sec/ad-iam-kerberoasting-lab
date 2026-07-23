# AD/IAM Home Lab — Kerberoasting Attack Simulation & Detection

A self-built Active Directory lab demonstrating Kerberoasting attack
simulation, detection engineering in Splunk, and IAM root-cause remediation —
built to combine SOC detection skills with IAM analysis in a single project,
rather than treating them as two separate ones.

## Overview

This project stands up a small two-tier AD domain, deliberately configures a
realistic vulnerable service account (weak/non-expiring password, registered
SPN, over-privileged group membership), simulates a Kerberoasting attack
against it from a low-privileged domain user, and detects the attack using
two complementary, iteratively-tuned Splunk detections mapped to MITRE
ATT&CK T1558.003.

**What this demonstrates:**
- Standing up an Active Directory domain (Windows Server 2025) and joining a
-   domain-joined workstation
-   - Structuring OUs and users to reflect a realistic small organization
    - - Deliberately modeling a real-world IAM misconfiguration (weak password +
      -   SPN + missing AES support + excessive privilege) and explaining *why* each
      -     piece matters independently
      - - Simulating Kerberoasting using only native, unprivileged Windows/.NET
        -   functionality — no external attacker tooling required
        -   - Writing and iteratively tuning SPL detection logic, including a documented
            -   false-positive-reduction story (not just a query that worked on the first
            -     try)
            - - Mapping detections to MITRE ATT&CK
              - - Producing a two-part incident report that separates the SOC detection
                -   narrative from the IAM root-cause/remediation narrative
               
                -   ## Architecture
               
                -   ```
                    ┌─────────────────────┐        ┌─────────────────────────┐
                    │   WS01 (Windows 11   │        │   DC01 (Windows Server   │
                    │   Pro, domain-joined) │──────▶│   2025) — AD DS + DNS    │
                    │   Attacker: jdoe      │  LDAP/ │   labcorp.local          │
                    │   (standard user)     │ Kerberos│  Universal Forwarder     │
                    └─────────────────────┘  :88/389└───────────┬──────────────┘
                                                                 │ TCP 9997
                                                                 ▼
                                                     ┌─────────────────────────┐
                                                     │    Splunk Enterprise     │
                                                     │  (existing home-lab      │
                                                     │   indexer, index=ad)     │
                                                     └─────────────────────────┘
                    ```

                    All VMs run on a VirtualBox host-only network (`192.168.56.0/24`), isolated
                    from the host machine's network.

                    **Stack:**
                    | Component | Details |
                    |---|---|
                    | Domain Controller | Windows Server 2025 Standard (Desktop Experience) |
                    | Domain | `labcorp.local` (NetBIOS `LABCORP`) |
                    | Workstation | Windows 11 Pro, domain-joined |
                    | Indexer | Existing Splunk Enterprise instance from [`splunk-siem-lab`](https://github.com/BWhite-Sec/splunk-siem-lab) |
                    | Forwarder | Splunk Universal Forwarder on DC01, forwarding the Security event log |

                    ## Repo Structure

                    ```
                    ├── README.md
                    ├── docs/                       → Two-part incident report (SOC + IAM)
                    ├── detections/                 → SPL detection queries
                    ├── screenshots/                → Evidence from Splunk searches and AD/PowerShell
                    └── configs/                    → Sanitized inputs.conf used on DC01
                    ```

                    ## Detections

                    | Detection | Technique | File |
                    |---|---|---|
                    | RC4-encrypted service ticket (primary indicator) | T1558.003 | [`detections/kerberoasting_rc4_detection.spl`](detections/kerberoasting_rc4_detection.spl) |
                    | Multi-SPN enumeration burst (with documented tuning history) | T1558.003 | [`detections/kerberoasting_burst_detection.spl`](detections/kerberoasting_burst_detection.spl) |

                    See [`docs/kerberoasting_incident_report.md`](docs/kerberoasting_incident_report.md)
                    for the full two-part write-up: Part A covers the attack simulation and
                    detection engineering; Part B covers the root cause and IAM remediation.

                    ## Key Technical Notes

                    A few real findings worth calling out (documented in full in the incident
                    report):

                    - **SPN-to-account collapsing**: Event ID 4769's `Service_Name` field
                    -   reflects the *account* an SPN belongs to, not the raw SPN string
                    -     requested. Several commonly-enumerated SPNs (`HTTP`, `LDAP`, `CIFS`) are
                    -   registered to the domain controller's own machine account by default,
                    -     which means a burst-detection threshold tuned for a large enterprise
                    -   domain (many separate service accounts) does not transfer directly to a
                    -     small lab domain and needs to be tuned to the actual environment.
                    - - **Encryption downgrade without any attacker action**: `svc-sql`'s Kerberos
                      -   ticket came back RC4-encrypted not because of anything the simulated
                      -     attacker did, but because the account was never explicitly configured to
                      -   support AES (`msDS-SupportedEncryptionTypes` was `0x0`) — a separate,
                      -     independently-remediable misconfiguration from the weak password itself.
                      - - **Iterative false-positive tuning**: the burst detection went through
                        -   three versions before reaching a clean result, including a version that
                        -     correctly caught the attack but also flagged legitimate machine-account
                        -   and admin activity — full tuning history is documented in the `.spl` file
                        -     and the incident report.
                       
                        - ## Roadmap
                       
                        - - [x] Build AD domain + vulnerable service account + Kerberoasting simulation
                          - [ ] - [x] Detect via RC4 ticket encryption (primary indicator)
                          - [ ] - [x] Detect via multi-SPN enumeration burst, with documented tuning
                          - [ ] - [ ] Cross-reference Event ID 4768 (TGT requests) for full authentication chain visibility
                          - [ ] - [ ] Add a gMSA before/after comparison (same service, gMSA-backed, demonstrate reduced roastability)
                          - [ ] - [ ] Combine with [`splunk-siem-lab`](https://github.com/BWhite-Sec/splunk-siem-lab) detections into a single "Credential Attack Overview" dashboard
                         
                          - [ ] ## Author
                          - [ ] Brandon White — [LinkedIn](https://www.linkedin.com/in/brandon-white-b62701177)
                          - [ ] 
