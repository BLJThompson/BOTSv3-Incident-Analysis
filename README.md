# BOTSv3 Incident Analysis Report (AWS 200-Level Q1–Q8)
**Project:** Frothly Corporation Incident Response  
**Author:** Benjamin Thompson (@CompPly)

---

## 1. Introduction
The Security Operations Centre (SOC) serves as the enterprise's central hub for monitoring, detecting, and responding to cyber threats (Vielberth et al., 2020). This report details a forensic investigation into a security incident at Frothly Corporation using the Boss of the SOC (BOTSv3) dataset. The scenario highlights the challenge of maintaining visibility across hybrid and cloud environments (Cloud Security Alliance, 2021).

The investigation leverages BOTSv3’s detailed telemetry to simulate real SOC conditions (Splunk, 2020). Unlike static data, the analyst must distinguish legitimate administrative actions from adversarial Tactics, Techniques, and Procedures (TTPs). This approach mirrors Tier 2 investigations, where interpretation and context are as crucial as raw log volume.

The goal is to demonstrate a defensible investigative workflow addressing the AWS-focused 200-level questions (Q1–Q8). Using Splunk Search Processing Language (SPL), the analysis identifies IAM principals, detects non-MFA API activity, and attributes S3 misconfigurations. Queries are designed for repeatability, with explicit indexes and sourcetypes, to maintain evidential integrity, enable peer review, and facilitate dashboard operationalisation for future audits. Findings follow the NIST incident response lifecycle to aid root cause analysis (Cichonski et al., 2012).

The scope includes only `botsv3` events, prioritising control-plane activity through `aws:cloudtrail`, data-plane confirmation via `aws:s3:accesslogs`, and endpoint inventory via `winhostmon`. Written from a Tier 2 Incident Responder perspective, recommendations adopt an “assumed breach” approach (SANS Institute, 2023).

---

## 2. SOC Roles & Incident Handling Reflection
For this investigation, a standard three-tier SOC model is assumed. The objective is to convert raw telemetry into defensible evidence, ensuring timely escalation while minimising "alert fatigue" (Vielberth et al., 2020).

The BOTSv3 dataset demonstrates that effective defence requires cross-functional competency (SANS Institute, 2023):

* **Tier 1 (Monitoring & Triage):** Validates high-volume signals (e.g., public S3 changes, non-MFA API spikes) and filters benign activity against approved change.
* **Tier 2 (Incident Response):** Correlates identity with data-plane impact, cross-checks endpoint logs for drift, and confirms scope and intent.
* **Tier 3 (Threat Hunting & Engineering):** Converts Tier 2 findings into durable detections, tuning logic to reduce noise and surface “Shadow IT”.

The workflow aligns with NIST SP 800-61 Rev. 2 (Cichonski et al., 2012):

* **Preparation:** Centralised CloudTrail and WinHostMon telemetry.
* **Detection & Analysis:** Validation, scoping, and TTP mapping (MITRE Corporation, 2025) to build confidence.
* **Containment:** Revoke keys and enforce S3 “Block Public Access”.
* **Eradication & Recovery:** Remove unauthorised objects and isolate non-compliant endpoints for reimaging.
* **Post-Incident:** Implement SCP guardrails to prevent recurrence.

Escalation from Tier 1 to Tier 2 occurs once unauthorised activity is confirmed (e.g., public access change plus upload evidence). The incident shows over-reliance on detection for high-risk cloud actions. Prevention is required: platform-level SCPs enforcing Multi-Factor Authentication (MFA) would reduce credential abuse at source, and shared accounts should be removed to restore non-repudiation. In cloud environments, identity is the perimeter; traditional network controls offer limited visibility into configuration changes (Cloud Security Alliance, 2021).

## 3. Installation & Data Preparation
Splunk Enterprise (v10.0.2) was installed on a Linux workstation in the `/opt/splunk` directory, following standard Linux conventions. This location isolates Splunk binaries and indexes from the root filesystem. The service was started using `$SPLUNK_HOME/bin/splunk start`. Although production SOCs use distributed architectures for scalability, a standalone design was chosen here for forensic isolation and data stability (Vielberth et al., 2020).

![System Verification](evidence/Installation%20and%20Dashboard%20Setup/figure1.png)
*Figure 1: Hostname 'DefianceX-15' and Splunk Version 10.0.2 validation.*

The BOTSv3 dataset was acquired from GitHub via the “botsv3” repository. The download was verified by checking the archive size, ensuring error-free extraction, and confirming the directory structure contained expected files before ingestion.

![Data Preparation](evidence/Installation%20and%20Dashboard%20Setup/figure2.png)
*Figure 2: Verifying the BOTSv3 dataset file structure.*

The process started by manually installing the `botsv3_data_set` app into `/opt/splunk/etc/apps/`, which included `props.conf` settings for CIM compliance, normalising raw JSON fields like `userIdentity` for cross-domain correlation. The dataset was then extracted locally and ingested through a monitored directory input to maintain a static, repeatable path separate from live network feeds.

![Ingestion Settings](evidence/Installation%20and%20Dashboard%20Setup/figure3.png)
*Figure 3: Configuring the monitored directory input.*

Data was sent to a dedicated `botsv3` index instead of the main index. This segmentation enforces Data Governance, supporting granular Retention Policies and Role-Based Access Control (RBAC) to protect sensitive data (ISACA, 2019). Post-ingestion, `tstats` validation confirmed **1,944,092 events**, establishing a baseline.

![Data Validation](evidence/Installation%20and%20Dashboard%20Setup/figure4.png)
*Figure 4: Validating event count (1,944,092) in the botsv3 index.*

3. Installation & Data Preparation
This section establishes the technical foundation for the investigation by describing Splunk installation and dataset onboarding steps in a manner that supports repeatability, traceability, and data confidence in a SOC context. The setup is deemed successful once Splunk is reachable via the web interface and operates reliably after reboot.

3.1 Deployment architecture and environment baseline
Splunk Enterprise was deployed as a single-node instance on a local Ubuntu workstation (KDE Plasma desktop environment) to prioritise repeatability, straightforward troubleshooting, and controlled dataset onboarding for SOC-style investigation. The trade-off versus a production SOC architecture is the absence of enterprise characteristics such as separated roles (dedicated indexers/search heads), horizontal scaling, and high availability.
The host baseline was recorded to support reproducibility and capacity awareness during ingestion and indexing.
    • Host type: Local workstation (hostname: benjamin-thompson-DefianceX-15)
    • Operating system: Ubuntu 24.04.3 LTS (Release 24.04, Codename noble)
    • Kernel: Linux 6.14.0-37-generic (x86_64)
    • CPU: 12th Gen Intel® Core™ i7-12700H, 20 logical CPUs (x86_64)
    • Memory: 32 GB RAM
    • Storage devices and mount points (summary):
        ◦ nvme1n1 1.8 TB (root filesystem mounted on nvme1n1p3 at /)
        ◦ nvme0n1 238.5 GB (mounted at /media/benjamin-thompson/New Volume)
    • Splunk installation and data location: Splunk was installed under /opt/splunk. BOTSv3 indexes were stored on local disk within Splunk’s indexing storage (default path typically under /opt/splunk/var/lib/splunk.
    • Splunk version: Splunk 10.0.2 (build e2d18b4767e9)
This deployment mirrors a SOC “lab” approach: an isolated analysis environment with controlled access, local evidence handling, and reproducible configuration. Recording OS/kernel, compute capacity, storage layout, Splunk version, and access boundaries supports defensible reporting by demonstrating that data ingestion and validation were performed under a known, repeatable system baseline.

3.3 BOTSv3 dataset acquisition and integrity handling
The BOTSv3 dataset was obtained from GitHub using the “botsv3” repository the download was verified by confirming the archive size, validating successful extraction without errors, and checking that the extracted directory structure contained the expected files prior to ingestion. 
[Evidence fig]

3.4 Dataset ingestion workflow (main part)
BOTSv3 was acquired as an archive, extracted locally, and the extracted dataset directories were then copied onto the Splunk host for ingestion. Data onboarding was performed from local disk to maintain a controlled and repeatable ingestion path and to avoid reliance on network-based transfers during indexing. The dataset was validated through searching for the index on the search screen.
[Fig]

3.5 Validation and quality checks
To confirm that BOTSv3 was ingested correctly and is suitable for SOC-style investigation, a short set of onboarding QA checks was performed. These checks focus on index presence, volume, coverage.
[Fig]
[Fig]
In a SOC context, validation acts as data onboarding QA: analysts must be confident that telemetry is complete, time-aligned, and correctly parsed before attempting detection or root-cause investigation. These checks provide a defensible basis for later findings by demonstrating that the dataset was indexed into the correct location, exhibits broad source coverage, spans an appropriate timeframe, and contains the core fields required for investigative pivoting.

3.6 Design choices in SOC infrastructure context
A single-node Splunk deployment was considered acceptable for this scenario because the work was performed in a controlled, local lab environment with a bounded investigation dataset and a requirement for repeatable, auditable setup steps. Compared with a production SOC architecture, this design does not provide horizontal scalability, high availability, or role separation (e.g., dedicated indexers and search heads), and therefore would not be suitable for enterprise-wide continuous monitoring. Risk within scope was mitigated by establishing a clear host baseline (OS/kernel, CPU, memory, and storage capacity), restricting exposure to local administration, and applying validation gates (index presence, sourcetype coverage, time-range checks, and field spot-checks) to ensure the telemetry was trustworthy prior to investigation.

Q1 - Identification of IAM Users
The objective of identifying the IAM (Identity & Access Management) users that accessed the AWS services within Frothly’s environment, using Splunk to interrogate the BOTSv3 dataset. As CloudTrail provides authoritative audit records of AWS control-plane and data-plane API activity. I I first confirmed the CloudTrail telemetry was present by using a Metadata search within the dataset sourcetypes (| metadata type=sourcetypes index=botsv3 | stats values(sourcetype)).

(Figure A)

Inspecting user-related fields within CloudTrail events (index=botsv3 sourcetype=aws:cloudtrail | fields user* | head 10000) to establish the correct field for human IAM users onfirming that userIdentity.type="IAMUser" distinguishes named IAM principals from other identity categories such as assumed roles or service principals.

(Figure B)

On this basis, I executed the final aggregation query below to derive the definitive IAM user list:

   index=botsv3 sourcetype=aws:cloudtrail "userIdentity.type"=IAMUser
   | stats count by userIdentity.userName
   
(Figure C)

The results indicate that the IAM users who accessed AWS services (successfully or unsuccessfully) are bstoll,btun,splunk_access,web_admin

(Figure D)

These IAM users were also put into a dashboard so future actions can be monitored seen below:

Q1

index=botsv3 sourcetype=aws:cloudtrail "userIdentity.type"=IAMUser
| stats count by userIdentity.userName


Q2

index=botsv3 sourcetype=aws:cloudtrail NOT eventName=ConsoleLogin

index=botsv3 sourcetype=aws:cloudtrail NOT eventName=ConsoleLogin "userIdentity.sessionContext.attributes.mfaAuthenticated"="*"

Q3
index=botsv3 sourcetype="hardware" 

Q4

index=botsv3 sourcetype=aws:cloudtrail eventName=PutBucketAcl
| table _time userIdentity.userName eventID requestParameters.bucketName


Q5
index=botsv3 sourcetype=aws:cloudtrail eventID=ab45689d-69cd-41e7-8705-5350402cf7ac
| table _time eventName eventID userIdentity.userName userIdentity.arn

Q7
index=botsv3 sourcetype="aws:s3:accesslogs" put .txt

Q8
index=botsv3 sourcetype=winhostmon

index=botsv3 sourcetype=winhostmon source=operatingsystem

index=botsv3 sourcetype=winhostmon
| dedup OS, host
| table OS, host
