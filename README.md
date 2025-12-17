1. Introduction
1.1 Context and Operational Environment
   
The Security Operations Centre (SOC) serves as the critical defence mechanism for enterprise resilience, providing the central capability for monitoring, detecting, and responding to cyber threats (Vielberth et al., 2020). By aggregating telemetry from networks, endpoints, and cloud services into SIEM platforms like Splunk, SOCs enable analysts to coordinate incident response in a repeatable manner. This report presents a forensic analysis of a simulated security incident at Frothly Corporation using the Boss of the SOC (BOTSv3) dataset. The scenario simulates a sophisticated attack by the Taedonggang APT group against a hybrid infrastructure (AWS and on-premise), reflecting the modern challenge of maintaining visibility across fragmented attack surfaces (Cloud Security Alliance, 2021). Effective operation is framed by lifecycle models emphasising preparation, detection, and recovery.

1.2 The BOTSv3 Exercise
The BOTSv3 dataset serves as the operational substrate for this investigation, providing a high-fidelity emulation of a modern breach. Unlike static examples, BOTSv3 aggregates real-world telemetry, including AWS CloudTrail, Sysmon, and WinHostMon,to replicate the "fog of war" inherent in live operations (Splunk, 2020). This environment compels the analyst to apply rigorous detection engineering, distinguishing legitimate administrative behaviour from adversarial Tactics, Techniques, and Procedures (TTPs). By forcing the correlation of cloud API events with endpoint process execution, the exercise accurately simulates the cognitive load required in a live Tier 2 SOC role.

1.3 Objectives
The primary aim is to demonstrate mastery of the investigative workflow within Splunk, moving beyond alert validation to root cause analysis. The investigation is driven by four core objectives:
    
    • Forensic Reconstruction: Accurately answering the AWS-focused 200-level questions using advanced Splunk Search Processing Language (SPL) to extract high-fidelity Indicators of Compromise (IoCs).
    • Framework Application: Rigorously applying the MITRE ATT&CK Cloud matrix (e.g., T1078, T1098) and NIST SP 800-61 lifecycle to structure the narrative (The MITRE Corporation, 2024; Cichonski et al., 2012).
    • Evidence Synthesis: Substantiating findings with precise JSON field extractions to maintain a theoretical chain of custody.
    • Strategic Application: Formulating professional recommendations regarding the failure of identity-based perimeters (IAM) and egress filtering.
    
1.4 Scope and Assumptions
Defining forensic boundaries is critical to prevent scope creep.
    
    • Operational Scope: Analysis is strictly confined to the AWS and Endpoint sourcetypes within the local BOTSv3 (v3.0) deployment.
    
    • Role Definition: The report assumes the persona of a Tier 2 Incident Responder performing deep-dive correlation rather than initial triage.
    
    • Assumptions: The dataset is treated as a faithful, immutable representation of the incident. Remediation steps are theoretical recommendations based on an "Assumed Breach" mindset (SANS Institute, 2023).
    
2. SOC Roles & Incident Handling Reflection
2.1 Critical Evaluation of SOC Tiers
Standard industry models arrange SOC capabilities into tiers to manage alert velocity (Vielberth et al., 2020). Tier 1 (Triage) analysts validate high-volume alerts against playbooks, typically limited to binary "True/False Positive" decisions. In the Frothly scenario, a Tier 1 analyst monitoring AWS CloudTrail might flag a ConsoleLogin event. However, the limitation of this siloed approach becomes evident in BOTSv3: without the Tier 2 (Incident Response) skill set to correlate this cloud event with endpoint telemetry (e.g., WinHostMon), the wider scope of the Taedonggang intrusion,specifically the lateral movement to internal servers,would be missed. This exercise demonstrates that effective hybrid defence requires moving beyond rigid tiers to cross-functional competency, where analysts can pivot between cloud management planes and endpoint forensics (SANS Institute, 2023).

2.2 Application of the Incident Response Lifecycle
The investigation follows the NIST SP 800-61 Rev. 2 lifecycle, mapping the BOTSv3 workflow to the four key phases (Cichonski et al., 2012):
    
    • Prevention: The incident highlights systemic failures in Frothly’s preventative posture. The successful compromise of the IAM user "Bud" and subsequent S3 bucket exposure underscores the critical necessity of enforcing Multi-Factor Authentication (MFA) and strict egress filtering, which were absent.
    • Detection: This phase constitutes the core investigative effort. Navigating the "fog of war" in Splunk, the analysis required filtering benign administrative noise to identify high-fidelity Indicators of Compromise (IoCs). Success relied on "Detection Engineering",constructing advanced SPL queries to map the adversary's TTPs (e.g., MITRE T1078 Valid Accounts) rather than relying on static signatures (Splunk, 2020).
    • Response: While the static nature of the dataset precludes active intervention, forensic findings dictate the response strategy. Effective containment would require the immediate revocation of compromised AWS access keys and the network isolation of the crypto-mining endpoint to sever the C2 channel (Shackleford, 2016).
    • Recovery: The final phase focuses on restoration and hardening. Recommendations include sanitising the public S3 bucket, reimaging affected hosts, and transitioning to an "Identity-Centric" security model.

(add Picture here of cyber incident response cycle) 

2.3 Strategic Insight
Critically, BOTSv3 illustrates that Identity is the new perimeter. Traditional network controls (firewalls) offered no visibility into the S3 configuration changes (Cloud Security Alliance, 2021). Consequently, modern incident handling must prioritise identity telemetry (aws:iam) alongside traditional endpoint monitoring to close the visibility gap.

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
