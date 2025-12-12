1. Introduction
1.1 Context and Operational Environment
   
The Security Operations Centre (SOC) serves as the critical defence mechanism for enterprise resilience, providing the central capability for monitoring, detecting, and responding to cyber threats (Vielberth et al., 2020). By aggregating telemetry from networks, endpoints, and cloud services into SIEM platforms like Splunk, SOCs enable analysts to coordinate incident response in a repeatable manner. This report presents a forensic analysis of a simulated security incident at Frothly Corporation using the Boss of the SOC (BOTSv3) dataset. The scenario simulates a sophisticated attack by the Taedonggang APT group against a hybrid infrastructure (AWS and on-premise), reflecting the modern challenge of maintaining visibility across fragmented attack surfaces (Cloud Security Alliance, 2021). Effective operation is framed by lifecycle models emphasising preparation, detection, and recovery.

1.2 The BOTSv3 Exercise
The BOTSv3 dataset serves as the operational substrate for this investigation, providing a high-fidelity emulation of a modern breach. Unlike static examples, BOTSv3 aggregates real-world telemetry—including AWS CloudTrail, Sysmon, and WinHostMon—to replicate the "fog of war" inherent in live operations (Splunk, 2020). This environment compels the analyst to apply rigorous detection engineering, distinguishing legitimate administrative behaviour from adversarial Tactics, Techniques, and Procedures (TTPs). By forcing the correlation of cloud API events with endpoint process execution, the exercise accurately simulates the cognitive load required in a live Tier 2 SOC role.

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
Standard industry models arrange SOC capabilities into tiers to manage alert velocity (Vielberth et al., 2020). Tier 1 (Triage) analysts validate high-volume alerts against playbooks, typically limited to binary "True/False Positive" decisions. In the Frothly scenario, a Tier 1 analyst monitoring AWS CloudTrail might flag a ConsoleLogin event. However, the limitation of this siloed approach becomes evident in BOTSv3: without the Tier 2 (Incident Response) skill set to correlate this cloud event with endpoint telemetry (e.g., WinHostMon), the wider scope of the Taedonggang intrusion—specifically the lateral movement to internal servers—would be missed. This exercise demonstrates that effective hybrid defence requires moving beyond rigid tiers to cross-functional competency, where analysts can pivot between cloud management planes and endpoint forensics (SANS Institute, 2023).

2.2 Application of the Incident Response Lifecycle
The investigation follows the NIST SP 800-61 Rev. 2 lifecycle, mapping the BOTSv3 workflow to the four key phases (Cichonski et al., 2012):
    • Prevention: The incident highlights systemic failures in Frothly’s preventative posture. The successful compromise of the IAM user "Bud" and subsequent S3 bucket exposure underscores the critical necessity of enforcing Multi-Factor Authentication (MFA) and strict egress filtering, which were absent.
    • Detection: This phase constitutes the core investigative effort. Navigating the "fog of war" in Splunk, the analysis required filtering benign administrative noise to identify high-fidelity Indicators of Compromise (IoCs). Success relied on "Detection Engineering"—constructing advanced SPL queries to map the adversary's TTPs (e.g., MITRE T1078 Valid Accounts) rather than relying on static signatures (Splunk, 2020).
    • Response: While the static nature of the dataset precludes active intervention, forensic findings dictate the response strategy. Effective containment would require the immediate revocation of compromised AWS access keys and the network isolation of the crypto-mining endpoint to sever the C2 channel (Shackleford, 2016).
    • Recovery: The final phase focuses on restoration and hardening. Recommendations include sanitising the public S3 bucket, reimaging affected hosts, and transitioning to an "Identity-Centric" security model.

(add Picture here of cyber incident response cycle) 

2.3 Strategic Insight
Critically, BOTSv3 illustrates that Identity is the new perimeter. Traditional network controls (firewalls) offered no visibility into the S3 configuration changes (Cloud Security Alliance, 2021). Consequently, modern incident handling must prioritise identity telemetry (aws:iam) alongside traditional endpoint monitoring to close the visibility gap.
