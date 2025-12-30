window.CYBER_RESOURCES_BLUE = [
  {
    "name": "MITRE ATT&CK",
    "url": "https://attack.mitre.org/",
    "cat": "blue",
    "type": "framework",
    "desc": "Adversary TTP knowledge base",
    "details": "## Overview\nMITRE ATT&CK is a curated knowledge base of adversary tactics, techniques, and procedures (TTPs).\n\n## How defenders use it\n- Map detections and controls to techniques (coverage & gaps).\n- Drive threat hunting hypotheses and purple-team exercises.\n- Standardize reporting (e.g., “T1059 Command and Scripting Interpreter”).\n\n## Practical workflow\n1. Pick a threat scenario (e.g., ransomware).\n2. Select likely techniques for your environment.\n3. Validate telemetry + write detections.\n\n## Alternatives\n- MITRE D3FEND (countermeasure taxonomy)\n- NIST SP 800-61 (IR lifecycle)"
  },
  {
    "name": "MITRE ATT&CK Navigator",
    "url": "https://mitre-attack.github.io/attack-navigator/",
    "cat": "blue",
    "type": "tool",
    "desc": "ATT&CK technique heatmaps",
    "details": "## Overview\nWeb app to create ATT&CK matrices/heatmaps for coverage, hunts, campaigns, or assessments.\n\n## Example usage (defensive planning)\nCreate a layer from a data source (e.g., EDR detections) and color techniques by confidence/coverage.\n\n## Notes\n- Keep layers versioned in your repo (JSON).\n- Align technique IDs to the correct ATT&CK domain (Enterprise / Mobile / ICS).\n\n## Alternatives\n- ATT&CK Workbench\n- Your own matrix in spreadsheets (less portable)"
  },
  {
    "name": "MITRE D3FEND",
    "url": "https://d3fend.mitre.org/",
    "cat": "blue",
    "type": "framework",
    "desc": "Defensive countermeasure knowledge base",
    "details": "## Overview\nMITRE D3FEND provides a knowledge base of cybersecurity countermeasures and their relationships.\n\n## Use cases\n- Normalize control language (“what are we doing?”) across teams and vendors.\n- Map controls to ATT&CK techniques to reason about defensive coverage.\n\n## Alternatives\n- CIS Controls\n- NIST SP 800-53"
  },
  {
    "name": "CIS Critical Security Controls",
    "url": "https://www.cisecurity.org/controls/cis-controls-list",
    "cat": "blue",
    "type": "framework",
    "desc": "Prioritized security best practices",
    "details": "## Overview\nCIS Controls are a prioritized set of safeguards to reduce the most common attacks.\n\n## Use cases\n- Build a roadmap (quick wins vs maturity work).\n- Benchmark your program and produce evidence for leadership.\n\n## Notes\n- Pair with CIS Benchmarks for technical hardening guidance.\n\n## Alternatives\n- NIST CSF\n- ISO/IEC 27001"
  },
  {
    "name": "NIST Cybersecurity Framework (CSF)",
    "url": "https://www.nist.gov/cyberframework",
    "cat": "blue",
    "type": "framework",
    "desc": "Identify/Protect/Detect/Respond/Recover framework",
    "details": "## Overview\nNIST CSF is a high-level framework for organizing security outcomes across five functions.\n\n## Use cases\n- Program maturity assessment and gap analysis.\n- Communicate priorities to non-technical stakeholders.\n\n## Alternatives\n- ISO/IEC 27001 Annex A\n- CIS Controls"
  },
  {
    "name": "NIST SP 800-61 (Incident Handling Guide)",
    "url": "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
    "cat": "blue",
    "type": "guide",
    "desc": "Incident response lifecycle and guidance",
    "details": "## Overview\nNIST SP 800-61 provides guidance on incident response, preparation, detection, containment, eradication, and recovery.\n\n## Operational tip\nTurn the guidance into checklists/runbooks for common incident types (phishing, malware, credential compromise).\n\n## Alternatives\n- SANS Incident Handler’s Handbook\n- ENISA IR guidance"
  },
  {
    "name": "FIRST CSIRT Services Framework",
    "url": "https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1",
    "cat": "blue",
    "type": "framework",
    "desc": "CSIRT capability and service catalog",
    "details": "## Overview\nA reference model describing CSIRT services and capabilities to help structure an internal or national CSIRT.\n\n## Use cases\n- Define what your SOC/CSIRT provides (and what it does not).\n- Align staffing, KPIs and processes to services.\n\n## Alternatives\n- ENISA CSIRT maturity materials\n- ITIL/Service catalogs"
  },
  {
    "name": "MITRE CWE",
    "url": "https://cwe.mitre.org/",
    "cat": "blue",
    "type": "database",
    "desc": "Weakness classification",
    "details": "## Overview\nCommon Weakness Enumeration (CWE) is a taxonomy of software weaknesses.\n\n## Use cases\n- Normalize findings (SAST/DAST/appsec reviews).\n- Trend analysis (“top weakness families in our code”).\n\n## Alternatives\n- OWASP Top 10 (risk list, not taxonomy)\n- CAPEC (attack patterns)"
  },
  {
    "name": "MITRE CAPEC",
    "url": "https://capec.mitre.org/",
    "cat": "blue",
    "type": "database",
    "desc": "Common Attack Pattern Enumeration and Classification",
    "details": "## Overview\nCAPEC catalogs common attack patterns and links to CWEs and ATT&CK where applicable.\n\n## Use cases\n- Threat modeling and secure design reviews.\n- Training developers on attacker thinking (pattern → mitigation).\n\n## Alternatives\n- OWASP ASVS/MASVS (requirements-based)\n- STRIDE (threat modeling)"
  },
  {
    "name": "CVE Program",
    "url": "https://www.cve.org/",
    "cat": "blue",
    "type": "database",
    "desc": "Vulnerability identifiers",
    "details": "## Overview\nCVE provides standardized identifiers for publicly disclosed vulnerabilities.\n\n## Defensive workflow\nUse CVE IDs to correlate scanner results, advisories, patch SLAs, and asset inventory.\n\n## Alternatives\n- Vendor advisories (less standardized)\n- GHSA (GitHub Security Advisories)"
  },
  {
    "name": "NVD (National Vulnerability Database)",
    "url": "https://nvd.nist.gov/",
    "cat": "blue",
    "type": "database",
    "desc": "CVE enrichment, CVSS, CPE mappings",
    "details": "## Overview\nNVD enriches CVEs with CVSS metrics, CPE matches, and references.\n\n## Notes\n- CVSS is not “risk”; add exploitability (EPSS), exposure, and business impact.\n\n## Alternatives\n- Vendor security bulletins\n- VulnDB (commercial)"
  },
  {
    "name": "CISA Known Exploited Vulnerabilities (KEV)",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "cat": "blue",
    "type": "database",
    "desc": "Actively exploited CVE catalog",
    "details": "## Overview\nCISA KEV is a list of vulnerabilities known to be exploited in the wild.\n\n## Practical use\n- Drive patch prioritization (KEV first).\n- Create detection and compensating controls for KEV that cannot be patched quickly.\n\n## Alternatives\n- EPSS (exploit probability)\n- Vendor threat intel feeds"
  },
  {
    "name": "FIRST EPSS",
    "url": "https://www.first.org/epss/",
    "cat": "blue",
    "type": "calculator",
    "desc": "Exploit probability scoring",
    "details": "## Overview\nEPSS estimates the probability that a vulnerability will be exploited in the wild.\n\n## Use cases\n- Patch prioritization alongside asset criticality and exposure.\n\n## Alternatives\n- CVSS (severity, not probability)\n- KEV (binary exploited/not)"
  },
  {
    "name": "Sigma Rules",
    "url": "https://github.com/SigmaHQ/sigma",
    "cat": "blue",
    "type": "reference",
    "desc": "SIEM-agnostic detection rules",
    "details": "## Overview\nSigma is a generic signature format for log-based detections. The main repo contains thousands of community rules.\n\n## Example usage (defensive engineering)\nConvert Sigma to your SIEM backend query using a converter, then validate on test data before enabling.\n\n## Notes\n- Treat community rules as starting points; tune to your environment.\n- Track false positives and maintain suppression logic.\n\n## Alternatives\n- Splunk SPL detections (vendor-specific)\n- Elastic detection rules (EQL/KQL)",
    "source": "https://github.com/SigmaHQ/sigma"
  },
  {
    "name": "Suricata",
    "url": "https://suricata.io/",
    "cat": "blue",
    "type": "tool",
    "desc": "Network IDS/IPS and NSM engine",
    "details": "## Overview\nSuricata is an open-source IDS/IPS/NSM engine supporting signatures, protocol parsing, and file extraction.\n\n## Example (lab / authorized network)\n```bash\n# Run Suricata on a pcap to generate alerts (offline analysis)\nsuricata -r traffic.pcap -S local.rules -l ./suricata-logs\n```\n\n## Alternatives\n- Snort\n- Zeek (protocol metadata and scripting)"
  },
  {
    "name": "Zeek",
    "url": "https://zeek.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Network security monitoring framework",
    "details": "## Overview\nZeek (formerly Bro) generates rich protocol logs and supports scripting for custom detections.\n\n## Example (pcap analysis)\n```bash\nzeek -r traffic.pcap\n# Inspect logs like conn.log, http.log, dns.log\n```\n\n## Alternatives\n- Suricata (signature-heavy IDS)\n- Wireshark (interactive packet analysis)"
  },
  {
    "name": "Wireshark",
    "url": "https://www.wireshark.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Packet capture and protocol analysis",
    "details": "## Overview\nWireshark is the standard GUI tool for inspecting network traffic and diagnosing protocol issues.\n\n## Example (capture filter vs display filter)\nCapture filter: `tcp port 443` (limits what is captured).\nDisplay filter: `tls && ip.addr==10.0.0.5` (filters what you view).\n\n## Alternatives\n- tshark (CLI)\n- tcpdump (lightweight capture)"
  },
  {
    "name": "Security Onion",
    "url": "https://securityonion.net/",
    "cat": "blue",
    "type": "tool",
    "desc": "NSM + SOC platform (Zeek/Suricata/etc.)",
    "details": "## Overview\nSecurity Onion is a Linux distribution/platform for network security monitoring, combining tools like Zeek and Suricata with analysis workflows.\n\n## Use cases\n- Rapid SOC lab setup for detections and investigations.\n- Centralize network logs and alerts for triage.\n\n## Alternatives\n- Elastic Stack + Beats/Agent\n- Splunk (commercial)"
  },
  {
    "name": "Wazuh",
    "url": "https://wazuh.com/",
    "cat": "blue",
    "type": "tool",
    "desc": "Open-source XDR/SIEM (agents + rules)",
    "details": "## Overview\nWazuh provides endpoint monitoring, file integrity monitoring, vulnerability detection, and SIEM-like alerting.\n\n## Example (agent install concept)\nDeploy the Wazuh agent to endpoints, forward alerts to the manager, then map rules to ATT&CK for coverage tracking.\n\n## Alternatives\n- OSSEC (ancestor project)\n- Elastic Security"
  },
  {
    "name": "osquery",
    "url": "https://osquery.io/",
    "cat": "blue",
    "type": "tool",
    "desc": "SQL interface for endpoint telemetry",
    "details": "## Overview\nosquery exposes OS state as SQL tables (processes, users, sockets, etc.) for DFIR and monitoring.\n\n## Example (local query)\n```bash\nosqueryi \"SELECT pid, name, path FROM processes LIMIT 10;\"\n```\n\n## Alternatives\n- Velociraptor (VQL + collections)\n- Sysmon + SIEM (Windows-heavy telemetry)"
  },
  {
    "name": "FleetDM",
    "url": "https://fleetdm.com/",
    "cat": "blue",
    "type": "tool",
    "desc": "osquery fleet management",
    "details": "## Overview\nFleet manages osquery deployments at scale with packs, live queries, and endpoint inventory views.\n\n## Example (defensive workflow)\nUse packs for baseline monitoring (startup items, persistence keys) and schedule queries for continuous visibility.\n\n## Alternatives\n- Kolide (commercial; similar approach)\n- Elastic Agent (different telemetry model)"
  },
  {
    "name": "Sysmon",
    "url": "https://learn.microsoft.com/sysinternals/downloads/sysmon",
    "cat": "blue",
    "type": "tool",
    "desc": "Windows event telemetry (Sysinternals)",
    "details": "## Overview\nSysmon provides detailed Windows telemetry (process creation, network connections, driver loads, etc.) into the Windows Event Log.\n\n## Example (high-level)\nDeploy Sysmon with a curated configuration and forward events to your SIEM/EDR data lake for detections.\n\n## Alternatives\n- Windows Security Auditing + advanced auditing\n- EDR telemetry (vendor-specific)"
  },
  {
    "name": "SwiftOnSecurity Sysmon Config",
    "url": "https://github.com/SwiftOnSecurity/sysmon-config",
    "cat": "blue",
    "type": "reference",
    "desc": "Curated Sysmon configuration",
    "details": "## Overview\nCommunity-maintained Sysmon configuration to capture high-value events while balancing noise.\n\n## Notes\n- Treat as baseline; tune for your environment and threat model.\n- Validate impact on endpoints before wide rollout.\n\n## Alternatives\n- Olaf Hartong Sysmon Modular\n- Custom configs via testing",
    "source": "https://github.com/SwiftOnSecurity/sysmon-config"
  },
  {
    "name": "Olaf Hartong Sysmon Modular",
    "url": "https://github.com/olafhartong/sysmon-modular",
    "cat": "blue",
    "type": "reference",
    "desc": "Modular Sysmon configs and tooling",
    "details": "## Overview\nModular Sysmon configuration sets to compose telemetry depending on use case (endpoints, servers, etc.).\n\n## Alternatives\n- SwiftOnSecurity sysmon-config\n- Vendor EDR (if available)",
    "source": "https://github.com/olafhartong/sysmon-modular"
  },
  {
    "name": "Velociraptor",
    "url": "https://docs.velociraptor.app/",
    "cat": "blue",
    "type": "tool",
    "desc": "Endpoint visibility, hunting and collections (VQL)",
    "details": "## Overview\nVelociraptor collects endpoint state using VQL queries for DFIR, hunting, and targeted artifact collection.\n\n## Example (defensive collection idea)\nCreate an artifact that collects suspicious persistence locations and run it across a scoped set of hosts.\n\n## Notes\n- Start with small hunts; ensure privacy/legal policies are satisfied.\n\n## Alternatives\n- osquery + Fleet\n- GRR Rapid Response",
    "source": "https://github.com/Velocidex/velociraptor"
  },
  {
    "name": "TheHive",
    "url": "https://thehive-project.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Incident response case management",
    "details": "## Overview\nTheHive is a platform for case management and collaborative incident response (tasks, observables, timelines).\n\n## Example workflow\nCreate a case, add observables (IPs/hashes/domains), run enrichment responders, assign tasks, and track containment actions.\n\n## Alternatives\n- ServiceNow SecOps (commercial)\n- Jira + custom IR templates (lighter weight)"
  },
  {
    "name": "Cortex",
    "url": "https://github.com/TheHive-Project/Cortex",
    "cat": "blue",
    "type": "tool",
    "desc": "Observable analysis and response automation",
    "details": "## Overview\nCortex runs analyzers (enrichments) and responders (actions) for observables and integrates with TheHive.\n\n## Example usage (safe automation)\nEnrich a suspicious domain with passive DNS and reputation sources; trigger a ticket or notification on high confidence.\n\n## Alternatives\n- SOAR platforms (commercial)\n- Custom serverless enrichment pipelines",
    "source": "https://github.com/TheHive-Project/Cortex"
  },
  {
    "name": "MISP",
    "url": "https://www.misp-project.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Threat intel platform and sharing",
    "details": "## Overview\nMISP supports creation, storage, and sharing of threat intelligence (events, attributes, sightings) with taxonomy support.\n\n## Use cases\n- Internal TI repository; share with trusted communities.\n- Drive blocking and detection content (with validation).\n\n## Alternatives\n- OpenCTI (graph-based)\n- Commercial TIPs"
  },
  {
    "name": "OpenCTI",
    "url": "https://www.opencti.io/",
    "cat": "blue",
    "type": "tool",
    "desc": "Open-source threat intel platform (STIX2 graph)",
    "details": "## Overview\nOpenCTI organizes CTI in a graph using STIX2, allowing relationships between actors, malware, indicators, and incidents.\n\n## Notes\n- Ensure source confidence and labeling discipline to avoid poisoning your own intel.\n\n## Alternatives\n- MISP\n- Commercial TIPs"
  },
  {
    "name": "YARA",
    "url": "https://virustotal.github.io/yara/",
    "cat": "blue",
    "type": "tool",
    "desc": "Pattern matching for malware and files",
    "details": "## Overview\nYARA lets you create rules to identify files based on strings and conditions; used for malware hunting and triage.\n\n## Example (safe local scan)\n```bash\n# Scan a directory for matches\nyara -r rules.yar /path/to/suspicious/files\n```\n\n## Alternatives\n- ClamAV (signature AV)\n- Sigma (log detections, not file content)"
  },
  {
    "name": "capa",
    "url": "https://github.com/mandiant/capa",
    "cat": "blue",
    "type": "tool",
    "desc": "Identify capabilities in binaries",
    "details": "## Overview\ncapa detects capabilities in executable files (e.g., “uses HTTP”, “creates service”) using a rule set.\n\n## Example (local triage)\n```bash\ncapa suspicious.exe\n```\n\n## Alternatives\n- Ghidra (manual reverse engineering)\n- PEStudio (Windows PE metadata focus)",
    "source": "https://github.com/mandiant/capa"
  },
  {
    "name": "Volatility 3",
    "url": "https://github.com/volatilityfoundation/volatility3",
    "cat": "blue",
    "type": "tool",
    "desc": "Memory forensics framework",
    "details": "## Overview\nVolatility analyzes memory dumps to extract processes, DLLs, network connections, and artifacts for DFIR.\n\n## Example (triage on memory dump)\n```bash\nvol -f mem.raw windows.pslist\n```\n\n## Alternatives\n- Rekall (older)\n- KAPE + live response (disk-focused)",
    "source": "https://github.com/volatilityfoundation/volatility3"
  },
  {
    "name": "KAPE",
    "url": "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape",
    "cat": "blue",
    "type": "tool",
    "desc": "Targeted forensic collection",
    "details": "## Overview\nKAPE (by Kroll) helps collect and process forensic artifacts quickly (triage and acquisition).\n\n## Notes\n- Validate collection scope and privacy/legal requirements.\n\n## Alternatives\n- Velociraptor collections\n- GRR Rapid Response"
  },
  {
    "name": "GRR Rapid Response",
    "url": "https://github.com/google/grr",
    "cat": "blue",
    "type": "tool",
    "desc": "Remote live forensics and response",
    "details": "## Overview\nGRR is an incident response framework for remote live forensics at scale.\n\n## Alternatives\n- Velociraptor\n- osquery + Fleet",
    "source": "https://github.com/google/grr"
  },
  {
    "name": "OpenSCAP",
    "url": "https://www.open-scap.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Compliance scanning and remediation (SCAP)",
    "details": "## Overview\nOpenSCAP implements SCAP standards for auditing and compliance scanning (e.g., security baselines).\n\n## Use cases\n- Continuous hardening checks on Linux fleets.\n- Evidence generation for audits.\n\n## Alternatives\n- Lynis (lightweight)\n- CIS-CAT (commercial)"
  },
  {
    "name": "Lynis",
    "url": "https://cisofy.com/lynis/",
    "cat": "blue",
    "type": "tool",
    "desc": "Unix security auditing and hardening suggestions",
    "details": "## Overview\nLynis audits Unix-like systems and suggests hardening improvements.\n\n## Example (local audit)\n```bash\nlynis audit system\n```\n\n## Alternatives\n- OpenSCAP\n- CIS Benchmarks (guidance)"
  },
  {
    "name": "CIS Benchmarks",
    "url": "https://www.cisecurity.org/cis-benchmarks",
    "cat": "blue",
    "type": "guide",
    "desc": "Configuration hardening guides",
    "details": "## Overview\nCIS Benchmarks provide prescriptive hardening guidance for OSs, cloud services, and applications.\n\n## Notes\n- Test in staging; some recommendations may break legacy apps.\n\n## Alternatives\n- DISA STIGs\n- Vendor hardening guides"
  },
  {
    "name": "DISA STIGs",
    "url": "https://public.cyber.mil/stigs/",
    "cat": "blue",
    "type": "guide",
    "desc": "Defense Information Systems Agency hardening guides",
    "details": "## Overview\nSTIGs are detailed security configuration guides used widely for compliance and secure baselines.\n\n## Alternatives\n- CIS Benchmarks\n- Vendor baselines"
  },
  {
    "name": "OWASP ASVS",
    "url": "https://owasp.org/www-project-application-security-verification-standard/",
    "cat": "blue",
    "type": "framework",
    "desc": "AppSec requirements baseline",
    "details": "## Overview\nOWASP ASVS is a standard for application security verification requirements across levels.\n\n## Use cases\n- Define security requirements for new apps.\n- Build testing checklists for appsec reviews.\n\n## Alternatives\n- NIST SSDF\n- ISO 27034"
  },
  {
    "name": "OWASP Cheat Sheet Series",
    "url": "https://cheatsheetseries.owasp.org/",
    "cat": "blue",
    "type": "reference",
    "desc": "Secure coding guidance",
    "details": "## Overview\nPractical, concise secure coding guidance (auth, session, crypto, input validation, etc.).\n\n## Use cases\n- Link cheat sheets directly in code review templates and dev docs.\n\n## Alternatives\n- Mozilla Web Security Guidelines (archived but still referenced in places)\n- Vendor secure coding guides"
  },
  {
    "name": "NIST Secure Software Development Framework (SSDF)",
    "url": "https://csrc.nist.gov/Projects/ssdf",
    "cat": "blue",
    "type": "framework",
    "desc": "Secure SDLC practices",
    "details": "## Overview\nNIST SSDF is a set of practices for integrating security into software development and supply chains.\n\n## Alternatives\n- OWASP SAMM\n- BSIMM (commercial)"
  },
  {
    "name": "OWASP SAMM",
    "url": "https://owasp.org/www-project-samm/",
    "cat": "blue",
    "type": "framework",
    "desc": "Software Assurance Maturity Model",
    "details": "## Overview\nSAMM helps assess and improve software security practices across governance, design, implementation, verification, and operations.\n\n## Alternatives\n- BSIMM\n- NIST SSDF"
  },
  {
    "name": "Trivy",
    "url": "https://github.com/aquasecurity/trivy",
    "cat": "blue",
    "type": "tool",
    "desc": "Container and dependency vulnerability scanning",
    "details": "## Overview\nTrivy scans container images, filesystems, and repositories for vulnerabilities and misconfigurations.\n\n## Example (scan an image in CI)\n```bash\ntrivy image alpine:3.20\n```\n\n## Alternatives\n- Grype\n- Snyk (commercial)",
    "source": "https://github.com/aquasecurity/trivy"
  },
  {
    "name": "Grype",
    "url": "https://github.com/anchore/grype",
    "cat": "blue",
    "type": "tool",
    "desc": "Vulnerability scanner for containers and SBOMs",
    "details": "## Overview\nGrype scans container images and filesystems, and can consume SBOMs for dependency vulnerability checks.\n\n## Example\n```bash\ngrype alpine:3.20\n```\n\n## Alternatives\n- Trivy\n- Clair (server-based)",
    "source": "https://github.com/anchore/grype"
  },
  {
    "name": "Syft",
    "url": "https://github.com/anchore/syft",
    "cat": "blue",
    "type": "tool",
    "desc": "Generate SBOMs (Software Bill of Materials)",
    "details": "## Overview\nSyft generates SBOMs for container images and filesystems (SPDX/CycloneDX).\n\n## Example\n```bash\nsyft packages alpine:3.20 -o cyclonedx-json\n```\n\n## Alternatives\n- Trivy SBOM\n- SPDX tooling",
    "source": "https://github.com/anchore/syft"
  },
  {
    "name": "OWASP Dependency-Check",
    "url": "https://owasp.org/www-project-dependency-check/",
    "cat": "blue",
    "type": "tool",
    "desc": "Find vulnerable dependencies (SCA)",
    "details": "## Overview\nOWASP Dependency-Check identifies known vulnerable components by analyzing project dependencies.\n\n## Example (CI usage idea)\nRun in CI and fail builds when critical vulnerabilities are introduced, with exception process for false positives.\n\n## Alternatives\n- Snyk (commercial)\n- GitHub Dependabot"
  },
  {
    "name": "Falco",
    "url": "https://falco.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Runtime security detection for Linux/Kubernetes",
    "details": "## Overview\nFalco detects suspicious behavior at runtime using syscall events and rules.\n\n## Use cases\n- Detect container escape attempts, credential access, unusual process behavior.\n\n## Alternatives\n- Tetragon (eBPF)\n- Auditd rules (manual)"
  },
  {
    "name": "Open Policy Agent (OPA)",
    "url": "https://www.openpolicyagent.org/",
    "cat": "blue",
    "type": "framework",
    "desc": "Policy-as-code (Kubernetes, CI/CD, APIs)",
    "details": "## Overview\nOPA enables policy-as-code (Rego) for admission control and authorization decisions.\n\n## Use cases\n- Enforce Kubernetes/security guardrails consistently.\n\n## Alternatives\n- Kyverno (K8s-specific)\n- Terraform policy tools"
  },
  {
    "name": "Kyverno",
    "url": "https://kyverno.io/",
    "cat": "blue",
    "type": "tool",
    "desc": "Kubernetes policy management",
    "details": "## Overview\nKyverno manages Kubernetes policies (validation, mutation, generation) using YAML policies.\n\n## Alternatives\n- OPA/Gatekeeper\n- Native admission controllers"
  },
  {
    "name": "ELK Stack (Elastic)",
    "url": "https://www.elastic.co/elastic-stack",
    "cat": "blue",
    "type": "tool",
    "desc": "Search/analytics platform (logs, security)",
    "details": "## Overview\nElastic Stack (Elasticsearch, Kibana, Beats/Agent) is widely used for log ingestion, search and security analytics.\n\n## Notes\n- Plan indices and retention carefully; security data grows fast.\n\n## Alternatives\n- Splunk (commercial)\n- OpenSearch"
  },
  {
    "name": "OpenSearch",
    "url": "https://opensearch.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Open-source search and analytics",
    "details": "## Overview\nOpenSearch is an open-source search/analytics engine compatible with many Elasticsearch patterns.\n\n## Alternatives\n- Elastic Stack\n- Splunk"
  },
  {
    "name": "Microsoft Sentinel (KQL docs)",
    "url": "https://learn.microsoft.com/azure/sentinel/kusto-query-language",
    "cat": "blue",
    "type": "reference",
    "desc": "KQL for detections and hunting",
    "details": "## Overview\nKusto Query Language (KQL) is used in Microsoft Sentinel and other Microsoft security products for detections and hunts.\n\n## Example (conceptual)\nStart from a hypothesis (e.g., suspicious PowerShell) and iterate: baseline → anomaly → enrichment joins.\n\n## Alternatives\n- Splunk SPL\n- Elastic EQL/KQL"
  },
  {
    "name": "Splunk Security Essentials",
    "url": "https://splunksecurityessentials.com/",
    "cat": "blue",
    "type": "reference",
    "desc": "Use-case driven detection content",
    "details": "## Overview\nSplunk Security Essentials curates security use cases with guidance and searches to accelerate detections.\n\n## Alternatives\n- Elastic detection rules\n- Sigma community rules"
  },
  {
    "name": "Elastic Detection Rules",
    "url": "https://github.com/elastic/detection-rules",
    "cat": "blue",
    "type": "reference",
    "desc": "Detection rules for Elastic Security",
    "details": "## Overview\nElastic maintains a repository of detection rules that can be used in Elastic Security.\n\n## Notes\n- Use as reference even if you don't run Elastic; detections translate to other SIEMs.\n\n## Alternatives\n- Sigma rules\n- Splunk detections",
    "source": "https://github.com/elastic/detection-rules"
  },
  {
    "name": "OSINT (Blue) - VirusTotal",
    "url": "https://www.virustotal.com/",
    "cat": "blue",
    "type": "tool",
    "desc": "File/URL reputation and metadata",
    "details": "## Overview\nVirusTotal aggregates AV and analysis results for files, URLs, domains and IPs (useful for triage).\n\n## Defensive tips\n- Use it for enrichment, not as a sole source of truth.\n- Avoid uploading sensitive binaries unless policy permits.\n\n## Alternatives\n- Hybrid Analysis\n- Any.Run (sandbox)"
  },
  {
    "name": "urlscan.io",
    "url": "https://urlscan.io/",
    "cat": "blue",
    "type": "tool",
    "desc": "URL scanning and passive intel",
    "details": "## Overview\nurlscan.io crawls a URL and records requests, DOM, screenshots and indicators to support phishing triage.\n\n## Example (safe workflow)\nSubmit suspicious links in a controlled environment, then extract domains/requests for blocklists and detections.\n\n## Alternatives\n- VirusTotal URL\n- Browserless internal sandbox"
  },
  {
    "name": "AbuseIPDB",
    "url": "https://www.abuseipdb.com/",
    "cat": "blue",
    "type": "tool",
    "desc": "IP abuse reporting and reputation",
    "details": "## Overview\nCommunity-driven IP reputation useful for enrichment and blocklist inputs (validate before blocking).\n\n## Alternatives\n- Spamhaus (lists)\n- Vendor reputation feeds"
  },
  {
    "name": "AlienVault OTX",
    "url": "https://otx.alienvault.com/",
    "cat": "blue",
    "type": "tool",
    "desc": "Open threat intel pulses",
    "details": "## Overview\nOTX provides community “pulses” of indicators and contextual intel.\n\n## Notes\n- Treat community feeds as noisy; apply confidence thresholds and expiration.\n\n## Alternatives\n- MISP sharing communities\n- OpenCTI connectors"
  },
  {
    "name": "MalwareBazaar",
    "url": "https://bazaar.abuse.ch/",
    "cat": "blue",
    "type": "database",
    "desc": "Malware samples and metadata",
    "details": "## Overview\nabuse.ch MalwareBazaar provides malware sample metadata for research and detection engineering.\n\n## Notes\n- Handle samples safely (isolated VM).\n\n## Alternatives\n- VirusTotal (limited sample access)\n- MalShare (varies)"
  },
  {
    "name": "URLHaus",
    "url": "https://urlhaus.abuse.ch/",
    "cat": "blue",
    "type": "database",
    "desc": "Malicious URLs feed",
    "details": "## Overview\nURLHaus (abuse.ch) tracks malware distribution URLs and provides feeds.\n\n## Use cases\n- Enrich telemetry with known-bad URLs.\n- Build blocklists with expiration and validation.\n\n## Alternatives\n- PhishTank (phishing)\n- Vendor URL reputation"
  },
  {
    "name": "PhishTank",
    "url": "https://phishtank.org/",
    "cat": "blue",
    "type": "database",
    "desc": "Community phishing URL database",
    "details": "## Overview\nPhishTank collects and verifies phishing URLs for defensive use.\n\n## Notes\n- Use time-based expiration; phishing infrastructure changes quickly.\n\n## Alternatives\n- URLHaus\n- Vendor feeds"
  },
  {
    "name": "MITRE Engenuity ATT&CK Evaluations",
    "url": "https://attackevals.mitre-engenuity.org/",
    "cat": "blue",
    "type": "reference",
    "desc": "EDR/SIEM evaluation reports",
    "details": "## Overview\nATT&CK Evaluations provide vendor evaluation results mapped to ATT&CK techniques.\n\n## Use cases\n- Compare detection visibility across products (not a “winner list”).\n\n## Alternatives\n- Independent testing labs\n- Internal bake-offs"
  },
  {
    "name": "SANS Blue Team Resources",
    "url": "https://www.sans.org/blog/category/blue-team/",
    "cat": "blue",
    "type": "guide",
    "desc": "Blue-team blogs and guides",
    "details": "## Overview\nSANS publishes articles, guides, and training-related resources for defenders.\n\n## Alternatives\n- Microsoft security blogs\n- Vendor threat research (validate bias)"
  },
  {
    "name": "Microsoft Security Blog",
    "url": "https://www.microsoft.com/en-us/security/blog/",
    "cat": "blue",
    "type": "reference",
    "desc": "Threat research and guidance",
    "details": "## Overview\nMicrosoft publishes threat research, incident writeups and defensive guidance across products and ecosystems.\n\n## Alternatives\n- Google Cloud / Mandiant blogs\n- CrowdStrike blogs"
  },
  {
    "name": "Mandiant (Google Cloud) Threat Intelligence",
    "url": "https://www.mandiant.com/resources",
    "cat": "blue",
    "type": "reference",
    "desc": "Reports and threat research",
    "details": "## Overview\nMandiant publishes detailed threat reports and incident learnings useful for detection engineering.\n\n## Notes\n- Use reports to derive hypotheses; validate in your telemetry.\n\n## Alternatives\n- Unit 42 (Palo Alto Networks)\n- Talos (Cisco)"
  },
  {
    "name": "Awesome Incident Response",
    "url": "https://github.com/meirwah/awesome-incident-response",
    "cat": "blue",
    "type": "reference",
    "desc": "Curated IR tools and resources",
    "details": "## Overview\nA curated list of incident response tools, reading, and checklists to bootstrap an IR program.\n\n## Alternatives\n- Awesome DFIR\n- Vendor playbooks",
    "source": "https://github.com/meirwah/awesome-incident-response"
  },
  {
    "name": "Awesome Threat Detection",
    "url": "https://github.com/0x4D31/awesome-threat-detection",
    "cat": "blue",
    "type": "reference",
    "desc": "Collections of detections, rules and resources",
    "details": "## Overview\nCurated collection of threat detection and defense resources (rules, blogs, training).\n\n## Alternatives\n- Sigma rules\n- Elastic detection-rules",
    "source": "https://github.com/0x4D31/awesome-threat-detection"
  },
  {
    "name": "Awesome DFIR",
    "url": "https://github.com/cugu/awesome-forensics",
    "cat": "blue",
    "type": "reference",
    "desc": "DFIR and forensics resources",
    "details": "## Overview\nCurated set of forensic tools and references for DFIR practitioners.\n\n## Alternatives\n- SANS DFIR reading room\n- Vendor forensics tooling",
    "source": "https://github.com/cugu/awesome-forensics"
  },
  {
    "name": "Threat Hunting Project",
    "url": "https://github.com/OTRF/ThreatHunter-Playbook",
    "cat": "blue",
    "type": "guide",
    "desc": "Hunting playbooks and notebooks",
    "details": "## Overview\nThreat Hunter Playbook collects hunting methodologies and playbooks for common threats.\n\n## Notes\n- Treat playbooks as templates; tune to your environment and data sources.\n\n## Alternatives\n- ATT&CK-based hunting guides\n- Vendor hunt libraries",
    "source": "https://github.com/OTRF/ThreatHunter-Playbook"
  },
  {
    "name": "Windows Event Log Encyclopedia",
    "url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
    "cat": "blue",
    "type": "reference",
    "desc": "Event ID explanations and fields",
    "details": "## Overview\nReference for Windows security event IDs and their meaning (useful for detections and investigations).\n\n## Alternatives\n- Microsoft documentation\n- Community cheat sheets"
  },
  {
    "name": "Sysmon Event ID Reference",
    "url": "https://learn.microsoft.com/sysinternals/downloads/sysmon",
    "cat": "blue",
    "type": "reference",
    "desc": "Sysmon event semantics",
    "details": "## Overview\nDocumentation for Sysmon event IDs and field meanings; essential when building detections from Sysmon.\n\n## Alternatives\n- Community mappings to ATT&CK\n- Vendor EDR field docs"
  },
  {
    "name": "Microsoft Defender XDR documentation",
    "url": "https://learn.microsoft.com/microsoft-365/security/defender/",
    "cat": "blue",
    "type": "guide",
    "desc": "Defender XDR operational docs",
    "details": "## Overview\nOfficial documentation covering Defender telemetry, alerts, advanced hunting, and response capabilities.\n\n## Alternatives\n- Your SIEM vendor docs\n- Community KQL queries (validate)"
  },
  {
    "name": "CrowdSec",
    "url": "https://www.crowdsec.net/",
    "cat": "blue",
    "type": "tool",
    "desc": "Collaborative IPS/IDS (behavior-based)",
    "details": "## Overview\nCrowdSec detects malicious behaviors (e.g., brute force) and can feed decisions to firewalls and proxies.\n\n## Notes\n- Validate community scenarios; avoid false-positive blocking for critical services.\n\n## Alternatives\n- Fail2ban (simpler)\n- WAF/IPS appliances"
  },
  {
    "name": "Fail2ban",
    "url": "https://www.fail2ban.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Ban IPs based on log patterns",
    "details": "## Overview\nFail2ban monitors logs and applies firewall rules to block abusive IPs for services like SSH.\n\n## Example (concept)\nEnable an SSH jail, tune retry thresholds, and monitor ban effectiveness and false positives.\n\n## Alternatives\n- CrowdSec\n- Rate limiting at the reverse proxy/WAF"
  },
  {
    "name": "OpenVAS / Greenbone",
    "url": "https://www.greenbone.net/en/community-edition/",
    "cat": "blue",
    "type": "tool",
    "desc": "Vulnerability scanning platform",
    "details": "## Overview\nGreenbone Community Edition (OpenVAS) provides vulnerability scanning and reporting.\n\n## Notes\n- Scanners find issues; remediation requires asset ownership and patch workflows.\n\n## Alternatives\n- Nessus (commercial)\n- Nuclei (lightweight templates; validate)"
  },
  {
    "name": "Microsoft Threat Modeling Tool",
    "url": "https://learn.microsoft.com/azure/security/develop/threat-modeling-tool",
    "cat": "blue",
    "type": "tool",
    "desc": "Threat modeling with STRIDE",
    "details": "## Overview\nTool to build threat models using STRIDE and generate mitigation guidance for architectures.\n\n## Alternatives\n- OWASP Threat Dragon\n- IriusRisk (commercial)"
  },
  {
    "name": "OWASP Threat Dragon",
    "url": "https://owasp.org/www-project-threat-dragon/",
    "cat": "blue",
    "type": "tool",
    "desc": "Open-source threat modeling tool",
    "details": "## Overview\nThreat Dragon supports drawing diagrams and capturing threats/mitigations for software systems.\n\n## Alternatives\n- Microsoft Threat Modeling Tool\n- pyTM (code-based)"
  },
  {
    "name": "MITRE ATT&CK for ICS",
    "url": "https://attack.mitre.org/matrices/ics/",
    "cat": "blue",
    "type": "framework",
    "desc": "ICS-specific ATT&CK matrix",
    "details": "## Overview\nATT&CK for ICS provides techniques and tactics tailored to industrial control environments.\n\n## Notes\n- ICS telemetry and controls differ; map to process safety requirements.\n\n## Alternatives\n- IEC 62443 standards\n- Vendor-specific OT guidance"
  },
  {
    "name": "IEC 62443 Overview",
    "url": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
    "cat": "blue",
    "type": "framework",
    "desc": "Industrial security standards series",
    "details": "## Overview\nISA/IEC 62443 is a family of standards for securing industrial automation and control systems.\n\n## Alternatives\n- NIST 800-82 (ICS guidance)\n- Vendor OT security baselines"
  },
  {
    "name": "NIST SP 800-82 (ICS Security Guide)",
    "url": "https://csrc.nist.gov/publications/detail/sp/800-82/rev-2/final",
    "cat": "blue",
    "type": "guide",
    "desc": "ICS security guidance",
    "details": "## Overview\nNIST 800-82 provides guidance for securing industrial control systems including architectures and recommended controls.\n\n## Alternatives\n- IEC 62443 guidance\n- CISA OT advisories"
  },
  {
    "name": "Snort",
    "url": "https://www.snort.org/",
    "cat": "blue",
    "type": "tool",
    "desc": "Network IDS/IPS",
    "details": "## Overview\nSnort is a widely used IDS/IPS with a large ecosystem of rules and deployments.\n\n## Alternatives\n- Suricata (multi-threaded, modern protocol support)\n- Zeek (metadata/log-focused)"
  },
  {
    "name": "ClamAV",
    "url": "https://www.clamav.net/",
    "cat": "blue",
    "type": "tool",
    "desc": "Open-source antivirus engine",
    "details": "## Overview\nClamAV provides signature-based malware scanning. Useful as a baseline scanner and for mail gateways.\n\n## Alternatives\n- YARA (custom rules, more flexible)\n- Commercial endpoint AV/EDR"
  },
  {
    "name": "Loki (Simple IOC Scanner)",
    "url": "https://github.com/Neo23x0/Loki",
    "cat": "blue",
    "type": "tool",
    "desc": "IOC scanner for file systems",
    "details": "## Overview\nLoki scans filesystems for IOCs and suspicious patterns to support triage and incident response.\n\n## Example (local triage)\n```bash\npython3 loki.py -p /path/to/scan\n```\n\n## Alternatives\n- YARA scans\n- EDR sweeps",
    "source": "https://github.com/Neo23x0/Loki"
  },
  {
    "name": "YARA-Rules (community)",
    "url": "https://github.com/Yara-Rules/rules",
    "cat": "blue",
    "type": "reference",
    "desc": "Community YARA rules",
    "details": "## Overview\nLarge community ruleset for YARA. Use as a reference and validate against your environment to avoid false positives.\n\n## Alternatives\n- Internal YARA rules based on your threats\n- Vendor signatures",
    "source": "https://github.com/Yara-Rules/rules"
  },
  {
    "name": "Florian Roth signature-base",
    "url": "https://github.com/Neo23x0/signature-base",
    "cat": "blue",
    "type": "reference",
    "desc": "YARA/IOC signature collection",
    "details": "## Overview\nSignature-base aggregates multiple YARA rules and IOC lists for detection and triage.\n\n## Notes\n- Validate and curate; large rule sets can be noisy.\n\n## Alternatives\n- Focused internal rule packs\n- Sigma + endpoint telemetry (different layer)",
    "source": "https://github.com/Neo23x0/signature-base"
  },
  {
    "name": "Chainsaw",
    "url": "https://github.com/WithSecureLabs/chainsaw",
    "cat": "blue",
    "type": "tool",
    "desc": "Fast Windows EVTX hunting",
    "details": "## Overview\nChainsaw hunts Windows Event Logs (EVTX) using Sigma rules and other heuristics.\n\n## Example (offline log hunt)\n```bash\nchainsaw hunt evtx/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml\n```\n\n## Alternatives\n- Hayabusa (Sigma-based timeline)\n- SIEM ingestion + queries",
    "source": "https://github.com/WithSecureLabs/chainsaw"
  },
  {
    "name": "Hayabusa",
    "url": "https://github.com/Yamato-Security/hayabusa",
    "cat": "blue",
    "type": "tool",
    "desc": "Windows event log analysis (Sigma, timelines)",
    "details": "## Overview\nHayabusa parses Windows event logs and applies Sigma-style detections to generate timelines and findings.\n\n## Alternatives\n- Chainsaw\n- Elastic/Splunk offline ingestion",
    "source": "https://github.com/Yamato-Security/hayabusa"
  },
  {
    "name": "Sysinternals Suite",
    "url": "https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite",
    "cat": "blue",
    "type": "tool",
    "desc": "Windows diagnostic utilities bundle",
    "details": "## Overview\nSysinternals Suite contains tools like Autoruns, Procmon, Process Explorer—critical for Windows investigations and troubleshooting.\n\n## Alternatives\n- NirSoft utilities (use with care)\n- Built-in Windows tools (limited)"
  },
  {
    "name": "Autoruns",
    "url": "https://learn.microsoft.com/sysinternals/downloads/autoruns",
    "cat": "blue",
    "type": "tool",
    "desc": "Startup/persistence inspection (Windows)",
    "details": "## Overview\nAutoruns enumerates persistence points (run keys, services, scheduled tasks) to support IR triage.\n\n## Alternatives\n- Sysmon + hunting queries\n- Velociraptor collections"
  },
  {
    "name": "Procmon",
    "url": "https://learn.microsoft.com/sysinternals/downloads/procmon",
    "cat": "blue",
    "type": "tool",
    "desc": "Process and file/registry activity monitor",
    "details": "## Overview\nProcmon provides detailed real-time file, registry, and process/thread activity—useful for deep triage in a controlled setting.\n\n## Alternatives\n- ETW tracing\n- EDR process telemetry"
  },
  {
    "name": "YARAForge (rules writing resources)",
    "url": "https://yara.readthedocs.io/",
    "cat": "blue",
    "type": "guide",
    "desc": "YARA documentation and best practices",
    "details": "## Overview\nOfficial YARA docs plus best practices for rule structure, performance, and false-positive control.\n\n## Alternatives\n- Community rule repos\n- Vendor signatures"
  },
  {
    "name": "OpenIOC",
    "url": "https://www.openioc.org/",
    "cat": "blue",
    "type": "reference",
    "desc": "IOC sharing format",
    "details": "## Overview\nOpenIOC is an indicator format historically used for sharing structured IOCs (many orgs also use STIX).\n\n## Alternatives\n- STIX2\n- Sigma (for log detections)"
  },
  {
    "name": "STIX/TAXII (OASIS)",
    "url": "https://oasis-open.github.io/cti-documentation/",
    "cat": "blue",
    "type": "framework",
    "desc": "Threat intel standards",
    "details": "## Overview\nSTIX and TAXII provide standardized structures and transport for threat intelligence sharing.\n\n## Alternatives\n- MISP formats\n- Proprietary TI feeds"
  },
  {
    "name": "OpenDXL / OpenDXL Broker (legacy)",
    "url": "https://www.opendxl.com/",
    "cat": "blue",
    "type": "framework",
    "desc": "Security messaging bus (historical)",
    "details": "## Overview\nOpenDXL is a messaging fabric concept used for security orchestration in some environments (legacy but still seen).\n\n## Alternatives\n- SOAR platforms\n- Event streaming (Kafka) + integrations"
  }
];
