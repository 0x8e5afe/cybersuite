window.CYBER_RESOURCES_PURPLE = [
  {
    "name": "CVSS v3 Calculator (NVD)",
    "url": "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator",
    "cat": "purple",
    "type": "calculator",
    "desc": "Official CVSS v3 scoring",
    "details": "## Overview\nOfficial calculator for CVSS v3 base metrics to score vulnerability severity.\n\n## Practical tip\nRecord the rationale for each metric choice so scores are reproducible and explainable.\n\n## Alternatives\n- CVSS v4 calculators (if you score v4)\n- Vendor scoring (often differs)"
  },
  {
    "name": "FIRST EPSS",
    "url": "https://www.first.org/epss/",
    "cat": "purple",
    "type": "calculator",
    "desc": "Exploit probability scoring",
    "details": "## Overview\nEPSS estimates exploitation probability; useful to prioritize triage and patching.\n\n## How purple teams use it\nCombine EPSS + asset criticality + exposure to choose what to emulate/test first.\n\n## Alternatives\n- CISA KEV (known exploited list)\n- Internal threat intel"
  },
  {
    "name": "MITRE ATT&CK Navigator",
    "url": "https://mitre-attack.github.io/attack-navigator/",
    "cat": "purple",
    "type": "tool",
    "desc": "Plan and visualize coverage",
    "details": "## Overview\nBuild ATT&CK heatmaps for emulation plans, detection coverage, and hunt priorities.\n\n## Example workflow\nCreate a layer for a planned exercise: pick techniques → assign expected telemetry → track outcomes.\n\n## Alternatives\n- ATT&CK Workbench\n- Custom matrix tools"
  },
  {
    "name": "Atomic Red Team",
    "url": "https://github.com/redcanaryco/atomic-red-team",
    "cat": "purple",
    "type": "tool",
    "desc": "Portable ATT&CK-mapped tests",
    "details": "## Overview\nAtomic Red Team is a library of small tests mapped to ATT&CK techniques, designed to produce repeatable telemetry for defenders.\n\n## Typical workflow\nSelect a technique, run the associated atomic test in a controlled environment, then validate that logs/alerts and response playbooks behave as expected.\n\n## Notes\n- Run first in a lab or staging environment.\n- Document prerequisites and cleanup steps for each test.\n\n## Alternatives\n- Caldera (campaign-style emulation)\n- Infection Monkey (lateral movement simulation)",
    "source": "https://github.com/redcanaryco/atomic-red-team"
  },
  {
    "name": "Invoke-AtomicRedTeam",
    "url": "https://github.com/redcanaryco/invoke-atomicredteam",
    "cat": "purple",
    "type": "tool",
    "desc": "Run Atomic tests (PowerShell)",
    "details": "## Overview\nPowerShell module to execute Atomic Red Team tests and manage prerequisites and cleanup on Windows.\n\n## Example (conceptual)\nInstall the module, select a technique (T####), run a test, then review Defender/SIEM telemetry to confirm detection and response steps.\n\n## Alternatives\n- Manual execution of atomic test steps\n- Caldera operations",
    "source": "https://github.com/redcanaryco/invoke-atomicredteam"
  },
  {
    "name": "MITRE Caldera",
    "url": "https://github.com/mitre/caldera",
    "cat": "purple",
    "type": "tool",
    "desc": "Adversary emulation platform",
    "details": "## Overview\nCaldera runs ATT&CK-aligned operations to validate detection and response in controlled environments.\n\n## Purple team workflow\nDefine an objective (e.g., credential access), run an operation, then measure: telemetry quality, alert fidelity, and response time.\n\n## Alternatives\n- Atomic Red Team (unit tests)\n- Commercial BAS tools",
    "source": "https://github.com/mitre/caldera"
  },
  {
    "name": "Infection Monkey",
    "url": "https://github.com/guardicore/monkey",
    "cat": "purple",
    "type": "tool",
    "desc": "Breach and attack simulation",
    "details": "## Overview\nInfection Monkey simulates lateral movement and common techniques to help validate segmentation and detection in lab/authorized environments.\n\n## Alternatives\n- Caldera\n- Atomic Red Team",
    "source": "https://github.com/guardicore/monkey"
  },
  {
    "name": "PurpleSharp",
    "url": "https://github.com/mvelazc0/PurpleSharp",
    "cat": "purple",
    "type": "tool",
    "desc": "ATT&CK simulation tool (Windows)",
    "details": "## Overview\nPurpleSharp simulates multiple ATT&CK techniques to generate telemetry for detection validation in authorized environments.\n\n## Notes\n- Run with change control; confirm cleanup and endpoint stability.\n\n## Alternatives\n- Atomic Red Team\n- Caldera",
    "source": "https://github.com/mvelazc0/PurpleSharp"
  },
  {
    "name": "DetectionLab",
    "url": "https://github.com/clong/DetectionLab",
    "cat": "purple",
    "type": "training",
    "desc": "Lab environment for detections (AD + logging)",
    "details": "## Overview\nDetectionLab provisions a Windows domain lab with common logging tools to practice detection engineering and purple teaming.\n\n## How to use it\nReproduce attacker behaviors in the lab, then build and validate detections in your chosen SIEM.\n\n## Alternatives\n- Security Onion lab for network-focused telemetry\n- Custom IaC lab builds",
    "source": "https://github.com/clong/DetectionLab"
  },
  {
    "name": "MITRE ATT&CK Evaluations",
    "url": "https://attackevals.mitre-engenuity.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Vendor evaluation results mapped to ATT&CK",
    "details": "## Overview\nEvaluation reports help you understand product visibility across techniques and what telemetry is available.\n\n## Purple team use\nTurn evaluation gaps into test plans and telemetry requirements.\n\n## Alternatives\n- Internal bake-offs\n- Independent testing labs"
  },
  {
    "name": "Sigma Rules",
    "url": "https://github.com/SigmaHQ/sigma",
    "cat": "purple",
    "type": "reference",
    "desc": "Portable detection rules",
    "details": "## Overview\nSigma rules can be used as detection hypotheses. Purple teams validate rule quality by running controlled tests and tuning.\n\n## Alternatives\n- Elastic detection rules\n- Vendor detection libraries",
    "source": "https://github.com/SigmaHQ/sigma"
  },
  {
    "name": "Elastic detection-rules",
    "url": "https://github.com/elastic/detection-rules",
    "cat": "purple",
    "type": "reference",
    "desc": "Detection engineering reference",
    "details": "## Overview\nRepository of detection rules that can be adapted as references for other SIEMs.\n\n## Alternatives\n- Sigma rules\n- Splunk Security Essentials",
    "source": "https://github.com/elastic/detection-rules"
  },
  {
    "name": "Splunk Security Essentials",
    "url": "https://splunksecurityessentials.com/",
    "cat": "purple",
    "type": "reference",
    "desc": "Use cases + searches for detections",
    "details": "## Overview\nUse-case oriented detection content; purple teams can map use cases to ATT&CK and validate coverage with tests.\n\n## Alternatives\n- Sigma\n- Vendor detection packs"
  },
  {
    "name": "ATT&CK Workbench",
    "url": "https://github.com/mitre-attack/attack-workbench-frontend",
    "cat": "purple",
    "type": "tool",
    "desc": "Local ATT&CK knowledge base management",
    "details": "## Overview\nWorkbench allows managing ATT&CK data locally; useful for custom technique notes, internal mappings, and offline environments.\n\n## Alternatives\n- Navigator (visual focus)\n- Direct STIX ingestion pipelines",
    "source": "https://github.com/mitre-attack/attack-workbench-frontend"
  },
  {
    "name": "ATT&CK STIX Data",
    "url": "https://github.com/mitre/cti",
    "cat": "purple",
    "type": "database",
    "desc": "ATT&CK data in STIX/TAXII form",
    "details": "## Overview\nMITRE provides ATT&CK content in STIX format for programmatic ingestion.\n\n## Use cases\n- Build internal knowledge graphs and mappings.\n- Automate coverage reporting from detections to techniques.\n\n## Alternatives\n- Navigator exports (manual)\n- Commercial ATT&CK mapping tools",
    "source": "https://github.com/mitre/cti"
  },
  {
    "name": "DeTT&CT",
    "url": "https://github.com/rabobank-cdc/DeTTECT",
    "cat": "purple",
    "type": "tool",
    "desc": "ATT&CK-based detection maturity assessment",
    "details": "## Overview\nDeTT&CT helps assess detection and data source coverage mapped to ATT&CK and supports planning improvements.\n\n## Purple use\nUse it to plan which telemetry to collect and which detections to prioritize before running emulations.\n\n## Alternatives\n- Navigator layers\n- Custom coverage scoring",
    "source": "https://github.com/rabobank-cdc/DeTTECT"
  },
  {
    "name": "Purple Team Exercise Framework (concept)",
    "url": "https://www.sans.org/blog/purple-team-exercises/",
    "cat": "purple",
    "type": "guide",
    "desc": "Guidance on purple teaming",
    "details": "## Overview\nArticles and guidance on running purple team exercises focusing on measurable improvements.\n\n## Alternatives\n- ATT&CK-based emulation plans\n- Atomic Red Team + documented outcomes"
  },
  {
    "name": "OpenBAS",
    "url": "https://github.com/OpenBAS-Platform/openbas",
    "cat": "purple",
    "type": "tool",
    "desc": "Open Breach and Attack Simulation platform",
    "details": "## Overview\nOpenBAS provides BAS capabilities to run simulations and measure defensive controls. Use in authorized environments.\n\n## Alternatives\n- Caldera\n- Infection Monkey",
    "source": "https://github.com/OpenBAS-Platform/openbas"
  },
  {
    "name": "AtomicTestHarnesses",
    "url": "https://github.com/redcanaryco/AtomicTestHarnesses",
    "cat": "purple",
    "type": "reference",
    "desc": "Harnesses for running Atomic tests",
    "details": "## Overview\nSupplemental harnesses and helpers to execute Atomic tests more consistently across environments.\n\n## Alternatives\n- Invoke-AtomicRedTeam\n- Custom orchestration scripts",
    "source": "https://github.com/redcanaryco/AtomicTestHarnesses"
  },
  {
    "name": "MITRE Engenuity Center for Threat-Informed Defense",
    "url": "https://ctid.mitre-engenuity.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Threat-informed defense projects",
    "details": "## Overview\nProjects and guidance to operationalize threat-informed defense and measure outcomes.\n\n## Alternatives\n- ATT&CK resources\n- Vendor guidance (validate)"
  },
  {
    "name": "Compass Security - Detection Engineering Resources (generic)",
    "url": "https://github.com/OTRF",
    "cat": "purple",
    "type": "reference",
    "desc": "OTRF org: hunting & detection research",
    "details": "## Overview\nOSSEM, Helk, and other projects from the Open Threat Research Forge (OTRF) support detection engineering and hunting.\n\n## Alternatives\n- Sigma community\n- Vendor detection packs"
  },
  {
    "name": "OSSEM",
    "url": "https://github.com/OTRF/OSSEM",
    "cat": "purple",
    "type": "framework",
    "desc": "Open Source Security Events Metadata (logging schemas)",
    "details": "## Overview\nOSSEM provides guidance and schemas for security logging and event normalization.\n\n## Purple use\nAlign telemetry fields across sources so detections are portable and comparable.\n\n## Alternatives\n- ECS (Elastic Common Schema)\n- Splunk CIM",
    "source": "https://github.com/OTRF/OSSEM"
  },
  {
    "name": "Elastic Common Schema (ECS)",
    "url": "https://www.elastic.co/guide/en/ecs/current/ecs-reference.html",
    "cat": "purple",
    "type": "framework",
    "desc": "Common field schema for events",
    "details": "## Overview\nECS is a field naming and typing schema for event data; improves portability of detections and dashboards.\n\n## Alternatives\n- OSSEM\n- Splunk CIM"
  },
  {
    "name": "Splunk Common Information Model (CIM)",
    "url": "https://docs.splunk.com/Documentation/CIM/latest/User/Overview",
    "cat": "purple",
    "type": "framework",
    "desc": "Data model for normalized security data",
    "details": "## Overview\nSplunk CIM defines normalized data models for security events. Useful even if you’re not on Splunk as a reference for field design.\n\n## Alternatives\n- ECS\n- OSSEM"
  },
  {
    "name": "RITA",
    "url": "https://github.com/activecm/rita",
    "cat": "purple",
    "type": "tool",
    "desc": "Network beaconing detection",
    "details": "## Overview\nRITA analyzes network logs to identify beacons and suspicious communications; helpful for validating detections against simulated C2.\n\n## Alternatives\n- Zeek scripts + custom analytics\n- SIEM behavioral detections",
    "source": "https://github.com/activecm/rita"
  },
  {
    "name": "Sysmon",
    "url": "https://learn.microsoft.com/sysinternals/downloads/sysmon",
    "cat": "purple",
    "type": "tool",
    "desc": "High-fidelity Windows telemetry",
    "details": "## Overview\nSysmon provides detailed Windows events; purple teams rely on it to validate that simulations generate expected telemetry.\n\n## Alternatives\n- Windows Security Auditing\n- EDR telemetry"
  },
  {
    "name": "Velociraptor",
    "url": "https://docs.velociraptor.app/",
    "cat": "purple",
    "type": "tool",
    "desc": "Endpoint hunting and collections",
    "details": "## Overview\nUse Velociraptor to hunt for artifacts created during simulations and to validate response steps at scale.\n\n## Alternatives\n- osquery + Fleet\n- GRR",
    "source": "https://github.com/Velocidex/velociraptor"
  },
  {
    "name": "Timesketch",
    "url": "https://github.com/google/timesketch",
    "cat": "purple",
    "type": "tool",
    "desc": "Timeline analysis and collaboration",
    "details": "## Overview\nTimesketch helps analyze event timelines. Purple teams can use it to compare “expected” vs “observed” activity during exercises.\n\n## Alternatives\n- Plaso directly\n- SIEM timelines",
    "source": "https://github.com/google/timesketch"
  },
  {
    "name": "Plaso (log2timeline)",
    "url": "https://github.com/log2timeline/plaso",
    "cat": "purple",
    "type": "tool",
    "desc": "Super timeline generation",
    "details": "## Overview\nPlaso builds forensic timelines from diverse artifacts; useful for post-exercise analysis.\n\n## Alternatives\n- Velociraptor collections\n- Commercial DFIR suites",
    "source": "https://github.com/log2timeline/plaso"
  },
  {
    "name": "Prelude Operator (community)",
    "url": "https://github.com/Prelude-SIEM/Operator",
    "cat": "purple",
    "type": "tool",
    "desc": "ATT&CK automation and simulation",
    "details": "## Overview\nPrelude Operator helps run ATT&CK-aligned actions to validate detections and response in controlled environments.\n\n## Alternatives\n- Caldera\n- Atomic Red Team",
    "source": "https://github.com/Prelude-SIEM/Operator"
  },
  {
    "name": "VECTR",
    "url": "https://github.com/SecurityRiskAdvisors/VECTR",
    "cat": "purple",
    "type": "tool",
    "desc": "Purple team metrics & tracking platform",
    "details": "## Overview\nVECTR is a tool to plan and track adversary emulation, detection validation results, and improvements over time.\n\n## Purple workflow\nModel an exercise, record which steps were detected, where response failed, and assign remediation actions.\n\n## Alternatives\n- Spreadsheets (lighter)\n- Commercial BAS platforms",
    "source": "https://github.com/SecurityRiskAdvisors/VECTR"
  },
  {
    "name": "Splunk Attack Range",
    "url": "https://github.com/splunk/attack_range",
    "cat": "purple",
    "type": "training",
    "desc": "Build labs + simulate attacks for detections",
    "details": "## Overview\nAttack Range provisions a lab environment and automates simulation of attack behaviors to validate detections (especially in Splunk).\n\n## Alternatives\n- DetectionLab\n- Caldera + custom lab",
    "source": "https://github.com/splunk/attack_range"
  },
  {
    "name": "Stratus Red Team",
    "url": "https://github.com/DataDog/stratus-red-team",
    "cat": "purple",
    "type": "tool",
    "desc": "Cloud attack emulation (AWS/Azure/GCP)",
    "details": "## Overview\nStratus Red Team emulates cloud attack techniques in controlled environments to validate cloud detections and guardrails.\n\n## Notes\n- Always use dedicated test accounts/projects; cloud actions can have cost and risk implications.\n\n## Alternatives\n- Caldera cloud plugins (if used)\n- Cloud provider simulation tools",
    "source": "https://github.com/DataDog/stratus-red-team"
  },
  {
    "name": "AWS CloudTrail Lake / Athena hunting patterns (docs)",
    "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html",
    "cat": "purple",
    "type": "reference",
    "desc": "Cloud hunting data sources",
    "details": "## Overview\nCloudTrail provides audit logs; purple teams validate that simulated cloud actions appear in audit trails and SIEM pipelines.\n\n## Alternatives\n- Azure Activity Logs\n- GCP Cloud Audit Logs"
  },
  {
    "name": "Azure Sentinel KQL hunting guidance",
    "url": "https://learn.microsoft.com/azure/sentinel/hunt-with-kql",
    "cat": "purple",
    "type": "guide",
    "desc": "KQL hunting workflows",
    "details": "## Overview\nGuidance for using KQL to hunt and validate detections in Microsoft Sentinel.\n\n## Alternatives\n- Kusto Detective Agency (practice)\n- Vendor-specific query guides"
  },
  {
    "name": "Kusto Detective Agency",
    "url": "https://detective.kusto.io/",
    "cat": "purple",
    "type": "training",
    "desc": "Hands-on KQL learning",
    "details": "## Overview\nKusto Detective Agency teaches KQL with interactive cases. Useful for building hunting and purple-team analysis skills.\n\n## Alternatives\n- Microsoft Learn KQL modules\n- Internal query playbooks"
  },
  {
    "name": "MITRE D3FEND",
    "url": "https://d3fend.mitre.org/",
    "cat": "purple",
    "type": "framework",
    "desc": "Defensive countermeasures mapping",
    "details": "## Overview\nMap technique simulations to defensive countermeasures to ensure exercises drive concrete improvements.\n\n## Alternatives\n- CIS Controls\n- NIST 800-53 control families"
  },
  {
    "name": "CISA KEV",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "cat": "purple",
    "type": "database",
    "desc": "Known exploited vulnerability list",
    "details": "## Overview\nUse KEV to choose which vulnerabilities/behaviors to emulate and which patch SLAs to validate.\n\n## Alternatives\n- EPSS\n- Vendor exploitation telemetry"
  },
  {
    "name": "ATT&CK-Based Emulation Plans (community)",
    "url": "https://github.com/center-for-threat-informed-defense/adversary_emulation_library",
    "cat": "purple",
    "type": "reference",
    "desc": "Emulation plans and resources",
    "details": "## Overview\nCommunity library of adversary emulation plans that can be adapted for purple team exercises.\n\n## Notes\n- Adapt steps to your environment and ensure safe execution paths in lab/staging.\n\n## Alternatives\n- Caldera campaigns\n- Custom internal emulation plans",
    "source": "https://github.com/center-for-threat-informed-defense/adversary_emulation_library"
  },
  {
    "name": "Detection Engineering notes (Sigma workshop)",
    "url": "https://github.com/SigmaHQ/sigma-workshop",
    "cat": "purple",
    "type": "training",
    "desc": "Write and convert Sigma rules",
    "details": "## Overview\nMaterials for learning how to write Sigma rules and convert them into backend queries.\n\n## Alternatives\n- Vendor detection training\n- Community detection blogs",
    "source": "https://github.com/SigmaHQ/sigma-workshop"
  },
  {
    "name": "pySigma",
    "url": "https://github.com/SigmaHQ/pySigma",
    "cat": "purple",
    "type": "tool",
    "desc": "Sigma rule processing library",
    "details": "## Overview\npySigma parses and transforms Sigma rules and supports backend conversions through plugins.\n\n## Purple use\nAutomate: rule linting → conversion → test execution → report on hits and false positives.\n\n## Alternatives\n- sigmac (legacy)\n- Uncoder.io (UI)",
    "source": "https://github.com/SigmaHQ/pySigma"
  },
  {
    "name": "Uncoder.io",
    "url": "https://uncoder.io/",
    "cat": "purple",
    "type": "tool",
    "desc": "Sigma rule translation UI",
    "details": "## Overview\nUncoder.io helps translate Sigma rules to multiple query languages (use as a helper; always validate semantics).\n\n## Alternatives\n- pySigma toolchain\n- Vendor converters"
  },
  {
    "name": "Splunk Attack Data (dataset)",
    "url": "https://github.com/splunk/attack_data",
    "cat": "purple",
    "type": "database",
    "desc": "Datasets mapped to ATT&CK",
    "details": "## Overview\nAttack Data provides telemetry datasets mapped to ATT&CK, useful for validating detection logic and pipelines.\n\n## Alternatives\n- Mordor datasets (OTRF)\n- Your lab-generated logs",
    "source": "https://github.com/splunk/attack_data"
  },
  {
    "name": "Mordor (OTRF) datasets",
    "url": "https://github.com/OTRF/mordor",
    "cat": "purple",
    "type": "database",
    "desc": "Attack simulation datasets",
    "details": "## Overview\nMordor provides datasets of adversary simulations with telemetry to develop and test detections.\n\n## Alternatives\n- Splunk attack_data\n- Internal lab datasets",
    "source": "https://github.com/OTRF/mordor"
  }
];
