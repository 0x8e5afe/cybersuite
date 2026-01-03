window.CYBER_RESOURCES_PURPLE = window.CYBER_RESOURCES_PURPLE || [];
window.CYBER_RESOURCES_PURPLE.push(
  {
    "name": "MITRE ATT&CK Navigator",
    "url": "https://mitre-attack.github.io/attack-navigator/",
    "website": "https://github.com/mitre-attack/attack-navigator",
    "source": "https://github.com/mitre-attack/attack-navigator",
    "binaries": "https://github.com/mitre-attack/attack-navigator/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Plan and visualize coverage",
    "details": "## Overview\nBuild ATT&CK heatmaps for emulation plans, detection coverage, and hunt priorities.\n\n## Example workflow\nCreate a layer for a planned exercise: pick techniques → assign expected telemetry → track outcomes.\n\n## Alternatives\n- ATT&CK Workbench\n- Custom matrix tools"
  },
  {
    "name": "Atomic Red Team",
    "url": "https://atomicredteam.io/",
    "website": "https://atomicredteam.io/",
    "source": "https://github.com/redcanaryco/atomic-red-team",
    "binaries": null,
    "cat": "purple",
    "type": "tool",
    "desc": "Portable ATT&CK-mapped tests",
    "details": "## Overview\nAtomic Red Team is a library of small tests mapped to ATT&CK techniques, designed to produce repeatable telemetry for defenders.\n\n## Typical workflow\nSelect a technique, run the associated atomic test in a controlled environment, then validate that logs/alerts and response playbooks behave as expected.\n\n## Notes\n- Run first in a lab or staging environment.\n- Document prerequisites and cleanup steps for each test.\n\n## Alternatives\n- Caldera (campaign-style emulation)\n- Infection Monkey (lateral movement simulation)"
  },
  {
    "name": "Invoke-AtomicRedTeam",
    "url": "https://github.com/redcanaryco/invoke-atomicredteam",
    "website": "https://atomicredteam.io/invoke-atomicredteam/",
    "source": "https://github.com/redcanaryco/invoke-atomicredteam",
    "binaries": "https://github.com/redcanaryco/invoke-atomicredteam/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Run Atomic tests (PowerShell)",
    "details": "## Overview\nPowerShell module to execute Atomic Red Team tests and manage prerequisites and cleanup on Windows.\n\n## Example (conceptual)\nInstall the module, select a technique (T####), run a test, then review Defender/SIEM telemetry to confirm detection and response steps.\n\n## Alternatives\n- Manual execution of atomic test steps\n- Caldera operations"
  },
  {
    "name": "MITRE Caldera",
    "url": "https://caldera.mitre.org/",
    "website": "https://caldera.mitre.org/",
    "source": "https://github.com/mitre/caldera",
    "binaries": "https://github.com/mitre/caldera/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Adversary emulation platform",
    "details": "## Overview\nCaldera runs ATT&CK-aligned operations to validate detection and response in controlled environments. \n\n## Purple team workflow\nDefine an objective (e.g., credential access), run an operation, then measure: telemetry quality, alert fidelity, and response time.\n\n## Alternatives\n- Atomic Red Team (unit tests)\n- Commercial BAS tools"
  },
  {
    "name": "Infection Monkey",
    "url": "https://www.akamai.com/infectionmonkey",
    "website": "https://www.akamai.com/infectionmonkey",
    "source": "https://github.com/guardicore/monkey",
    "binaries": "https://github.com/guardicore/monkey/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Breach and attack simulation",
    "details": "## Overview\nInfection Monkey simulates lateral movement and common techniques to help validate segmentation and detection in lab/authorized environments.\n\n## Alternatives\n- Caldera\n- Atomic Red Team"
  },
  {
    "name": "PurpleSharp",
    "url": "https://www.purplesharp.com/",
    "website": "https://www.purplesharp.com/",
    "source": "https://github.com/mvelazc0/PurpleSharp",
    "binaries": "https://github.com/mvelazc0/PurpleSharp/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "ATT&CK simulation tool (Windows)",
    "details": "## Overview\nPurpleSharp simulates multiple ATT&CK techniques to generate telemetry for detection validation in authorized environments.\n\n## Notes\n- Run with change control; confirm cleanup and endpoint stability.\n\n## Alternatives\n- Atomic Red Team\n- Caldera"
  },
  {
    "name": "ATT&CK Workbench",
    "url": "https://github.com/mitre-attack/attack-workbench-frontend",
    "website": "https://mitre-attack.github.io/attack-workbench-frontend/",
    "source": "https://github.com/mitre-attack/attack-workbench-frontend",
    "binaries": "https://github.com/mitre-attack/attack-workbench-frontend/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Local ATT&CK knowledge base management",
    "details": "## Overview\nWorkbench allows managing ATT&CK data locally; useful for custom technique notes, internal mappings, and offline environments.\n\n## Alternatives\n- Navigator (visual focus)\n- Direct STIX ingestion pipelines"
  },
  {
    "name": "DeTT&CT",
    "url": "https://rabobank-cdc.github.io/DeTTECT/",
    "website": "https://rabobank-cdc.github.io/DeTTECT/",
    "source": "https://github.com/rabobank-cdc/DeTTECT",
    "binaries": "https://github.com/rabobank-cdc/DeTTECT/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "ATT&CK-based detection maturity assessment",
    "details": "## Overview\nDeTT&CT helps assess detection and data source coverage mapped to ATT&CK and supports planning improvements.\n\n## Purple use\nUse it to plan which telemetry to collect and which detections to prioritize before running emulations.\n\n## Alternatives\n- Navigator layers\n- Custom coverage scoring"
  },
  {
    "name": "OpenBAS",
    "url": "https://openbas.io/",
    "website": "https://openbas.io/",
    "source": "https://github.com/OpenBAS-Platform/openbas",
    "binaries": "https://github.com/OpenBAS-Platform/openbas/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Open Breach and Attack Simulation platform",
    "details": "## Overview\nOpenBAS provides BAS capabilities to run simulations and measure defensive controls. Use in authorized environments. \n\n## Alternatives\n- Caldera\n- Infection Monkey"
  },
  {
    "name": "RITA",
    "url": "https://www.activecountermeasures.com/free-tools/rita/",
    "website": "https://www.activecountermeasures.com/free-tools/rita/",
    "source": "https://github.com/activecm/rita",
    "binaries": "https://github.com/activecm/rita/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Network beaconing detection",
    "details": "## Overview\nRITA analyzes network logs to identify beacons and suspicious communications; helpful for validating detections against simulated C2.\n\n## Alternatives\n- Zeek scripts + custom analytics\n- SIEM behavioral detections"
  },
  {
    "name": "Sysmon",
    "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "website": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "source": null,
    "binaries": "https://download.sysinternals.com/files/Sysmon.zip",
    "cat": "purple",
    "type": "tool",
    "desc": "High-fidelity Windows telemetry",
    "details": "## Overview\nSysmon provides detailed Windows events; purple teams rely on it to validate that simulations generate expected telemetry.\n\n## Alternatives\n- Windows Security Auditing\n- EDR telemetry"
  },
  {
    "name": "Velociraptor",
    "url": "https://docs.velociraptor.app/",
    "website": "https://velociraptor.app/",
    "source": "https://github.com/Velocidex/velociraptor",
    "binaries": "https://github.com/Velocidex/velociraptor/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Endpoint hunting and collections",
    "details": "## Overview\nUse Velociraptor to hunt for artifacts created during simulations and to validate response steps at scale.\n\n## Alternatives\n- osquery + Fleet\n- GRR"
  },
  {
    "name": "Timesketch",
    "url": "https://timesketch.org/",
    "website": "https://timesketch.org/",
    "source": "https://github.com/google/timesketch",
    "binaries": "https://github.com/google/timesketch/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Timeline analysis and collaboration",
    "details": "## Overview\nTimesketch helps analyze event timelines. Purple teams can use it to compare “expected” vs “observed” activity during exercises.\n\n## Alternatives\n- Plaso directly\n- SIEM timelines"
  },
  {
    "name": "Plaso (log2timeline)",
    "url": "https://plaso.readthedocs.io/en/latest/",
    "website": "https://plaso.readthedocs.io/",
    "source": "https://github.com/log2timeline/plaso",
    "binaries": "https://github.com/log2timeline/plaso/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Super timeline generation",
    "details": "## Overview\nPlaso builds forensic timelines from diverse artifacts; useful for post-exercise analysis.\n\n## Alternatives\n- Velociraptor collections\n- Commercial DFIR suites"
  },
  {
    "name": "Prelude Operator (community)",
    "url": "https://www.preludesecurity.com/products/operator",
    "website": "https://www.preludesecurity.com/",
    "source": "https://github.com/Prelude-SIEM/Operator",
    "binaries": "https://github.com/Prelude-SIEM/Operator/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "ATT&CK automation and simulation",
    "details": "## Overview\nPrelude Operator helps run ATT&CK-aligned actions to validate detections and response in controlled environments.\n\n## Alternatives\n- Caldera\n- Atomic Red Team"
  },
  {
    "name": "VECTR",
    "url": "https://docs.vectr.io/",
    "website": "https://vectr.io/",
    "source": "https://github.com/SecurityRiskAdvisors/VECTR",
    "binaries": "https://github.com/SecurityRiskAdvisors/VECTR/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Purple team metrics & tracking platform",
    "details": "## Overview\nVECTR is a tool to plan and track adversary emulation, detection validation results, and improvements over time. \n\n## Purple workflow\nModel an exercise, record which steps were detected, where response failed, and assign remediation actions.\n\n## Alternatives\n- Spreadsheets (lighter)\n- Commercial BAS platforms"
  },
  {
    "name": "Stratus Red Team",
    "url": "https://stratus-red-team.cloud/",
    "website": "https://stratus-red-team.cloud/",
    "source": "https://github.com/DataDog/stratus-red-team",
    "binaries": "https://github.com/DataDog/stratus-red-team/releases",
    "cat": "purple",
    "type": "tool",
    "desc": "Cloud attack emulation (AWS/Azure/GCP)",
    "details": "## Overview\nStratus Red Team emulates cloud attack techniques in controlled environments to validate cloud detections and guardrails.\n\n## Notes\n- Always use dedicated test accounts/projects; cloud actions can have cost and risk implications.\n\n## Alternatives\n- Caldera cloud plugins (if used)\n- Cloud provider simulation tools"
  },
  {
    "name": "pySigma",
    "url": "https://sigmahq-pysigma.readthedocs.io/",
    "website": "https://sigmahq.io/",
    "source": "https://github.com/SigmaHQ/pySigma",
    "binaries": null,
    "cat": "purple",
    "type": "tool",
    "desc": "Sigma rule processing library",
    "details": "## Overview\npySigma parses and transforms Sigma rules and supports backend conversions through plugins.\n\n## Purple use\nAutomate: rule linting → conversion → test execution → report on hits and false positives.\n\n## Alternatives\n- sigmac (legacy)\n- Uncoder.io (UI)"
  },
  {
    "name": "Uncoder.io",
    "url": "https://uncoder.io/",
    "website": "https://uncoder.io/",
    "source": null,
    "binaries": null,
    "cat": "purple",
    "type": "tool",
    "desc": "Sigma rule translation UI",
    "details": "## Overview\nUncoder.io helps translate Sigma rules to multiple query languages (use as a helper; always validate semantics).\n\n## Alternatives\n- pySigma toolchain\n- Vendor converters"
  }
);