window.CYBER_RESOURCES_BLUE = window.CYBER_RESOURCES_BLUE || [];
window.CYBER_RESOURCES_BLUE.push(
  {
    "name": "NIST SP 800-61 Rev. 3 (Incident Response Recommendations)",
    "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    "website": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "Current NIST incident response guidance (Rev. 3) aligned with CSF 2.0 and cyber risk management.",
    "details": "## What it is\nNIST SP 800-61 Rev. 3 is the current NIST guidance for building and operating an incident response capability: governance, preparation, detection/analysis, containment/eradication/recovery, and continuous improvement—framed as part of broader cyber risk management (CSF 2.0 context).\n\n## Download (offline copy)\nThe CSRC page links the official PDF.\n\n```bash\nwget -O NIST.SP.800-61r3.pdf https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf\n```\n\n## How to turn it into something operational\nThe guide becomes useful when you translate it into a small set of concrete artifacts your org actually runs:\n\n- **IR policy + roles**: who can declare an incident, who owns comms, who can isolate hosts, who approves customer notifications.\n- **Severity model**: 3–5 levels with explicit triggers (e.g., “confirmed credential theft affecting privileged accounts” → Sev-1).\n- **Runbooks/playbooks**: phishing, BEC, endpoint malware, ransomware, cloud key leak, web app compromise, insider exfil.\n- **Evidence handling**: what to collect first (volatile vs non-volatile), chain-of-custody, retention, legal hold triggers.\n- **Metrics**: MTTD/MTTR, containment time, dwell time estimates, recurrence rate, % incidents with postmortem actions completed.\n\n## Practical implementation pattern\n- Start with the top 5 incident types you *actually see*.\n- For each, define: detection sources → triage questions → containment actions → eradication steps → validation → comms checklist.\n- Run tabletop exercises quarterly and update playbooks based on what broke (permissions, missing logs, unclear ownership).\n\n## Notes\n- SP 800-61 Rev. 2 was withdrawn/archived by NIST; Rev. 3 is the current reference."
  },
  {
    "name": "CIS Benchmarks",
    "url": "https://www.cisecurity.org/cis-benchmarks",
    "website": "https://www.cisecurity.org/cis-benchmarks",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "Consensus hardening baselines for OSs, cloud services, and applications—usable as secure configuration standards.",
    "details": "## What it is\nCIS Benchmarks are prescriptive configuration recommendations developed through a community consensus process. They’re commonly used to define “secure by default” baselines for endpoints, servers, cloud services, and common software stacks.\n\n## How to access & download\nMost Benchmark PDFs are obtained via CIS WorkBench (free registration is typical). Product-specific benchmark pages often provide a “Download Latest CIS Benchmark” option.\n\nOperationally, treat the benchmark document as the spec and build an internal implementation that is:\n- tested in staging\n- versioned\n- enforced via configuration management / policy-as-code\n\n## How to apply them without breaking production\nA reliable rollout approach is:\n- **Profile selection**: start with Level 1 recommendations (lower operational risk), then evaluate Level 2 where appropriate.\n- **Exception workflow**: exceptions must be time-bound and justified (owner, risk accepted, compensating control).\n- **Drift control**: measure compliance continuously and alert on drift rather than doing “annual hardening sprints.”\n\n## Turning guidance into enforcement\n- Windows/macOS: MDM baselines + GPO/Intune policies.\n- Linux: Ansible/Salt/Chef hardening roles.\n- Cloud: CSPM + IaC guardrails (Terraform policies, org policies, service control policies).\n\nIf you want automated assessment against Benchmarks, CIS provides tooling (e.g., CIS-CAT). Keep this entry focused on the guidance/baselines, and model the assessor as a separate tool entry if you catalog executables.\n\n## Practical tip\nDon’t implement everything blindly. The most valuable outcome is an auditable, repeatable baseline you can keep stable across fleets—plus a safe path to tighten it over time."
  },
  {
    "name": "DISA STIGs",
    "url": "https://public.cyber.mil/stigs/",
    "website": "https://public.cyber.mil/stigs/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "DoD/DISA Security Technical Implementation Guides and SRGs for detailed secure configuration baselines.",
    "details": "## What it is\nDISA STIGs are detailed configuration baselines widely used in government/defense contexts and by organizations that want highly specific, auditable hardening requirements.\n\n## How to download & navigate\n- The public STIG portal provides browsing and access to the STIG library and related tools.\n- Many STIGs are available as documents and/or machine-readable content (e.g., XCCDF/SCAP packages depending on the STIG).\n\nA practical workflow is:\n- pick the applicable STIG (OS / app / network device)\n- identify the version/release you are standardizing on\n- track updates and release notes like you would for any baseline\n\n## Making STIGs operational (not just compliance paperwork)\n- **Map STIG rules to enforcement mechanisms**: GPO/Intune settings, MDM profiles, Ansible roles, cloud policy, or device config templates.\n- **Automate validation where possible**: integrate assessment results into CI/CD for images (golden AMIs, container base images) and into continuous monitoring for running fleets.\n- **Handle exceptions deliberately**: document why a control is not applied, set a review date, and attach compensating controls.\n\n## Useful companion tooling\nDISA provides STIG-related tools (e.g., STIG Viewer) via official pages; these help review STIG content and validate compliance workflows. If you want binaries in your catalog, add a separate entry specifically for the STIG Viewer tool."
  },
  {
    "name": "SANS Blue Team Resources (SANS Blue Team Wiki)",
    "url": "https://wiki.sans.blue/",
    "website": "https://wiki.sans.blue/",
    "source": "https://github.com/sans-blue-team/blue-team-wiki",
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "Curated defensive wiki with tools, techniques, cheat sheets, and blue-team operational references.",
    "details": "## What it is\nThe SANS Blue Team Wiki is a curated, practitioner-oriented knowledge base: detection/response references, cheat sheets, and operational guides that are easy to drop into SOC workflows.\n\n## How to use it effectively\nInstead of reading it like a blog, use it like a SOC knowledge base:\n- Link common investigation tasks from your ticket templates (e.g., “suspicious PowerShell” → relevant triage notes).\n- Build an internal “first 15 minutes” checklist per alert type and cite the corresponding reference pages.\n- Pull posters/cheat sheets into onboarding for new analysts.\n\n## How to keep an internal mirror\nIf your SOC environment is restricted or you want change tracking, mirror the content repo:\n\n```bash\ngit clone https://github.com/sans-blue-team/blue-team-wiki.git\n```\n\nThen serve it internally (static site) or import pages into your internal wiki so analysts can access references even during outages.\n\n## Practical tip\nTreat your internal version as the operational truth: keep your own addenda for environment-specific log sources, data retention, and escalation contacts."
  },
  {
    "name": "Threat Hunting Project (Threat Hunter Playbook)",
    "url": "https://github.com/OTRF/ThreatHunter-Playbook",
    "website": "https://github.com/OTRF/ThreatHunter-Playbook",
    "source": "https://github.com/OTRF/ThreatHunter-Playbook",
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "Hunting playbooks and methodologies (often notebook-driven) you can adapt to your data sources and telemetry.",
    "details": "## What it is\nThreat Hunter Playbook is a collection of hunting hypotheses, procedures, and practical playbooks—commonly delivered as notebooks or structured writeups.\n\n## How to set it up locally\n```bash\ngit clone https://github.com/OTRF/ThreatHunter-Playbook.git\ncd ThreatHunter-Playbook\n```\n\nIf the project uses Jupyter notebooks, a typical safe setup is:\n```bash\npython3 -m venv .venv\nsource .venv/bin/activate\npip install -U pip\n# install dependencies if a requirements file is provided\n# pip install -r requirements.txt\n```\n\n## How to use it effectively in a real SOC\n- **Start from data reality**: pick playbooks that match the telemetry you actually have (EDR, Windows logs, proxy, DNS, cloud audit).\n- **Convert notebooks to repeatable hunts**: turn the query logic into saved searches / scheduled hunts in your SIEM.\n- **Document tuning decisions**: what was filtered, what’s noisy, what’s high-signal in your environment.\n\n## Operational pattern that scales\nPick 1–2 hunts per week, run them consistently, and track outcomes:\n- detections created\n- coverage gaps discovered (missing logs)\n- time-to-execute\n- false-positive drivers\n\n## Notes\nTreat playbooks as templates: they work best when you align field names, event IDs, and entity normalization to your environment."
  },
  {
    "name": "Microsoft Defender XDR documentation",
    "url": "https://learn.microsoft.com/en-us/defender-xdr/",
    "website": "https://learn.microsoft.com/en-us/defender-xdr/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "Official operational documentation for Defender XDR (portal workflows, incidents, hunting, response).",
    "details": "## What it is\nMicrosoft’s official documentation for Defender XDR: how incidents/alerts are correlated, how to investigate entities, how response actions work, and how to operationalize advanced hunting.\n\n## Getting started (practical path)\nA useful enablement order that avoids “we turned it on but nothing is actionable”:\n- Confirm data connectors/telemetry sources you expect are actually onboarded (endpoints, identity, email, cloud apps).\n- Define incident severity mapping aligned to your SOC workflow (what becomes a ticket, what pages someone, what’s informational).\n- Establish a baseline of response actions (isolation, AV scan, file quarantine, block indicators) and the required RBAC.\n\n## Making Advanced Hunting valuable\n- Start by codifying your top 10 investigations as KQL queries (lateral movement, suspicious PowerShell, anomalous mailbox rules, risky sign-ins).\n- Turn high-signal hunts into detections/analytics rules with clear suppression and expiry.\n- Maintain a small internal library: query → what it detects → expected false positives → triage steps.\n\n## Operational tip\nTreat the docs as your source of truth for feature behavior and limits (retention, query limits, role requirements) and keep your SOC runbooks linked directly to the relevant pages."
  },
  {
    "name": "NIST SP 800-82 Rev. 3 (Guide to Operational Technology Security)",
    "url": "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
    "website": "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "guide",
    "desc": "Current NIST guidance for securing OT environments (includes ICS as a subset) with OT-specific constraints (safety, availability, reliability).",
    "details": "## What it is\nNIST SP 800-82 Rev. 3 expands from ICS-only framing to broader Operational Technology (OT) security, covering architectures/topologies, common threats and vulnerabilities, and recommended safeguards suited to OT constraints.\n\n## Download (offline copy)\n```bash\nwget -O NIST.SP.800-82r3.pdf https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf\n```\n\n## How to use it in real OT programs\nThe doc becomes operational when you map guidance to an OT-specific control strategy:\n- **Network zoning & conduits**: define OT zones (safety, control, supervisory, DMZ, enterprise) and enforce controlled conduits.\n- **Remote access**: strong auth + jump hosts + session recording + strict time-bounded access.\n- **Asset inventory that includes “unscannable” devices**: passive discovery + engineering documentation + change control.\n- **Detection strategy**: prioritize passive monitoring, protocol-aware sensors, and anomaly detection that won’t disrupt operations.\n- **Patch/change management**: align with plant outages, vendor constraints, and safety validation requirements.\n\n## Practical implementation pattern\n- Start by modeling your OT architecture (zones/flows) and identifying the “crown jewel” processes.\n- Define compensating controls for legacy devices that cannot be patched or have fragile protocols.\n- Build IR playbooks that explicitly address OT realities (when isolation is unsafe, when fail-safe triggers, who authorizes shutdowns).\n\n## Notes\nEarlier revisions (e.g., Rev. 2) are older/archived; Rev. 3 is the current reference for OT guidance."
  }
);
