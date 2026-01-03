[
  {
    "name": "MITRE ATT&CK",
    "url": "https://attack.mitre.org/",
    "website": "https://attack.mitre.org/",
    "source": "https://github.com/mitre-attack/attack-website",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "MITRE ATT&CK is a curated knowledge base of adversary tactics and techniques (TTPs) used to plan, describe, and measure detection and response coverage.",
    "details": "ATT&CK gives defenders a shared language for adversary behavior (e.g., “T1059 Command and Scripting Interpreter”) so coverage and gaps are visible and comparable.\n\n## Use\n- Build a **coverage map**: list your detections/controls and map each one to technique IDs; gaps become obvious.\n- Drive **threat hunting**: pick a technique relevant to your environment, write a hypothesis (“if TTP X happened we should see Y”), then validate against logs.\n- Standardize reporting: write incidents and findings in terms of tactics/techniques, then link the evidence you saw.\n\n## Practical workflow\nPick a scenario (ransomware, insider abuse, cloud compromise), choose 5–10 likely techniques, then for each:\n- identify the log sources that should prove it happened,\n- validate field quality/normalization,\n- implement or tune one detection,\n- store the final artifacts: technique ID, query/rule, required logs, and known false positives.\n\n## Tip\nSeparate **visibility** (the evidence exists in logs) from **signal** (an alert/hunt reliably finds it). Most failures are visibility or parsing, not “bad logic”."
  },
  {
    "name": "MITRE D3FEND",
    "url": "https://d3fend.mitre.org/",
    "website": "https://d3fend.mitre.org/",
    "source": "https://github.com/d3fend/d3fend-ontology",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "MITRE D3FEND is a defensive countermeasure knowledge base/ontology to describe, structure, and map defensive techniques and artifacts to improve security outcomes.",
    "details": "D3FEND helps you express “what we do defensively” in a precise, reusable way (countermeasures, artifacts, and relationships), making improvements easier to track and communicate.\n\n## Use\n- Build a **defense backlog**: for a given threat behavior, list the countermeasures you have vs need (hardening, isolation, filtering, detection, analysis).\n- Tie work to outcomes: map exercise findings to D3FEND countermeasures so “we improved logging” becomes a concrete technique + artifact change.\n- Create a knowledge graph: ingest the ontology to query relationships (countermeasure → artifact → adversary behavior mapping).\n\n## Download the ontology files\n```bash\nwget -O d3fend.ttl  \"https://d3fend.mitre.org/ontologies/d3fend.ttl\"\nwget -O d3fend.owl  \"https://d3fend.mitre.org/ontologies/d3fend.owl\"\nwget -O d3fend.json \"https://d3fend.mitre.org/ontologies/d3fend.json\"\n```\n\n## Tip\nUse D3FEND to make exercises “actionable”: every finding should end as a named countermeasure, an owner, and a measurable change (new control, better telemetry, improved triage context)."
  },
  {
    "name": "CIS Critical Security Controls",
    "url": "https://www.cisecurity.org/controls/cis-controls-list",
    "website": "https://www.cisecurity.org/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "The CIS Controls are a prioritized set of safeguards designed to reduce common attack paths and provide a practical security roadmap.",
    "details": "CIS Controls are most useful when you need a pragmatic “what do we implement next?” plan, with clear safeguards you can measure.\n\n## Use\n- Pick an **Implementation Group (IG1/IG2/IG3)** that matches your risk and resources.\n- Turn safeguards into a delivery plan: owners, evidence, rollout dates, and success checks.\n- Use them as a bridge between technical work and leadership reporting (progress by control/safeguard).\n\n## Practical tip\nTreat each safeguard as a test: define what “implemented” means, what evidence proves it (configs, logs, scans), and how you’ll continuously verify it."
  },
  {
    "name": "NIST Cybersecurity Framework (CSF)",
    "url": "https://www.nist.gov/cyberframework",
    "website": "https://www.nist.gov/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "NIST CSF is a high-level framework to organize cybersecurity outcomes across functions, enabling consistent maturity assessment, prioritization, and communication.",
    "details": "CSF is best when you need an organization-wide view of outcomes (governance, risk, protection, detection, response, recovery) and a structured way to assess gaps.\n\n## Use\n- Create a **Current Profile** (what outcomes you meet today) and a **Target Profile** (what you need).\n- Convert gaps into a roadmap: projects, controls, metrics, and owners.\n- Use “Informative References” to map CSF outcomes to concrete standards/controls you already use.\n\n## Practical workflow\nRun a workshop per function: capture evidence, score consistency, record blockers, then produce a short prioritized backlog (top risks first, not “everything”)."
  },
  {
    "name": "FIRST CSIRT Services Framework",
    "url": "https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2-1",
    "website": "https://www.first.org/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "A reference catalog of CSIRT services and capabilities to define what your SOC/CSIRT provides, align staffing, and set measurable service expectations.",
    "details": "This framework is useful when your incident response capability needs to be described as a service catalog (scope, deliverables, interfaces, and expectations).\n\n## Use\n- Define your **service menu** (what you do and don’t do).\n- For each service, specify inputs, outputs, SLAs, escalation paths, and KPIs.\n- Use it to align tooling and staffing to real services (not vague “we do IR”).\n\n## Tip\nOperational clarity comes from boundaries: define where SOC ends and where IT/Ops/Legal/Comms begins, then document the handoffs."
  },
  {
    "name": "OWASP ASVS",
    "url": "https://owasp.org/www-project-application-security-verification-standard/",
    "website": "https://owasp.org/",
    "source": "https://github.com/OWASP/ASVS",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "OWASP ASVS is a security requirements standard for web apps/services, designed to be used as a consistent verification checklist across assurance levels.",
    "details": "ASVS turns “secure app” into concrete, testable requirements, so security expectations can be agreed upfront and verified consistently.\n\n## Use\n- Choose the right level:\n  - **L1** for most apps (baseline).\n  - **L2** for sensitive data/important business functions.\n  - **L3** for high-risk apps (critical, high-value targets).\n- Convert requirements into: tickets for developers, test cases for QA/AppSec, and acceptance criteria for releases.\n\n## Practical tip\nStart with one feature area (auth, session, access control). Implement and verify those requirements end-to-end before expanding, otherwise ASVS becomes “a big list nobody finishes”."
  },
  {
    "name": "NIST Secure Software Development Framework (SSDF)",
    "url": "https://csrc.nist.gov/projects/ssdf",
    "website": "https://csrc.nist.gov/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "NIST SSDF is a set of secure development practices to reduce software vulnerabilities and supply-chain risk across the SDLC.",
    "details": "SSDF helps you build a secure SDLC by defining practices you can integrate into any engineering process (requirements, design, build, test, release, and maintenance).\n\n## Use\n- Map SSDF practices to your SDLC stages and assign owners (platform, app teams, security, suppliers).\n- Make practices measurable (e.g., signed builds, provenance, dependency policies, secure code review gates).\n- Extend it to suppliers: require evidence of key practices for third-party software.\n\n## Tip\nTreat SSDF as “controls for software delivery”. If a practice can’t be verified continuously (CI evidence), it will erode over time."
  },
  {
    "name": "OWASP SAMM",
    "url": "https://owaspsamm.org/",
    "website": "https://owaspsamm.org/",
    "source": "https://github.com/owaspsamm/core",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "OWASP SAMM is a maturity model for improving software security across governance, design, implementation, verification, and operations with a roadmap-oriented approach.",
    "details": "SAMM is most useful when you need to measure and improve software security practices over time (not just checklists).\n\n## Use\n- Assess current maturity per practice area (how consistently you do it, not whether you did it once).\n- Define a target maturity aligned to risk (different product lines can have different targets).\n- Build a roadmap with a few high-leverage improvements per quarter (training, threat modeling, secure build controls, verification automation).\n\n## Tip\nPick improvements that change the system, not heroics: platform guardrails, CI gates, standardized libraries, and repeatable verification win faster than “more reviews”."
  },
  {
    "name": "Open Policy Agent (OPA)",
    "url": "https://www.openpolicyagent.org/",
    "website": "https://www.openpolicyagent.org/",
    "source": "https://github.com/open-policy-agent/opa",
    "binaries": "https://github.com/open-policy-agent/opa/releases",
    "cat": "blue",
    "type": "framework",
    "desc": "OPA is a policy-as-code engine (Rego) that centralizes authorization and compliance decisions across Kubernetes, CI/CD, APIs, and microservices.",
    "details": "OPA lets you move “who/what is allowed?” decisions into versioned policy code, so enforcement is consistent and reviewable.\n\n## Download & setup\nPreferred: download the correct binary from GitHub Releases and put it on your PATH.\n\nExample (Linux amd64):\n```bash\n# download the latest release asset from GitHub Releases (pick the right file for your OS/arch)\n# then:\nchmod +x opa\nsudo mv opa /usr/local/bin/opa\nopa version\n```\nContainer option (useful for CI/labs):\n```bash\ndocker pull openpolicyagent/opa:latest\ndocker run --rm openpolicyagent/opa:latest version\n```\n\n## Use\n- Local evaluation (fast feedback while writing policies): `opa eval` / `opa test`.\n- Service authorization: your app sends JSON input to OPA, OPA returns allow/deny + reasons.\n- Guardrails: enforce rules in pipelines (IaC checks) and admission control patterns in Kubernetes.\n\n## Tip\nKeep policy inputs small and stable (a normalized JSON contract). Most long-term pain comes from changing input shapes, not from Rego."
  },
  {
    "name": "MITRE ATT&CK for ICS",
    "url": "https://attack.mitre.org/matrices/ics/",
    "website": "https://attack.mitre.org/",
    "source": "https://github.com/mitre-attack/attack-website",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "ATT&CK for ICS tailors adversary techniques and tactics to industrial control environments, where objectives and telemetry differ from enterprise IT.",
    "details": "ICS ATT&CK is most valuable when you need behavior-driven planning that respects OT realities: safety, availability, and constrained visibility.\n\n## Use\n- Map techniques to **zones/conduits** and critical process assets.\n- Define what “evidence” looks like in OT (engineering workstation actions, historian changes, PLC programming, remote access paths).\n- Build detections and playbooks that prioritize process safety and controlled response.\n\n## Tip\nDon’t copy enterprise detections into OT unchanged. Start from the technique, then define OT-appropriate telemetry and response constraints (what you can safely isolate or block)."
  },
  {
    "name": "IEC 62443 Overview",
    "url": "https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards",
    "website": "https://www.isa.org/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "ISA/IEC 62443 is a family of standards for securing industrial automation and control systems (IACS), covering processes, system requirements, and component requirements.",
    "details": "IEC 62443 is the go-to structure for OT security programs because it ties security engineering to IACS architecture and lifecycle practices.\n\n## Use\n- Build an OT security architecture around **zones and conduits** (segmentation with purpose).\n- Use security levels and requirements to drive procurement and system acceptance criteria.\n- Align governance: roles, risk management, patching constraints, and change control.\n\n## Tip\nUse 62443 to make vendor deliverables measurable: require evidence for secure configuration, account management, logging capabilities, and update mechanisms before deployment."
  },
  {
    "name": "STIX/TAXII (OASIS)",
    "url": "https://oasis-open.github.io/cti-documentation/",
    "website": "https://oasis-open.github.io/cti-documentation/",
    "source": "https://github.com/oasis-open/cti-documentation",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "STIX defines a machine-readable model for cyber threat intelligence, and TAXII defines an HTTPS-based protocol/API for transporting that intelligence between producers and consumers.",
    "details": "STIX/TAXII matters when you want threat intel exchange that’s automatable: consistent objects/relationships (STIX) and a standard transport (TAXII).\n\n## Use\n- Define what you exchange (indicators, incidents, malware, TTPs, sightings) as STIX objects.\n- Publish and consume via TAXII collections so tools can sync and de-duplicate.\n- Normalize enrichment: attach confidence, timestamps, and provenance so downstream decisions are explainable.\n\n## Practical tip\nStart small: one TAXII collection, a few object types, and strict dedup rules. “All intel, all the time” becomes noise unless you control quality and lifecycle."
  },
  {
    "name": "OpenDXL / OpenDXL Broker (legacy)",
    "url": "https://www.opendxl.com/",
    "website": "https://www.opendxl.com/",
    "source": "https://github.com/opendxl/opendxl-broker",
    "binaries": null,
    "cat": "blue",
    "type": "framework",
    "desc": "OpenDXL is a security messaging fabric concept; the OpenDXL Broker is a legacy-but-seen messaging broker used to connect security services via pub/sub patterns.",
    "details": "OpenDXL is most relevant in environments that already have DXL-based integrations (legacy ecosystems). It provides a message bus for event exchange and automation.\n\n## Download & run (Docker)\n```bash\ndocker pull opendxl/opendxl-broker\n# run using the repo docs for required volumes/certs/ports\n```\n\n## Use\n- Publish security events (detections, enrichments) and subscribe automation/services to them.\n- Integrate tools that already support DXL clients so they can exchange telemetry and actions.\n\n## Tip\nTreat it as an integration layer, not a modern SOAR replacement. If you’re starting fresh, evaluate contemporary event streaming/SOAR patterns before adopting DXL."
  }
]
