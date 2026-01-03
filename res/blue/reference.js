window.CYBER_RESOURCES_BLUE = window.CYBER_RESOURCES_BLUE || [];
window.CYBER_RESOURCES_BLUE.push(
  {
    "name": "Sigma Rules",
    "url": "https://sigmahq.io/",
    "website": "https://sigmahq.io/",
    "source": "https://github.com/SigmaHQ/sigma",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "SIEM-agnostic detection rules (Sigma format) with a conversion ecosystem to target SPL/KQL/EQL/Lucene and more.",
    "details": "## What it is\nSigma is a vendor-neutral detection format (YAML) for log-based detections. You keep detections as code (rules + review + versioning) and convert them into the query language of your SIEM.\n\n## How to download the rules\n```bash\ngit clone https://github.com/SigmaHQ/sigma.git\n# or keep it as a submodule inside your detections-as-code repo\n```\n\n## How to actually use Sigma (conversion workflow)\nSigma rules don’t run by themselves; you typically convert them into your SIEM backend queries.\n\n### Install the converter (sigma-cli)\n```bash\npip3 install sigma-cli\n# ensure ~/.local/bin is in PATH if needed\nsigma version\n```\n\n### Install a backend plugin (example: Splunk)\n```bash\nsigma plugin list\nsigma plugin install splunk\n```\n\n### Convert rules (example)\nA common pattern is to keep a `rules/` directory and convert a subset by platform/logsource.\n\n```bash\n# convert a single rule\necho \"---\" >/dev/null\nsigma convert --target splunk path/to/rule.yml\n\n# convert a directory (you’ll usually restrict by platform/use-case)\nsigma convert --target splunk path/to/rules/\n```\n\n## How Sigma is most useful in blue-team practice\nSigma is strongest when treated as a controlled engineering pipeline:\n- maintain a curated fork (or overlay) with environment-specific tuning\n- validate against your log schema (field mappings) and data model assumptions\n- test on replayed events or a dedicated “detection QA” dataset before enabling\n- track false positives like bugs (triage, suppression rules, unit tests)\n\n## Practical tips\n- Start from a small, high-signal set (credential access, persistence, LOLBins) and expand.\n- Pair each deployed detection with a short triage runbook (what to check next, what’s benign noise, what’s escalatable).\n\n## Alternatives\n- Splunk SPL detections (vendor-specific)\n- Elastic detection rules (EQL/KQL/ES|QL in Elastic Security)"
  },
  {
    "name": "SwiftOnSecurity Sysmon Config",
    "url": "https://github.com/SwiftOnSecurity/sysmon-config",
    "website": null,
    "source": "https://github.com/SwiftOnSecurity/sysmon-config",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Widely used Sysmon configuration baseline focused on high-value telemetry with manageable noise.",
    "details": "## What it is\nA community-maintained Sysmon configuration template (XML) that aims to capture high-value endpoint telemetry without exploding noise.\n\n## How to download\n```bash\ngit clone https://github.com/SwiftOnSecurity/sysmon-config.git\n# primary config is commonly: sysmonconfig-export.xml\n```\n\n## How to deploy (typical Windows workflow)\n1) Download Sysmon from Microsoft Sysinternals (official page).\n2) Extract it (Sysmon is distributed as an archive).\n3) Copy the config XML (e.g., `sysmonconfig-export.xml`) next to Sysmon.\n4) Install Sysmon with the config.\n\nTypical install/update commands (run in an elevated shell):\n- Install with config: `Sysmon64.exe -accepteula -i sysmonconfig.xml`\n- Update config: `Sysmon64.exe -c sysmonconfig.xml`\n\nSysmon logs to `Microsoft-Windows-Sysmon/Operational` (ingest this into your SIEM).\n\n## How to use it effectively\n- Treat this as a baseline. Tune excludes for your estate (developer tools, patching agents, management software).\n- Validate performance/volume on a pilot group first; Sysmon can increase event volume materially depending on what you enable.\n- Maintain a simple change process: config versioning + rollback plan.\n\n## Practical tip\nNoise control is the difference between “great telemetry” and “SOC meltdown.” Make tuning a planned activity (weekly/biweekly) and track which exclusions you add and why.\n\n## Alternatives\n- Olaf Hartong Sysmon Modular\n- Custom configs validated via testing"
  },
  {
    "name": "Olaf Hartong Sysmon Modular",
    "url": "https://github.com/olafhartong/sysmon-modular",
    "website": null,
    "source": "https://github.com/olafhartong/sysmon-modular",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Composable Sysmon configuration modules so you can build different telemetry profiles per endpoint/server role.",
    "details": "## What it is\nA modular Sysmon configuration approach: instead of one monolithic XML, you use modules and assemble a config that matches your role (workstation vs server), use-case (IR-focused vs threat-hunting), and noise tolerance.\n\n## How to download\n```bash\ngit clone https://github.com/olafhartong/sysmon-modular.git\n```\n\n## How to deploy\nThe repo typically includes a ready-to-use compiled config (and the modules to customize it). In practice you:\n- start with the provided compiled `sysmonconfig.xml` (or the recommended export)\n- deploy via your software distribution/MDM/GPO mechanism\n- iterate by enabling/disabling modules as you learn what’s useful/noisy in your environment\n\nInstallation/update is done with the standard Sysmon commands (install with config, then update config), and ingestion targets `Microsoft-Windows-Sysmon/Operational`.\n\n## How it’s useful\nSysmon Modular is ideal when different fleets need different telemetry:\n- domain controllers / jump hosts: tighter monitoring, more sensitive events\n- developer workstations: more exclusions for build tools and package managers\n- RDS / terminal servers: special focus on logon/session activity and process trees\n\n## Practical tip\nBuild two profiles first:\n- “Core” (low noise, high coverage)\n- “IR surge” (temporarily higher volume during an incident)\nThen automate switching profiles for a subset of hosts when you need deeper visibility."
  },
  {
    "name": "OWASP Cheat Sheet Series",
    "url": "https://cheatsheetseries.owasp.org/",
    "website": "https://cheatsheetseries.owasp.org/",
    "source": "https://github.com/OWASP/CheatSheetSeries",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Practical secure coding and AppSec implementation guidance (auth, sessions, crypto, input validation, etc.).",
    "details": "## What it is\nOWASP Cheat Sheets are short, implementation-oriented guidance pages that are easy to embed into engineering workflows (code review templates, secure design checklists, internal standards).\n\n## How to use it operationally\nThe highest-leverage way to use these is not “read them once,” but:\n- link the relevant cheat sheet directly from your PR templates (e.g., “Auth changes” → Authentication, Session Management)\n- embed snippets into internal secure coding standards\n- turn key recommendations into reusable libraries/paved paths (e.g., centralized input validation, standardized JWT handling)\n\n## Offline / internal mirror\n```bash\ngit clone https://github.com/OWASP/CheatSheetSeries.git\n```\nYou can then host internally (static site) or import into your internal wiki so developers have a stable reference even when external access is restricted.\n\n## Practical tip\nPick a small subset that matches your stack (e.g., Node/Java/.NET) and make those the default references in review. Breadth is great, but consistent usage beats “the perfect doc nobody opens.”"
  },
  {
    "name": "Microsoft Sentinel (KQL docs)",
    "url": "https://learn.microsoft.com/en-us/kusto/query/tutorials/common-tasks-microsoft-sentinel?view=microsoft-sentinel",
    "website": "https://learn.microsoft.com/en-us/kusto/query/tutorials/common-tasks-microsoft-sentinel?view=microsoft-sentinel",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "KQL guidance for hunting and detections in Microsoft Sentinel (query patterns, common tasks, analyst workflows).",
    "details": "## What it is\nKQL (Kusto Query Language) is the query language used throughout Microsoft Sentinel (and other Microsoft data platforms) for hunting, investigation, and scheduled analytics/detections.\n\n## How to use it effectively\nThe winning workflow is iterative and data-driven:\n- start from a hypothesis (e.g., suspicious PowerShell, impossible travel, new persistence mechanism)\n- build a baseline (what’s normal in your tenant)\n- narrow to anomalies, then enrich with joins (identity, device, process, network)\n- only then promote into a scheduled detection with suppression/thresholding\n\n## How to operationalize\n- Maintain a small internal KQL library: query → intent → required tables → expected false positives → triage steps.\n- For every detection, store the companion hunt query that analysts can run immediately to scope impact.\n- Use consistent entity normalization (account/device/ip/url) so joins and investigations stay reliable.\n\n## Practical tip\nMost “bad detections” fail because of missing context. Always add enrichment steps (identity/device context, known admin tools, allowlists) before you enable alerting."
  },
  {
    "name": "Splunk Security Essentials",
    "url": "https://splunkbase.splunk.com/app/3435",
    "website": "https://splunkbase.splunk.com/app/3435",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Use-case driven security content and guidance to accelerate detections and investigations in Splunk.",
    "details": "## What it is\nSplunk Security Essentials (SSE) helps you map security use-cases to available data sources, provides detection guidance, and accelerates building practical security content aligned to common SOC needs.\n\n## Install / setup (Splunk)\nSSE is installed as a Splunk app (typically via Splunkbase / in-product app browsing). After installation, follow the Splunk docs to configure mappings and validate data availability.\n\nKey operational steps:\n- install the app\n- map your data sources to the content/use-cases\n- run the built-in checks/dashboards to confirm the needed events exist\n- start from a few high-value use-cases and iterate\n\n## How to use it effectively\n- Use SSE as a planning tool: identify “we can’t detect X because we don’t ingest Y.”\n- Treat each use-case as a mini-project: data prerequisites → detection → tuning → runbook.\n- Promote only the tuned, validated searches into production alerting.\n\n## Practical tip\nSSE shines when you pair it with a disciplined content lifecycle: every alert must have an owner, a triage path, and a suppression strategy—otherwise you just create noise faster."
  },
  {
    "name": "Elastic Detection Rules",
    "url": "https://elastic.github.io/detection-rules-explorer/",
    "website": "https://elastic.github.io/detection-rules-explorer/",
    "source": "https://github.com/elastic/detection-rules",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Open detection content used by Elastic Security’s detection engine (useful both inside and outside Elastic as detection reference).",
    "details": "## What it is\nElastic’s public detection rules repository contains prebuilt detection logic (and the development/test tooling around it). Even if you don’t run Elastic, it’s valuable as a reference library for detection ideas and logic patterns.\n\n## How to browse quickly\nUse the explorer site to filter by tactic/technique, data source, and rule type.\n\n## How to download / work with it as code\n```bash\ngit clone https://github.com/elastic/detection-rules.git\n```\n\n## How to use it effectively\n- If you run Elastic Security: use it to understand what’s prebuilt, what assumptions exist, and how to tune.\n- If you run another SIEM: translate the logic into your query language and keep a traceable mapping (original rule → translated query → tuning notes).\n\n## Practical tip\nWhen translating across SIEMs, the hard part isn’t syntax—it’s field semantics and data coverage. Validate that your events actually contain the required fields before you judge a rule as “working” or “broken.”"
  },
  {
    "name": "MITRE Engenuity ATT&CK Evaluations",
    "url": "https://evals.mitre.org/",
    "website": "https://evals.mitre.org/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Public evaluation results mapping security vendors’ visibility/detections to ATT&CK techniques under controlled emulations.",
    "details": "## What it is\nATT&CK Evaluations publishes results from controlled adversary emulations, reported against ATT&CK techniques. The right way to use it is as structured evidence about visibility and detection categories under defined conditions—not as a simplistic scorecard.\n\n## How to use it for real procurement/engineering decisions\n- Start from your threat model: pick evaluation rounds/adversaries close to what you care about.\n- Read the **participant configuration** sections: the settings and data sources enabled matter as much as the product.\n- Compare results technique-by-technique for the ATT&CK areas you prioritize (credential access, lateral movement, persistence).\n- Convert gaps into explicit requirements for your vendor bake-off (what logs/telemetry must be present, what alerts must fire).\n\n## Practical tip\nUse evaluations to drive your own test plan: reproduce a handful of techniques in your environment and validate the same visibility end-to-end (sensor → pipeline → detection → ticket → response)."
  },
  {
    "name": "Microsoft Security Blog",
    "url": "https://www.microsoft.com/en-us/security/blog/",
    "website": "https://www.microsoft.com/en-us/security/blog/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Threat research, incident writeups, and defensive guidance across Microsoft’s security ecosystem.",
    "details": "## What it is\nA high-volume source of threat intelligence writeups, security product guidance, and incident-response learnings.\n\n## How to use it without getting lost\n- Treat posts as hypothesis generators: extract behaviors/IOCs/TTPs and validate them against your telemetry.\n- For each relevant writeup, produce:\n  - 2–3 hunting queries (identity + endpoint + email/network)\n  - 1 detection candidate with clear suppressions\n  - a short analyst runbook (what to check next)\n\n## Practical tip\nVendor blogs can bias toward their own telemetry and controls. Use them for ideas, then prove them in your data (coverage, field availability, false positives)."
  },
  {
    "name": "Mandiant (Google Cloud) Threat Intelligence",
    "url": "https://www.mandiant.com/resources",
    "website": "https://www.mandiant.com/resources",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Long-form threat reports and frontline incident-response learnings useful for detection engineering and threat modeling.",
    "details": "## What it is\nMandiant publishes detailed reporting on threat actor behaviors, campaigns, and incident-response lessons learned.\n\n## How to convert reports into defensive value\n- Extract ATT&CK techniques and map them to your telemetry sources (EDR, identity, email, proxy/DNS, cloud audit).\n- Build a small “detection pack” per report:\n  - a handful of hunts (broad, then refined)\n  - 1–2 high-signal detections\n  - an exposure checklist (which assets/services are most at risk)\n- Track what you *couldn’t* validate due to missing logs; those become roadmap items.\n\n## Practical tip\nReports often include environment-agnostic indicators; prioritize behavior-based detections (process chains, auth patterns, persistence mechanisms) over brittle IOCs."
  },
  {
    "name": "Awesome Incident Response",
    "url": "https://github.com/meirwah/awesome-incident-response",
    "website": null,
    "source": "https://github.com/meirwah/awesome-incident-response",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Curated incident response tools, checklists, reading, and program-building references.",
    "details": "## What it is\nA curated index of IR tools and resources—useful for bootstrapping an IR toolkit and building an IR program roadmap.\n\n## How to use it effectively\nInstead of treating it as a link dump, use it to drive concrete deliverables:\n- define your IR stack by phase (collection, triage, containment support, forensics, reporting)\n- pick one tool per need, pilot it, and document the workflow\n- keep an internal shortlist that matches your OS mix and constraints (EDR present, cloud-first, air-gapped, etc.)\n\n## Download / internal mirror\n```bash\ngit clone https://github.com/meirwah/awesome-incident-response.git\n```\n\n## Practical tip\nTooling is only valuable when paired with runbooks and access. For each adopted tool, document: required permissions, where evidence is stored, and how analysts escalate."
  },
  {
    "name": "Awesome Threat Detection",
    "url": "https://github.com/0x4D31/awesome-threat-detection",
    "website": null,
    "source": "https://github.com/0x4D31/awesome-threat-detection",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Curated threat detection resources (rules, blogs, training, frameworks) for detection engineers and hunters.",
    "details": "## What it is\nA curated collection spanning detection formats, rule repositories, learning resources, and practitioner references.\n\n## How to use it without boiling the ocean\n- Use it as a quarterly “capability gap” review: pick 1–2 areas (endpoint, identity, cloud, email) and improve one slice.\n- Build an internal detection backlog: convert the most relevant references into tasks with owners and success criteria.\n\n## Download / internal mirror\n```bash\ngit clone https://github.com/0x4D31/awesome-threat-detection.git\n```\n\n## Practical tip\nCurated lists are best as discovery tools; your real value comes from what you operationalize (detections, hunts, and runbooks)."
  },
  {
    "name": "Awesome DFIR",
    "url": "https://github.com/cugu/awesome-forensics",
    "website": null,
    "source": "https://github.com/cugu/awesome-forensics",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Curated DFIR/forensics tools and references across acquisition, analysis, and reporting.",
    "details": "## What it is\nA broad DFIR curation that helps you identify tools and methods for evidence acquisition, triage, forensic analysis, and reporting.\n\n## How to use it effectively\n- Build a minimal, tested DFIR kit first (acquisition + triage + timeline + memory + reporting).\n- Standardize evidence formats and storage (where images go, naming, hashing, chain-of-custody).\n- Practice on known-good datasets so analysts learn what “normal” looks like.\n\n## Download / internal mirror\n```bash\ngit clone https://github.com/cugu/awesome-forensics.git\n```\n\n## Practical tip\nIn DFIR, repeatability matters: prefer fewer tools you’ve validated end-to-end over many tools you’ve never exercised under pressure."
  },
  {
    "name": "Windows Event Log Encyclopedia",
    "url": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
    "website": "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Windows Security log Event ID reference with descriptions and field-level context for investigations and detections.",
    "details": "## What it is\nA practical reference for Windows Security event IDs (what they mean, typical contexts, and what fields matter).\n\n## How to use it for detection engineering\n- When you build a detection, link the Event ID reference into the ticket/runbook.\n- Use the field descriptions to avoid fragile queries (e.g., which account field is authoritative in the event).\n- For high-value IDs (4624, 4625, 4672, 4688, etc.), create a short internal “what good looks like” baseline per environment.\n\n## Practical tip\nEvent IDs are only half the story: ensure your audit policy is configured to actually produce the events you’re writing detections for, and confirm your forwarders preserve the key fields."
  },
  {
    "name": "Sysmon Event ID Reference",
    "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "website": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Official Sysmon documentation: event IDs, schema, configuration concepts, and operational guidance.",
    "details": "## What it is\nSysmon (Sysinternals) provides high-fidelity Windows telemetry (process creation, network connections, driver loads, file events, etc.) into the Windows Event Log. This page documents event IDs and configuration semantics.\n\n## Setup (practical overview)\n- Download Sysmon from the official Sysinternals page (distributed as an archive), extract it, and deploy via your endpoint management.\n- Deploy a configuration (SwiftOnSecurity baseline or Sysmon Modular profile).\n- Ingest `Microsoft-Windows-Sysmon/Operational` into your SIEM.\n\nTypical operations (elevated shell):\n- install with config: `Sysmon64.exe -accepteula -i sysmonconfig.xml`\n- update config: `Sysmon64.exe -c sysmonconfig.xml`\n\n## How to use it effectively\n- Start with a tuned baseline config; don’t enable everything at once.\n- Build detections around stable fields (parent/child process, command line, hashes, signer, network destination) and add allowlists.\n- Treat Sysmon config changes like code: versioning, staged rollout, rollback.\n\n## Practical tip\nSysmon is a force multiplier only if you can keep volume and noise under control. Pilot, measure, tune, then expand."
  },
  {
    "name": "YARA-Rules (community)",
    "url": "https://github.com/Yara-Rules/rules",
    "website": null,
    "source": "https://github.com/Yara-Rules/rules",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Large community-maintained YARA rule repository; useful as a starting point for malware classification and detection.",
    "details": "## What it is\nA community repository that aggregates YARA rules from many contributors. It’s best treated as a rich reference set, not a drop-in production ruleset.\n\n## How to download\n```bash\ngit clone https://github.com/Yara-Rules/rules.git\n```\n\n## How to use it safely and effectively\n- Validate rules against both malicious and benign corpora to understand false positives.\n- Prefer staging: run scans offline or in a sandbox pipeline before pushing anywhere near production.\n- Curate: build your own “approved” subset and version it.\n\n## Practical tip\nRule quality varies. Create a simple acceptance bar (compiles, performance OK, low FP on benign set, provenance known) and keep only what passes."
  },
  {
    "name": "Florian Roth signature-base",
    "url": "https://github.com/Neo23x0/signature-base",
    "website": null,
    "source": "https://github.com/Neo23x0/signature-base",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Curated YARA rules + IOC collections used by tools like LOKI/THOR; structured for operational scanning and triage.",
    "details": "## What it is\nSignature-base is a structured collection of YARA signatures and IOC data maintained with an operational focus (quality, consistency, and usable structure).\n\n## How to download\n```bash\ngit clone https://github.com/Neo23x0/signature-base.git\n```\n\n## How to use it operationally\n- Use it as a curated upstream for your own YARA/IOC scanning pipeline.\n- Keep it version-pinned (commit hash or tagged release) so you can reproduce results during an incident.\n- Run QA: compile checks and performance checks across a representative file corpus.\n\n## Practical tip\nEven “high-quality” rule packs can generate noise in a specific environment. Maintain allowlists (signed admin tools, enterprise installers) and document the suppressions you apply."
  },
  {
    "name": "OpenIOC",
    "url": "https://github.com/fireeye/OpenIOC_1.1",
    "website": null,
    "source": "https://github.com/fireeye/OpenIOC_1.1",
    "binaries": null,
    "cat": "blue",
    "type": "reference",
    "desc": "Legacy structured IOC format/schema (XML) historically used to share investigation artifacts; often complemented/replaced by STIX 2.x today.",
    "details": "## What it is\nOpenIOC is an XML-based format for describing indicators/artifacts observed during investigations (file paths/hashes, registry keys, network artifacts, etc.). It’s still encountered in tooling and historical intel sharing.\n\n## How to get the schema and work with it\n```bash\ngit clone https://github.com/fireeye/OpenIOC_1.1.git\n```\nUse the schema/terms as the reference when you need to parse, validate, or generate OpenIOC documents.\n\n## How it can still be useful\n- Converting legacy IOC bundles into modern formats (e.g., into internal indicator stores or into STIX-based workflows).\n- Parsing historical IR packages from vendors/partners.\n- Normalizing IOCs into a single internal representation (so you can deploy to EDR/SIEM/blocklists consistently).\n\n## Practical tip\nTreat pure IOCs as volatile. Operational value comes from translating them into:\n- detections (behavior + context)\n- scoped hunts (where in your telemetry it should appear)\n- response actions with clear expiry/review (blocklists and suppressions shouldn’t be forever)."
  }
);
