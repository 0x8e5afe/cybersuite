window.CYBER_RESOURCES_PURPLE = window.CYBER_RESOURCES_PURPLE || [];
window.CYBER_RESOURCES_PURPLE.push(
  {
    "name": "MITRE ATT&CK Evaluations",
    "url": "https://evals.mitre.org/",
    "website": "https://evals.mitre.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Vendor evaluation results mapped to ATT&CK",
    "source": null,
    "binaries": null,
    "details": "## Overview\nMITRE Engenuity’s ATT&CK Evaluations publish repeatable adversary emulations and show what different security products detect (and how) for the same technique chain.\n\n## Use\nUse it as a **gap-finder** rather than a “winner picker”: pick the evaluation scenario closest to your threat model, then note where your stack should produce evidence (telemetry) and where it should produce signal (alerts). Many evaluation pages let you open an **ATT&CK Navigator layer (JSON)**—handy for turning results into a coverage map you can track over time.\n\n## Purple-team workflow\nMirror a slice of the evaluation (a few techniques), run it in your lab, then compare:\n- *Visibility*: did the raw logs appear?\n- *Analytics*: did your detections trigger?\n- *Triage*: did the alert context explain what happened?\n\n## Notes\nVendor results are informative, but your environment (logging, tuning, coverage) is what determines outcomes.",
    "tags": [
      "reference",
      "monitoring",
      "training"
    ]
  },
  {
    "name": "Sigma Rules",
    "url": "https://sigmahq.io/",
    "website": "https://sigmahq.io/",
    "cat": "purple",
    "type": "reference",
    "desc": "Portable detection rules",
    "source": "https://github.com/SigmaHQ/sigma",
    "binaries": null,
    "details": "## Overview\nSigma is a vendor-agnostic rule format you can translate into SIEM/EDR queries, making it a practical “common language” for detections.\n\n## Use\nStart with the **release packages** (Core is usually the best first pass), then treat rules as *hypotheses*: validate prerequisites (data fields), run safely in a test dataset, and tune false positives before production.\n\n## Setup (conversion)\nThe easiest path today is Sigma CLI (built on pySigma):  \n```bash\npip install sigma-cli\n```\nConvert a rule to a backend query (example backends depend on what you install):  \n```bash\nsigma convert -t <backend> path/to/rule.yml\n```\n\n## Notes\nTranslation quality depends on your data model. If your logs don’t match the expected fields, fix mapping first (ECS/OSSEM/CIM) or apply a pipeline during conversion.",
    "tags": [
      "reference",
      "detection",
      "database"
    ]
  },
  {
    "name": "Elastic detection-rules",
    "url": "https://elastic.github.io/detection-rules-explorer/",
    "website": "https://www.elastic.co/",
    "cat": "purple",
    "type": "reference",
    "desc": "Public detection logic for Elastic Security",
    "source": "https://github.com/elastic/detection-rules",
    "binaries": null,
    "details": "## Overview\nElastic’s detection-rules repository is the upstream source for many prebuilt Elastic Security detections, with tests and release bundles.\n\n## Use\nUse the Explorer to search rules by technique/data source, then copy patterns into your own detection engineering: required fields, lookback windows, thresholding, and suppressions.\n\n## Setup (local testing)\nClone and run the rule tooling locally when you want CI-like validation:  \n```bash\ngit clone https://github.com/elastic/detection-rules.git\ncd detection-rules\n```\nThen follow the repo docs to run unit tests and generate/export rule artifacts for your target stack version.\n\n## Notes\nTreat upstream rules as a baseline. The real value is learning *why* a rule is structured a certain way (data sources, false positive guidance, and test coverage).",
    "tags": [
      "reference",
      "web",
      "detection"
    ]
  },
  {
    "name": "Splunk Security Essentials",
    "url": "https://splunksecurityessentials.com/",
    "website": "https://www.splunk.com/",
    "cat": "purple",
    "type": "reference",
    "desc": "Guided security use cases + starter detection content for Splunk",
    "source": null,
    "binaries": null,
    "details": "## Overview\nSplunk Security Essentials (SSE) is a guided catalog of security use cases with example content, designed to help you align data onboarding, detections, and investigations.\n\n## Use\nPick a use case, follow the data onboarding guidance, and deploy the searches/detections incrementally. SSE is especially useful for purple teams because each exercise can map to a concrete “what data did we need?” and “what search should have fired?” outcome.\n\n## Download & install\nDownload from Splunkbase (login required) and install on your Splunk search head:\n1) Download the app package from Splunkbase.  \n2) In Splunk: **Apps → Manage Apps → Install app from file → Upload**.  \n3) Restart Splunk to complete installation.\n\n## Notes\nIf you build custom content, SSE also supports importing/structuring third-party detections into its format for consistent browsing and reporting.",
    "tags": [
      "reference",
      "detection",
      "search"
    ]
  },
  {
    "name": "AtomicTestHarnesses",
    "url": "https://www.powershellgallery.com/packages/AtomicTestHarnesses",
    "website": "https://www.powershellgallery.com/",
    "cat": "purple",
    "type": "tool",
    "desc": "Technique-level test harnesses to validate telemetry and detections",
    "source": "https://github.com/redcanaryco/AtomicTestHarnesses",
    "binaries": null,
    "details": "## Overview\nAtomicTestHarnesses executes focused “harness” implementations of ATT&CK techniques and emits output intended to confirm execution and surface detection-relevant telemetry.\n\n## Use\nRun a single harness for the technique you want to validate, capture endpoint + network telemetry, then check whether your expected detection (or at least the raw evidence) appears.\n\n## Download & setup\n**Windows (PowerShell module):**  \n```powershell\nInstall-Module AtomicTestHarnesses -Scope CurrentUser\nImport-Module AtomicTestHarnesses\n```\n**macOS/Linux (Python harnesses):** clone the repo and follow the POSIX docs in `posix/`:\n```bash\ngit clone https://github.com/redcanaryco/AtomicTestHarnesses.git\n```\n\n## Notes\nPrefer running in a lab, and treat harnesses like test code: pin versions, document commands used, and store the resulting logs so you can regression-test detections later.",
    "tags": [
      "web",
      "network",
      "detection"
    ]
  },
  {
    "name": "MITRE Engenuity Center for Threat-Informed Defense",
    "url": "https://ctid.mitre.org/",
    "website": "https://ctid.mitre.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Community projects for threat-informed defense (methods, datasets, mappings)",
    "source": "https://github.com/center-for-threat-informed-defense",
    "binaries": null,
    "details": "## Overview\nCTID is a hub of open, community-driven projects that turn ATT&CK and adversary knowledge into practical defensive engineering artifacts.\n\n## Use\nUse CTID projects as “building blocks”: pick a method (e.g., adversary emulation), ingest any provided mappings or datasets, then measure improvements by rerunning the same scenario after tuning logging/detections.\n\n## Setup\nMost deliverables are in GitHub repos—clone the specific project you need and follow its README for structure, prerequisites, and export formats.\n\n## Notes\nCTID content is most valuable when you connect it to your own environment: map techniques to your logs, then to detections, then to response playbooks.",
    "tags": [
      "reference",
      "monitoring"
    ]
  },
  {
    "name": "Open Threat Research Forge (OTRF) resources",
    "url": "https://blog.openthreatresearch.com/",
    "website": "https://blog.openthreatresearch.com/",
    "cat": "purple",
    "type": "reference",
    "desc": "Open detection engineering research and building blocks (OSSEM, HELK, playbooks)",
    "source": "https://github.com/OTRF",
    "binaries": null,
    "details": "## Overview\nOTRF publishes practical detection engineering work: logging schemas, hunting playbooks, and research-oriented projects you can reuse in purple-team pipelines.\n\n## Use\nTreat these resources as “recipes”: replicate the log source + parsing approach, run the associated hunt/detection idea, and record what telemetry and enrichments made it work.\n\n## Setup\nMost items are maintained as separate GitHub projects under the OTRF org—start from the project README, then pin versions and fork if you need environment-specific adaptations.",
    "tags": [
      "reference",
      "detection",
      "monitoring"
    ]
  },
  {
    "name": "AWS CloudTrail Lake / Athena hunting patterns (docs)",
    "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html",
    "website": "https://docs.aws.amazon.com/",
    "cat": "purple",
    "type": "reference",
    "desc": "How to store and query CloudTrail events for investigations and hunts",
    "source": null,
    "binaries": null,
    "details": "## Overview\nCloudTrail Lake lets you store CloudTrail events in an event data store and query them directly (including from the AWS console) for faster investigations and repeatable hunt queries.\n\n## Use\nStart by defining the time range and event types you need, then build queries that answer “who did what, where, and with which role/session”. Once a query is useful, save it as a repeatable hunt artifact and attach expected outputs (fields + examples).\n\n## Setup\nEnable an event data store, ensure you’re ingesting the right event sources (management/data events as needed), then validate with a simple query (e.g., filtering by `eventName` and `userIdentity.arn`). If you also use Athena, align partitions/time windows so queries stay fast and cheap.",
    "tags": [
      "reference",
      "cloud"
    ]
  },
  {
    "name": "ATT&CK-Based Emulation Plans (community)",
    "url": "https://attackevals.github.io/ael/",
    "website": "https://attackevals.github.io/ael/",
    "cat": "purple",
    "type": "reference",
    "desc": "Adversary emulation plans used in ATT&CK Evaluations (reusable scenarios)",
    "source": "https://github.com/attackevals/ael",
    "binaries": null,
    "details": "## Overview\nThe ATT&CK Emulation Library provides end-to-end adversary emulation plans (organized by actor/scenario) that you can use as structured purple-team playbooks.\n\n## Use\nPick one plan, then scope it down to a safe subset of techniques for your lab. As you execute, record: exact commands, prerequisites, expected artifacts, and the detections you expect to fire. The plan structure makes it easier to turn “we tested it” into a repeatable regression test.\n\n## Setup\nClone the repo and work from the actor folders (each includes background + step flow):  \n```bash\ngit clone https://github.com/attackevals/ael.git\n```",
    "tags": [
      "reference",
      "web",
      "training"
    ]
  },
  {
    "name": "OWASP Top 10 Web Application Security (2025)",
    "url": "https://owasp.org/Top10/2025/",
    "website": "https://owasp.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Latest OWASP Top 10 for web application risks",
    "source": "https://github.com/OWASP/Top10",
    "binaries": null,
    "details": "## Overview\nThe OWASP Top 10 (2025) is a widely used baseline for web app risk categories and common failure modes.\n\n## Use\nTurn each category into a **testable checklist** for your apps: identify where the risk could appear in *your* architecture, then define a concrete test (manual, SAST/DAST, or purple-team simulation) plus the logging/detection you expect when it’s exploited or blocked.\n\n## Notes\nUse it for prioritization and coverage tracking, not as a complete threat model. Pair it with system-specific abuse cases and data-flow analysis.",
    "tags": [
      "reference",
      "web",
      "detection"
    ]
  },
  {
    "name": "OWASP API Security Top 10 (2023)",
    "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    "website": "https://owasp.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Top API security risks (2023 edition)",
    "source": "https://github.com/OWASP/API-Security",
    "binaries": null,
    "details": "## Overview\nOWASP API Security Top 10 (2023) focuses on API-specific failure modes (authorization, inventory, consumption of third-party APIs, and more).\n\n## Use\nFor each API risk, map it to your endpoints and auth model, then build a small “abuse test” (e.g., object-level access, mass assignment, rate-limit bypass). In purple-team terms, you’re validating both **preventive controls** (authz, schema validation) and **detective controls** (audit trails that let you reconstruct the call chain).\n\n## Notes\nThe fastest win is often improving API inventory + logging consistency (request identity, object identifiers, outcome codes, and latency).",
    "tags": [
      "reference",
      "monitoring",
      "framework"
    ]
  },
  {
    "name": "OWASP Mobile Top 10 (2024)",
    "url": "https://owasp.org/www-project-mobile-top-10/",
    "website": "https://owasp.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Top mobile application security risks (2024 release)",
    "source": "https://github.com/OWASP/www-project-mobile-top-10",
    "binaries": null,
    "details": "## Overview\nOWASP Mobile Top 10 (2024) summarizes common mobile-app risk patterns across platform misuse, storage, transport, and backend interaction.\n\n## Use\nTranslate categories into concrete mobile tests: verify what’s stored on-device (and how), how auth tokens are protected, what traffic is exposed, and whether jailbreak/root or instrumentation changes security behavior. For purple teaming, pair findings with telemetry expectations on the backend (API logs, fraud signals, device posture).\n\n## Notes\nMobile issues often “surface” in the backend. Treat mobile + API as one system when designing detections.",
    "tags": [
      "reference",
      "monitoring",
      "mobile"
    ]
  },
  {
    "name": "OWASP Top 10 for LLM Applications (2025)",
    "url": "https://genai.owasp.org/llm-top-10/",
    "website": "https://genai.owasp.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Top risks and mitigations for LLM/GenAI applications (2025)",
    "source": "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications",
    "binaries": null,
    "details": "## Overview\nThe OWASP LLM Top 10 (2025) catalogues the most common ways LLM-enabled systems fail (prompt injection, data leakage, insecure output handling, tooling risks, and more).\n\n## Use\nTreat each item as a **design test**: identify where untrusted text can enter (users, web pages, emails, RAG sources), where the model can cause side effects (tools/actions), and what guardrails you have (scoping, allowlists, human-in-the-loop). Then run red-team prompts and tool-misuse scenarios while logging every tool call, decision, and retrieved document.\n\n## Notes\nGood purple-team artifacts here are: a small prompt set, a small tool set, and precise expected logs for “blocked”, “allowed”, and “review required” outcomes.",
    "tags": [
      "reference",
      "web",
      "monitoring"
    ]
  },
  {
    "name": "OWASP Top 10 for Agentic AI Applications (2026)",
    "url": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
    "website": "https://genai.owasp.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Autonomous/agentic AI security risks (ASI Top 10)",
    "source": null,
    "binaries": null,
    "details": "## Overview\nOWASP’s Agentic Applications Top 10 (2026) focuses on risks that emerge when agents can plan multi-step actions, call tools, and operate with autonomy.\n\n## Use\nModel the agent as a system with: *goals → plans → tool calls → side effects*. Then test where attackers can:\n- change the goal/plan via untrusted content,\n- abuse identity/permissions via tool integrations,\n- poison memory/context so failures persist.\n\n## Setup\nUse the downloadable guide to pick one category (e.g., tool misuse), create a minimal agent workflow with real tool permissions, and run a short scenario that tries to force an unsafe tool call. Success criteria is not only “it didn’t do it”, but also “we can explain why from logs”.",
    "tags": [
      "reference",
      "forensics",
      "guide"
    ]
  },
  {
    "name": "OWASP Kubernetes Top 10 (2022)",
    "url": "https://owasp.org/www-project-kubernetes-top-ten/",
    "website": "https://owasp.org/",
    "cat": "purple",
    "type": "reference",
    "desc": "Kubernetes security risks (OWASP Kubernetes Top 10)",
    "source": "https://github.com/OWASP/www-project-kubernetes-top-ten",
    "binaries": null,
    "details": "## Overview\nThe OWASP Kubernetes Top 10 helps prioritize common Kubernetes ecosystem risks across configuration, access control, supply chain, and runtime exposure.\n\n## Use\nTurn items into cluster checks and purple-team scenarios: verify RBAC boundaries, audit logging coverage, admission control policies, image provenance, and how quickly you can detect and contain suspicious pod behavior.\n\n## Setup\nStart with a single cluster baseline: enable audit logs, deploy policy controls (admission), and ensure you can correlate identity (user/service account) to actions. Then test one Top-10 item at a time and record the signals you expect to see.",
    "tags": [
      "reference",
      "monitoring",
      "containers"
    ]
  }
);
