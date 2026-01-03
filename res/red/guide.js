window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "OWASP Web Security Testing Guide (WSTG)",
    "url": "https://owasp.org/www-project-web-security-testing-guide/latest/",
    "website": "https://owasp.org/www-project-web-security-testing-guide/latest/",
    "source": "https://github.com/OWASP/wstg",
    "binaries": null,
    "cat": "red",
    "type": "guide",
    "desc": "Web app testing guide to turn scope into repeatable test cases and evidence-driven findings.",
    "details": "## Overview\nWSTG is most useful as an execution playbook: map your app’s features to WSTG scenarios, run them as test cases, and keep evidence consistent across the engagement.\n\n## How to use it (authorized testing)\nTranslate scope into coverage by selecting the relevant sections, then capture reproducible evidence (exact endpoint, requests/responses, prerequisites, impact) and attach a fix-oriented recommendation. Use the WSTG identifiers in notes so coverage and gaps stay explicit.\n\n## Alternatives\nPTES for broader engagement structure; NIST SP 800-115 for assessment planning and process.",
    "tags": [
      "guide",
      "web"
    ]
  },
  {
    "name": "NIST SP 800-115",
    "url": "https://csrc.nist.gov/pubs/sp/800/115/final",
    "website": "https://csrc.nist.gov/pubs/sp/800/115/final",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "guide",
    "desc": "Assessment guide for planning, executing, and reporting technical security testing.",
    "details": "## Overview\nUse it as the process backbone around testing: objectives, scope boundaries, rules, methods, documentation, and how to turn results into actionable mitigations.\n\n## How to use it\nDefine what you’re trying to prove, what’s out of bounds, how data is handled, and what success looks like before execution. During the work, keep activities traceable to your plan and produce a results package that prioritizes risk and remediation over raw findings.\n\n## Alternatives\nPTES for pentest phase structure; OWASP WSTG for deep web-app test procedures.",
    "tags": [
      "guide",
      "web"
    ]
  },
  {
    "name": "OWASP MASTG",
    "url": "https://mas.owasp.org/MASTG/",
    "website": "https://mas.owasp.org/MASTG/",
    "source": "https://github.com/OWASP/mastg",
    "binaries": null,
    "cat": "red",
    "type": "guide",
    "desc": "Mobile app testing guide for Android/iOS covering runtime analysis, code review, and reverse engineering.",
    "details": "## Overview\nMASTG is most effective when you use it to prove specific mobile security claims with repeatable checks across storage, crypto, auth, network, platform APIs, and resilience.\n\n## How to use it\nStart from threat model + requirements (often MASVS), then execute the corresponding MASTG tests and collect artifacts (logs, traces, traffic, PoC steps) so each issue is reproducible and maps cleanly to what must be fixed.\n\n## Alternatives\nMASVS for requirement baselines; vendor platform hardening guidance for OS-specific expectations.",
    "tags": [
      "guide",
      "network",
      "malware analysis"
    ]
  },
  {
    "name": "OWASP AI Testing Guide (AITG)",
    "url": "https://owasp.org/www-project-ai-testing-guide/",
    "website": "https://owasp.org/www-project-ai-testing-guide/",
    "source": "https://github.com/OWASP/www-project-ai-testing-guide",
    "binaries": null,
    "cat": "red",
    "type": "guide",
    "desc": "Methodology for testing AI/LLM systems for trustworthiness: security, privacy, robustness, and misuse risks.",
    "details": "## Overview\nAITG focuses on repeatable testing of AI systems beyond classic AppSec, covering security threats plus broader trustworthiness properties that impact real-world safety and reliability.\n\n## How to use it (authorized testing)\nInventory the AI system end-to-end (app layer, model, data, infrastructure), then select the relevant tests and run them like standard test cases with clear preconditions and expected outcomes. Treat outputs as evidence: prompts/inputs, model/config versions, retrieved context, tool actions, logs/traces, and the exact reproduction steps so you can separate model behavior from integration bugs.\n\n## Where it shines\nIt’s especially useful for scoping and reporting AI risks consistently (e.g., prompt injection/jailbreak pathways, leakage routes, unsafe autonomy, drift-related failures) because it gives you a common language and test structure you can map into your engagement runbook.",
    "tags": [
      "guide",
      "framework"
    ]
  }
);
