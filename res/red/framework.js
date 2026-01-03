window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "PTES",
    "url": "https://www.pentest-standard.org/index.php/Main_Page",
    "website": "https://www.pentest-standard.org/index.php/Main_Page",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "framework",
    "desc": "Engagement methodology that structures a penetration test from scoping to reporting.",
    "details": "## Overview\nPTES is most useful when you treat it as a checklistable workflow: it gives you the end-to-end phases (pre-engagement → recon → threat modeling → vuln analysis → exploitation → post-exploitation → reporting) so you don’t miss deliverables or forget to document key decisions.\n\n## How to use it in a real engagement\nStart by translating the phases into your own internal runbook: define inputs/outputs for each phase (e.g., scope + ROE signed in pre-engagement, target inventory and hypotheses after recon, prioritized attack paths after threat modeling, evidence-backed findings and remediation in reporting). Keep a single “evidence trail” (timestamps, requests, screenshots/logs, commands, hashes) throughout so reporting is mostly assembly, not reconstruction.\n\n## Notes\nPTES doesn’t replace authorization: pair it with a written scope/ROE, explicit test windows, data-handling rules, and a reporting format your stakeholders can act on.\n\n## Alternatives\nOSSTMM, NIST SP 800-115.",
    "tags": [
      "framework",
      "post-exploitation",
      "exploitation"
    ]
  },
  {
    "name": "OWASP MASVS",
    "url": "https://mas.owasp.org/MASVS/",
    "website": "https://mas.owasp.org/MASVS/",
    "source": "https://github.com/OWASP/masvs",
    "binaries": null,
    "cat": "red",
    "type": "framework",
    "desc": "Mobile app security standard to turn mobile risks into concrete requirements and test coverage.",
    "details": "## Overview\nMASVS is a requirements-focused standard for mobile apps (storage/crypto/auth/network/platform/code/resilience/privacy). It’s most valuable when you use it to define what “secure enough” means for a given app, then prove it with repeatable tests (typically via the OWASP MASTG).\n\n## Practical workflow\nPick the MASVS controls that match your threat model and platform reality, convert them into engineering requirements (what must be true in code/config), then validate them during testing. When you find gaps, report them mapped to the exact control so stakeholders can see impact, expected behavior, and what to fix.\n\n## Getting the documents\nRead online on the MASVS site, or download the official PDFs from the GitHub Releases page.\n\n## Alternatives\nOWASP ASVS (broader app/web baseline), platform/vendor mobile security guidance.",
    "tags": [
      "framework",
      "web",
      "network"
    ]
  }
);
