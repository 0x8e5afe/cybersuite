window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "GTFOBins",
    "url": "https://gtfobins.github.io/",
    "website": "https://gtfobins.github.io/",
    "source": "https://github.com/GTFOBins/GTFOBins.github.io",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Reference for how legit Unix binaries become escalation/privesc primitives under misconfig (sudo/SUID/capabilities).",
    "details": "## Overview\nUse GTFOBins to reason about impact when a binary is available with elevated privileges (sudo rules, SUID/SGID bits, file caps) or when you’re stuck in a constrained shell.\n\n## How to use it safely in practice\nSearch the binary you actually have, then focus on the *execution context* (sudo/SUID/caps/restricted shell) shown on the page. Translate that into concrete controls: tighten sudoers, remove risky SUID bits, reduce file capabilities, and add detections for unusual parent/child process chains around those binaries.\n\n## Defensive value\nIt’s excellent for reviewing hardening changes (“did we just allow a dangerous binary via sudo?”) and for building alerting baselines around living-off-the-land patterns."
  },
  {
    "name": "LOLBAS",
    "url": "https://lolbas-project.github.io/",
    "website": "https://lolbas-project.github.io/",
    "source": "https://github.com/LOLBAS-Project/LOLBAS",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Catalog of Windows LOLBIN/LOLScript abuse patterns to drive prevention (WDAC/AppLocker) and detection.",
    "details": "## Overview\nLOLBAS documents Windows-native binaries, scripts, and libraries that are commonly abused to execute code, download content, proxy execution, or evade controls.\n\n## How to use it safely in practice\nStart from what exists in your fleet (OS version + built-ins), then use LOLBAS entries to design rules: constrain high-risk binaries with WDAC/AppLocker where feasible and add detections based on command-line traits, suspicious parent processes, and unusual network/file behaviors.\n\n## Defensive value\nIt helps prioritize which “allowed by default” components deserve extra monitoring and which ones should be restricted in hardened baselines."
  },
  {
    "name": "HackTricks",
    "url": "https://book.hacktricks.xyz/",
    "website": "https://book.hacktricks.xyz/",
    "source": "https://github.com/HackTricks-wiki/hacktricks",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Large practitioner knowledge base for security testing, useful as a fast refresher and checklist source.",
    "details": "## Overview\nHackTricks is a broad, high-volume reference that’s most useful for quickly turning “we suspect X” into test ideas and validation steps during authorized work, and for defensive awareness.\n\n## How to use it effectively\nTreat it like a jump-start, not a source of truth: pull candidate checks, then validate them against your environment and the upstream docs for the specific technology. For internal/offline use, clone the repository and link the exact pages you relied on inside your engagement notes for repeatability."
  },
  {
    "name": "PayloadsAllTheThings",
    "url": "https://swisskyrepo.github.io/PayloadsAllTheThings/",
    "website": "https://swisskyrepo.github.io/PayloadsAllTheThings/",
    "source": "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Curated payload ideas for many bug classes; useful for building regression tests and validation harnesses (authorized use).",
    "details": "## Overview\nThis repo is best treated as a “pattern library” of inputs that often trigger edge cases across parsers, filters, and protocol handlers.\n\n## How to use it responsibly\nFor assessments, pick payload families that match your app’s technology and data-flow, then turn them into reproducible test cases with clear preconditions and expected outcomes. For defense, reuse payload sets as regression tests to prevent reintroducing the same parsing/filter bugs after fixes.\n\n## Offline use\nClone the GitHub repo and keep a curated subset in your internal testing playbooks so your team uses consistent, reviewable inputs."
  },
  {
    "name": "Awesome Pentest",
    "url": "https://github.com/enaqx/awesome-pentest",
    "website": null,
    "source": "https://github.com/enaqx/awesome-pentest",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Curated index of pentest tools/resources; useful for discovery and choosing fit-for-purpose tooling.",
    "details": "## Overview\nA starting point when you need options fast (e.g., “what tools exist for X?”). It’s most valuable when you treat it as a discovery map, then evaluate candidates against your constraints (OS, licensing, stealth, reporting needs).\n\n## Practical use\nKeep an internal shortlist derived from it (approved tools + versions + install notes) so teams don’t reinvent selection and setup each engagement."
  },
  {
    "name": "SSRF Bible",
    "url": "https://github.com/jdonsec/AllThingsSSRF",
    "website": null,
    "source": "https://github.com/jdonsec/AllThingsSSRF",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "SSRF techniques/edge cases to inform testing and to design strong egress + allowlist defenses.",
    "details": "## Overview\nUseful for enumerating SSRF failure modes (redirect chains, DNS tricks, IP literal formats, metadata targets) and for translating them into defensive requirements.\n\n## How to use it safely\nUse it to build a structured SSRF test matrix for your app’s fetchers (URL preview, webhooks, importers). On defense, derive clear rules: strict URL parsing, network-layer egress controls, hardened allowlists, and logging that records the final resolved destination."
  },
  {
    "name": "GTFOArgs",
    "url": "https://gtfoargs.github.io/",
    "website": "https://gtfoargs.github.io/",
    "source": "https://github.com/GTFOArgs/GTFOArgs.github.io",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Reference for argument-injection primitives when user-controlled args reach command execution paths.",
    "details": "## Overview\nGTFOArgs helps you reason about what happens when a program is called with attacker-influenced arguments (wrappers, cron jobs, CI scripts, web backends calling CLI tools).\n\n## How to use it safely\nStart from your actual execution chain (input → wrapper → exec), then check whether the called program has flags/argument forms that change behavior in dangerous ways. Use findings to harden: stop passing raw user input as args, use safe APIs, enforce strict allowlists, and add tests that confirm injection attempts fail."
  },
  {
    "name": "Exploit Database",
    "url": "https://www.exploit-db.com/",
    "website": "https://www.exploit-db.com/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Public archive of exploits/PoCs; helpful for validating exploit availability and patch priority (authorized use).",
    "details": "## Overview\nExploit-DB is most useful for answering “is there public exploit code for this bug?” and for understanding how issues are exploited in practice.\n\n## Safe, practical use\nUse it to inform risk decisions and patch verification: tie entries back to CVEs, confirm affected versions, and then validate that your mitigations remove the vulnerable condition. Keep strict boundaries around authorization and avoid treating PoCs as production-quality indicators of exploitability."
  },
  {
    "name": "Packet Storm Security",
    "url": "https://packetstormsecurity.com/",
    "website": "https://packetstormsecurity.com/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Long-running security archive for advisories, tools, and PoCs; useful for research and historical lookups.",
    "details": "## Overview\nPacket Storm is valuable as a breadth-heavy archive when you need historical context, alternative writeups, or older PoCs that aren’t easy to find elsewhere.\n\n## Practical use\nTreat it as an input stream for triage and for building internal test cases, then corroborate with vendor advisories and reproducible validation in controlled environments."
  },
  {
    "name": "Red Team Notes",
    "url": "https://www.ired.team/",
    "website": "https://www.ired.team/",
    "source": "https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Practitioner notes on red teaming/AD tradecraft; good for labs, checklists, and defensive awareness.",
    "details": "## Overview\niRed.Team is most useful when you need concise, real-world notes that connect tools, technique intent, and operational gotchas.\n\n## How to use it effectively\nUse it to design lab exercises and controlled validations, then convert what you learn into your own internal runbooks (approved tooling, detection expectations, evidence templates). For offline access, clone the referenced GitHub repo and link specific pages in your engagement documentation so the workflow stays repeatable."
  },
  {
    "name": "The Hacker Recipes",
    "url": "https://www.thehacker.recipes/",
    "website": "https://www.thehacker.recipes/",
    "source": "https://github.com/The-Hacker-Recipes/The-Hacker-Recipes",
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "High-signal offensive playbooks, especially for AD and internal engagements (authorized use).",
    "details": "## Overview\nStrong when you want compact, action-oriented playbooks that explain what to look for and why it matters.\n\n## How to use it safely\nStart from your environment’s reality (AD topology, constraints, logging), then adapt playbooks into a scoped test plan with explicit stop conditions and evidence requirements. If you need offline use, clone the GitHub repo and keep an internal, reviewed subset aligned to your rules of engagement."
  },
  {
    "name": "SANS Offensive Cheat Sheets",
    "url": "https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/",
    "website": "https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Quick-reference command and technique sheets; useful for standardizing team workflows.",
    "details": "## Overview\nBest used as a shared reference during incident response, assessments, and labs when you need accurate syntax fast.\n\n## Practical use\nMirror the specific sheets your team relies on into an internal knowledge base with versioning and context (when to use, prerequisites, and what logs should appear) so it becomes operationally consistent rather than ad-hoc."
  },
  {
    "name": "Kali Linux Tools Documentation",
    "url": "https://www.kali.org/tools/",
    "website": "https://www.kali.org/tools/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "reference",
    "desc": "Official Kali catalog with per-tool pages, usage hints, and install references.",
    "details": "## Overview\nUseful when you need authoritative basics for a tool (what it does, common flags, related docs) and a stable landing page to share with teammates.\n\n## How to use it\nUse the tool pages to confirm names/options and to discover upstream project links. In engagements, capture the exact tool version you used (package version or build) alongside your evidence so results remain reproducible."
  },
  {
    "name": "Parrot OS Security Tools",
    "url": "https://parrotsec.org/",
    "website": "https://parrotsec.org/",
    "source": null,
    "binaries": "https://parrotsec.org/download/",
    "cat": "red",
    "type": "reference",
    "desc": "Debian-based security distro oriented to pentest, privacy, and dev workflows (VM/live/WSL options).",
    "details": "## Overview\nParrot is typically used as a ready-to-go workspace for security testing and research, especially when you want a portable VM/live environment.\n\n## Download/setup (safe baseline)\nUse the official download page to pick an edition and format (ISO/live, VM images, WSL, Docker). Verify checksums/signatures when provided, then run it in a VM for controlled testing and snapshot-based rollback. Keep tools updated via the distro package manager and document versions used per engagement."
  },
  {
    "name": "BlackArch Linux",
    "url": "https://blackarch.org/",
    "website": "https://blackarch.org/",
    "source": "https://github.com/BlackArch/blackarch",
    "binaries": "https://blackarch.org/downloads.html",
    "cat": "red",
    "type": "reference",
    "desc": "Arch-based security distro and repo with large tooling coverage; useful for Arch users and lab environments.",
    "details": "## Overview\nBlackArch is most practical either as a tool repository layered onto an existing Arch install or as a live/installer ISO for lab use.\n\n## Download/setup (safe baseline)\nUse the official downloads page for ISOs/OVAs and follow the official install guidance. Prefer VMs with snapshots for repeatability, verify hashes where available, and keep a minimal toolset installed so your environment stays maintainable. When using the repo-on-Arch approach, document which tool groups/packages you added so the environment can be recreated."
  }
);
