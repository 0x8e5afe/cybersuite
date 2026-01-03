window.CYBER_RESOURCES_PURPLE = window.CYBER_RESOURCES_PURPLE || [];
window.CYBER_RESOURCES_PURPLE.push(
  {
    "name": "DetectionLab",
    "url": "https://dl-docs.netlify.app/",
    "website": "https://dl-docs.netlify.app/",
    "source": "https://github.com/clong/DetectionLab",
    "binaries": null,
    "cat": "purple",
    "type": "training",
    "desc": "Infrastructure-as-code lab that spins up a Windows AD environment with common logging/security tooling, built for practicing detection engineering and purple-team validation.",
    "details": "A ready-made AD lab so you can generate realistic endpoint/auth telemetry, then iterate on parsing + detections without touching production.\n\n## Setup\nYou provision the lab using IaC (commonly Vagrant/Packer, plus optional Terraform for cloud). Expect to need a hypervisor (e.g., VirtualBox/VMware), enough RAM/CPU, and host networking that supports multiple VMs.\n\nTypical local flow (high level):\n- Install a hypervisor + **Vagrant**.\n- Clone the repo.\n- Choose the lab flavor (Vagrant/Hyper-V/ESXi/Azure/AWS/Proxmox, depending on what you have).\n- Bring it up with the repo’s documented workflow for that platform.\n\n## Use\n1) Pick one ATT&CK technique to emulate (Atomic Red Team / manual steps).\n2) Execute it against the lab hosts.\n3) Verify **visibility first** (logs exist, parsing/fields look right), then **signal** (detections fire with good context).\n4) Save the artifacts you created: the exact command chain, expected logs, and the detection query/rule.\n\n## Practical tips\n- Treat the lab as a regression suite: rerun the same technique after every detection change.\n- Keep snapshots/checkpoints so you can restore quickly.\n- Separate “raw telemetry validation” from “alert logic” so you know which layer failed."
  },
  {
    "name": "Splunk Attack Range",
    "url": "https://attack-range.readthedocs.io/",
    "website": "https://www.splunk.com/",
    "source": "https://github.com/splunk/attack_range",
    "binaries": null,
    "cat": "purple",
    "type": "training",
    "desc": "Automated lab builder + attack simulation framework that provisions instrumented environments and generates telemetry to validate detections (commonly with Splunk, but usable as a general detection testbed).",
    "details": "A repeatable “build → simulate → collect → test detections” pipeline that’s especially useful when you want consistent datasets for CI/CD-style detection engineering.\n\n## Setup (fastest path: Docker)\nAttack Range ships a Docker image you can run locally; you’ll still need cloud credentials if you deploy to AWS/Azure/GCP.\n```bash\ndocker pull splunk/attack_range\ndocker run -it splunk/attack_range\n```\nInside the container, follow the repo docs to configure your target (cloud/local), then run the built-in workflows.\n\n## Use\nCore commands (pattern):\n- Configure: `python attack_range.py configure`\n- Build lab: `python attack_range.py build`\n- Run simulation (example):\n  - `python attack_range.py simulate -e ART -te T1003.001 -t <target>`\n- Dump/replay telemetry for testing pipelines:\n  - `python attack_range.py dump ...`\n  - `python attack_range.py replay ...`\n\n## What to focus on during purple-team work\n- Pin a small technique set and run it repeatedly.\n- Validate field normalization (ECS/OSSEM/CIM) before blaming detection logic.\n- Store the simulation inputs + resulting logs as “golden” test data for future rule changes."
  },
  {
    "name": "Kusto Detective Agency",
    "url": "https://detective.kusto.io/",
    "website": "https://detective.kusto.io/",
    "source": null,
    "binaries": null,
    "cat": "purple",
    "type": "training",
    "desc": "Interactive KQL learning game with investigation-style challenges; great for building hunting skills used in Microsoft Sentinel/Azure Data Explorer/M365 Defender contexts.",
    "details": "A hands-on way to learn KQL by solving cases, which translates directly to faster hunting and better purple-team analysis loops.\n\n## Use\nOpen the site, start a case, and treat each step as an investigation workflow:\n- Start with broad time filters + a single table.\n- Identify the pivot key (account, host, IP, process, correlation id).\n- Narrow, then enrich (joins/lookup) only after you confirm the core signal.\n\n## Why it helps purple teams\nBetter KQL means you can quickly answer: “Did the technique execute?”, “What evidence proves it?”, “What fields do we need to alert reliably?”, and “How do we reduce false positives?”"
  },
  {
    "name": "Detection Engineering notes (Sigma workshop)",
    "url": null,
    "website": null,
    "source": "https://github.com/SigmaHQ/sigma-workshop",
    "binaries": null,
    "cat": "purple",
    "type": "training",
    "desc": "Hands-on materials to learn how to write Sigma rules and translate them into backend queries for different platforms.",
    "details": "A practical path to go from “I understand the behavior” to “I can express it as a portable detection rule” and then generate SIEM-specific queries.\n\n## Setup\n```bash\ngit clone https://github.com/SigmaHQ/sigma-workshop\ncd sigma-workshop\n```\nTo convert Sigma rules you’ll typically also install a Sigma CLI (pySigma-based) and a backend target.\n\n## Use\nWork through the workshop examples, then apply the same process to one behavior you can reproduce in a lab:\n- Write a minimal rule (focus on stable selectors and key fields).\n- Convert to your backend query.\n- Test against known-good telemetry, tune, then document prerequisites (required log source + field mapping).\n\n## Practical tip\nMost “Sigma didn’t work” issues are field/model mismatches. Fix the mapping (ECS/OSSEM/CIM or your pipeline) before rewriting the rule logic."
  }
);
