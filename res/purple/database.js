window.CYBER_RESOURCES_PURPLE = window.CYBER_RESOURCES_PURPLE || [];
window.CYBER_RESOURCES_PURPLE.push(
  {
    "name": "ATT&CK STIX Data",
    "url": "https://attack.mitre.org/resources/attack-data-and-tools/",
    "website": "https://attack.mitre.org/",
    "source": "https://github.com/mitre-attack/attack-stix-data",
    "binaries": "https://github.com/mitre-attack/attack-stix-data/releases",
    "cat": "purple",
    "type": "database",
    "desc": "MITRE ATT&CK content published as STIX JSON (machine-readable) for ingestion, querying, and automation (including STIX 2.1 collections).",
    "details": "Use this when you want ATT&CK in a format your tools can **parse and query** (graphs, coverage maps, lookups), not just read on the website.\n\n## Use\nDownload the STIX JSON, ingest it into your pipeline (graph DB / CTI platform / custom scripts), then join it to detections, alerts, and telemetry so you can answer questions like “which techniques do we detect?” and “what data sources support this technique?”.\n\n## Download (quick)\nGrab the “latest” bundles directly (no Git needed):\n```bash\nwget -O enterprise-attack.json \"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json\"\nwget -O mobile-attack.json \"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json\"\nwget -O ics-attack.json \"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json\"\n```\nIf you need pinned versions (repeatability), prefer GitHub **Releases** and store the exact version you used.\n\n## Ingest / query (typical)\n- Parse STIX with a library (commonly `stix2`) and load objects/relationships into a DB (Neo4j, Postgres JSON, Elasticsearch, etc.).\n- Build lookups from technique IDs (e.g., `T1059`) to names, tactics, platforms, mitigations, and detection ideas.\n- Map detections/analytics to techniques to generate coverage reports and prioritize purple-team exercises.\n\nNote: For legacy STIX 2.0 content, MITRE maintains `https://github.com/mitre/cti`.",
    "tags": [
      "database",
      "web",
      "network"
    ]
  },
  {
    "name": "CISA KEV",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "website": "https://www.cisa.gov/",
    "source": null,
    "binaries": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cat": "purple",
    "type": "database",
    "desc": "CISA’s Known Exploited Vulnerabilities (KEV) catalog: vulnerabilities confirmed exploited in the wild, useful for prioritization and validation.",
    "details": "Use KEV as a **high-signal priority list** (what attackers are already exploiting), then validate patch SLAs and detection coverage around it.\n\n## Use\n- Join KEV against your vuln inventory (CVE list from scanners/CMDB) to drive patch queues.\n- Turn KEV entries into purple-team scenarios: emulate the exploitation chain or at least the post-exploitation behaviors and confirm detections/telemetry.\n- Use the due-date/required action fields (when present) to enforce remediation deadlines.\n\n## Download (feed)\n```bash\nwget -O cisa_kev.json \"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\"\n```\nQuick extraction examples:\n```bash\njq -r '.vulnerabilities[].cveID' cisa_kev.json | head\njq -r '.vulnerabilities[] | [.cveID,.vendorProject,.product,.vulnerabilityName] | @tsv' cisa_kev.json | head\n```\n\n## Practical integration\n- Nightly job: download → parse → compare with your open CVEs → open/refresh tickets.\n- Alerting: if an Internet-facing asset has a KEV CVE, page or escalate immediately (combine with asset criticality + exposure).",
    "tags": [
      "database",
      "post-exploitation",
      "exploitation"
    ]
  },
  {
    "name": "Splunk Attack Data (dataset)",
    "url": "https://research.splunk.com/attack_data/",
    "website": "https://research.splunk.com/",
    "source": "https://github.com/splunk/attack_data",
    "binaries": null,
    "cat": "purple",
    "type": "database",
    "desc": "Curated attack telemetry datasets mapped to ATT&CK, designed to test detections and validate pipelines (often stored via Git LFS).",
    "details": "Use these datasets to **replay realistic logs** into a SIEM/lab and verify your detections actually fire (and don’t false-positive) before production.\n\n## Setup (important: Git LFS)\nThis repo stores large datasets with Git LFS; cloning without LFS usually won’t fetch the real log content.\n```bash\n# install git-lfs (example for Debian/Ubuntu)\nsudo apt-get update && sudo apt-get install -y git-lfs\n\ngit lfs install --skip-smudge\ngit clone https://github.com/splunk/attack_data\ncd attack_data\n```\nPull everything (large) or just what you need:\n```bash\n# all datasets (can be very large)\ngit lfs pull\n\n# only one technique folder\ngit lfs pull --include=\"datasets/attack_techniques/T1003.001/\"\n\n# only one specific log file\ngit lfs pull --include=\"datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log\"\n```\n\n## Use (replay into Splunk)\n- Put the dataset path into Splunk ingest (Add Data) or replay via the repo tooling (commonly `replay.py`) to a dedicated index (e.g., `attack_data`).\n- Validate: expected detections trigger, field extractions work, sourcetypes are correct, and correlation searches behave as intended.\n\n## Tips\nStart with a single technique you’re improving (one dataset), replay it end-to-end, then expand coverage iteratively.",
    "tags": [
      "database",
      "web",
      "detection"
    ]
  },
  {
    "name": "Mordor / Security Datasets (OTRF)",
    "url": "https://securitydatasets.com/",
    "website": "https://securitydatasets.com/",
    "source": "https://github.com/OTRF/Security-Datasets",
    "binaries": "https://github.com/OTRF/Security-Datasets/releases",
    "cat": "purple",
    "type": "database",
    "desc": "OTRF’s Security Datasets (formerly widely referred to as “Mordor”): pre-recorded security telemetry and artifacts from attack simulations for detection engineering.",
    "details": "Use these datasets when you need **repeatable, shareable telemetry** to develop detections, test parsers, and run purple-team validation without recreating every attack in a lab.\n\n## Use\nPick a dataset matching your platform/technique, ingest it into your tooling (Splunk/Elastic/etc.), then iterate on detections until you get stable signal and good enrichment.\n\n## Download a specific dataset (fast)\nMany datasets are published as zip files inside the repo; download one directly from GitHub raw:\n```bash\nwget -O dataset.zip \"https://raw.githubusercontent.com/OTRF/Security-Datasets/master/<PATH-TO-DATASET>.zip\"\nunzip -d dataset dataset.zip\n```\nExample (replace with the path you want from the repo tree):\n- `datasets/small/windows/.../*.zip`\n\n## Alternative: clone the repo\n```bash\ngit clone https://github.com/OTRF/Security-Datasets\ncd Security-Datasets\n```\n\n## Practical tip\nTreat datasets as unit tests for detections: keep a “golden” dataset per technique, rerun it after every detection change, and fail the pipeline if expected detections stop matching.",
    "tags": [
      "database",
      "web",
      "detection"
    ]
  }
);
