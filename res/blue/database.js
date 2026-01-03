window.CYBER_RESOURCES_BLUE = window.CYBER_RESOURCES_BLUE || [];
window.CYBER_RESOURCES_BLUE.push(
  {
    "name": "MITRE CWE",
    "url": "https://cwe.mitre.org/",
    "website": "https://cwe.mitre.org/",
    "source": "https://github.com/CWE-CAPEC/CWE-Content-Development-Repository",
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "Canonical taxonomy of software & hardware weakness types (CWE IDs).",
    "details": "## What it is\nCWE (Common Weakness Enumeration) is the standard taxonomy used to name and group weakness types (e.g., CWE-79 XSS, CWE-287 Improper Authentication). It’s ideal for *normalizing* findings coming from different scanners and reviews.\n\n## How to get the data (offline / automation)\nCWE provides downloadable datasets (XML/CSV) from the official downloads page.\n\n### Download latest XML (common for pipelines)\n```bash\nwget -O cwec_latest.xml.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip\nunzip -o cwec_latest.xml.zip\n# produces: cwec_latest.xml\n```\n\n### Download latest CSV (quick analysis in spreadsheets)\n```bash\nwget -O cwec_latest.csv.zip https://cwe.mitre.org/data/csv/cwec_latest.csv.zip\nunzip -o cwec_latest.csv.zip\n# produces: cwec_latest.csv\n```\n\n## How to use it effectively\n### 1) Normalize findings (SAST/DAST/SCA/AppSec reviews)\n- Store CWE IDs alongside each finding.\n- Aggregate by CWE family to avoid “tool-specific naming” fragmentation.\n- Use CWE as the join key when correlating: scanner finding ↔ ticket ↔ remediation guidance.\n\n### 2) Trend analysis that actually helps engineering\n- Build quarterly charts like: “Top CWE by repo / team / service” and “CWE recurrence rate after fix”.\n- Measure *time-to-remediate by CWE* to spot where secure-by-default libraries or patterns are missing.\n\n### 3) Threat modeling + secure design reviews\n- Map components to likely CWE clusters (input handling, authN/authZ, crypto misuse).\n- Use CWE examples and related weaknesses to generate targeted review checklists.\n\n## Operational tips\n- CWE is a *taxonomy*, not a prioritization list. Pair it with context (exposure, exploitability, business impact).\n- If you need a curated “top” list, use CWE Top 25 as a lens—but keep CWE IDs as the system of record.\n\n## Related / alternatives\n- OWASP Top 10 (risk list, not a taxonomy)\n- CAPEC (attack patterns that often exploit CWEs)",
    "tags": [
      "database",
      "exploitation",
      "enumeration"
    ]
  },
  {
    "name": "MITRE CAPEC",
    "url": "https://capec.mitre.org/",
    "website": "https://capec.mitre.org/",
    "source": "https://github.com/mitre/cti",
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "Library of common attack patterns (CAPEC IDs) with links to CWEs and other knowledge bases.",
    "details": "## What it is\nCAPEC (Common Attack Pattern Enumeration and Classification) catalogs attacker behaviors/patterns (e.g., phishing variants, injection patterns). It’s great for moving from “weakness exists” → “how it’s typically exploited”.\n\n## How to get the data\nCAPEC provides official downloads (XML/CSV). MITRE also publishes CAPEC in STIX via the `mitre/cti` repo.\n\n### Download latest CAPEC XML\n```bash\nwget -O capec_latest.xml https://capec.mitre.org/data/xml/capec_latest.xml\n```\n\n### Download latest CAPEC CSV\n```bash\nwget -O capec_latest.csv https://capec.mitre.org/data/csv/capec_latest.csv\n```\n\n### Use STIX (if you already consume ATT&CK via STIX)\n- Source repo: https://github.com/mitre/cti\n- Typical flow:\n  - clone/pull the repo periodically\n  - ingest STIX objects into your graph/knowledge store\n  - link CAPEC ↔ ATT&CK ↔ internal detections/playbooks\n\n## How to use it effectively\n### 1) Threat modeling workshops\n- Start from system assets → likely CAPEC patterns → identify controls and detection points.\n- Translate CAPEC patterns into abuse cases and acceptance tests.\n\n### 2) Detection engineering & response playbooks\n- For a given CAPEC pattern, extract:\n  - prerequisites\n  - typical indicators/artifacts\n  - mitigations\n- Turn those into log requirements, detections (SIEM/EDR), and IR checklists.\n\n### 3) Developer training that sticks\n- Use CAPEC “story form” to teach the attacker workflow, then map to preventive controls (often via CWE links).\n\n## Practical tips\n- CAPEC is best paired with CWE: CAPEC describes *how* attacks happen; CWE describes *what* weakness type enabled it.\n\n## Related / alternatives\n- STRIDE (threat modeling categories)\n- OWASP ASVS/MASVS (requirements-based secure design guidance)",
    "tags": [
      "database",
      "enumeration",
      "web"
    ]
  },
  {
    "name": "CVE Program",
    "url": "https://www.cve.org/",
    "website": "https://www.cve.org/",
    "source": "https://github.com/CVEProject/cvelistV5",
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "Global vulnerability identifier system (CVE IDs) + public CVE records.",
    "details": "## What it is\nCVE provides standardized identifiers (e.g., CVE-2025-XXXX) so scanners, advisories, and ticketing systems can talk about the *same* issue.\n\n## How to get the data\n### Option A: Use the official CVE List repository (bulk/offline)\nThe CVE Program maintains the official CVE List in CVE JSON 5 format.\n\n```bash\ngit clone https://github.com/CVEProject/cvelistV5.git\ncd cvelistV5\n# pull updates later\n# git pull\n```\n\nCommon pipeline pattern:\n- schedule `git pull`\n- ingest changed/added JSON records\n- enrich internally (asset exposure, exploit intel, patch status)\n\n### Option B: Use CVE.org for browsing & references\n- Use CVE.org for the human workflow (reading, triage) and the Git repo for automation.\n\n## How to use it effectively\n### 1) Correlate across tools\nUse CVE IDs as the join key between:\n- scanner output (SAST/DAST/SCA)\n- vendor advisories\n- SBOM/component inventory\n- patch management and SLAs\n\n### 2) Prioritize correctly\nCVE alone is not “priority”. Add:\n- exploit status (KEV), exploit probability (EPSS), and exposure (internet-facing, privilege, blast radius)\n- your asset criticality and compensating controls\n\n### 3) Reporting that leadership understands\n- “% of internet-facing assets with unpatched CVEs older than N days”\n- “Mean time to remediate CVEs by severity *and* exploit status”\n\n## Related / alternatives\n- GHSA (GitHub Security Advisories) for GitHub ecosystem context\n- Vendor advisories (often faster, but less standardized)",
    "tags": [
      "database",
      "exploitation",
      "scanning"
    ]
  },
  {
    "name": "NVD (National Vulnerability Database)",
    "url": "https://nvd.nist.gov/",
    "website": "https://nvd.nist.gov/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "NIST’s enrichment of CVEs (CVSS, CPE/product matching, references) + APIs/feeds.",
    "details": "## What it is\nNVD enriches CVE records with:\n- CVSS vectors/scores\n- CPE matches (product identifiers)\n- references and additional metadata\n\n## How to use (practical workflow)\n### 1) Query via API (best for near-real-time enrichment)\nBase endpoint (CVE API v2):\n- https://services.nvd.nist.gov/rest/json/cves/2.0\n\nExample (by keyword):\n```bash\ncurl 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssl&resultsPerPage=20'\n```\n\nExample (filter by CWE):\n```bash\ncurl 'https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-287&resultsPerPage=20'\n```\n\n### 2) Use NVD data feeds when you want file-based ingestion\nNVD provides JSON feed information here:\n- https://nvd.nist.gov/vuln/data-feeds\n\n(Feeds may be large; treat them as datasets and build incremental ingestion and caching.)\n\n## How to use it effectively\n- Treat CVSS as *severity*, not business risk.\n- Combine with:\n  - exploit intel (KEV)\n  - exploit probability (EPSS)\n  - exposure (internet-facing, reachable path, auth required)\n  - asset criticality and compensating controls\n\n## Operational tips\n- Cache responses and rate-limit your enrichment jobs.\n- Keep a stable internal schema so changing external fields doesn’t break your pipeline.\n\n## Related / alternatives\n- Vendor security bulletins\n- Commercial vulnerability databases (e.g., VulnDB) depending on needs",
    "tags": [
      "database",
      "exploitation",
      "web"
    ]
  },
  {
    "name": "CISA Known Exploited Vulnerabilities (KEV)",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "website": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "source": "https://github.com/cisagov/kev-data",
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "Authoritative list of CVEs confirmed exploited in the wild (high-signal prioritization feed).",
    "details": "## What it is\nCISA KEV is a curated, high-signal catalog of vulnerabilities *known to be exploited*. It’s one of the strongest inputs for patch prioritization.\n\n## How to get the data\n### Option A: Consume the GitHub mirror (easy automation)\n```bash\ngit clone https://github.com/cisagov/kev-data.git\ncd kev-data\n# update later\n# git pull\n```\n\nTypical automation pattern:\n- pull the repo on a schedule\n- ingest the JSON/CSV\n- join KEV CVE IDs against your asset inventory + vuln scan results\n\n### Option B: Use the official website for human triage\n- https://www.cisa.gov/known-exploited-vulnerabilities-catalog\n\n## How to use it effectively\n### 1) Patch prioritization rules that work\n- “KEV on internet-facing assets” = top priority.\n- “KEV + reachable (confirmed by attack path tooling)” = immediate.\n\n### 2) Compensating controls when you can’t patch fast\nFor KEV items with patch delays:\n- WAF/IPS rules (temporary)\n- EDR hardening + specific detection logic\n- network segmentation and exposure reduction\n- monitor exploitation attempts based on vendor/IOC guidance\n\n### 3) Metrics\n- KEV backlog aging\n- KEV remediation SLA adherence per BU/team\n\n## Practical tips\n- Don’t blocklist blindly; validate scope and add expiry/review.\n- Use KEV as a “must-fix” driver, not as your only risk input.",
    "tags": [
      "database",
      "exploitation",
      "scanning"
    ]
  },
  {
    "name": "MalwareBazaar",
    "url": "https://bazaar.abuse.ch/",
    "website": "https://bazaar.abuse.ch/",
    "source": "https://github.com/abusech/MalwareBazaar",
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "Malware sample exchange with metadata + API for research and detection engineering.",
    "details": "## What it is\nMalwareBazaar (abuse.ch) is a malware sample exchange platform. It’s useful for:\n- collecting samples for reverse engineering\n- extracting IOCs for detection/hunting\n- validating YARA rules against real-world samples\n\n## Safe handling (important)\n- Treat all samples as live malware.\n- Use isolated VMs, no shared clipboard, no host mounts, and a controlled network.\n- Prefer detonation sandboxes or offline analysis where possible.\n\n## How to use (API-driven)\n### 1) Get API access\nYou typically need an Auth-Key from abuse.ch auth portal (used across abuse.ch projects).\n\n### 2) Use example scripts / reference implementation\n- GitHub: https://github.com/abusech/MalwareBazaar\n\n### 3) Query the API (basic pattern)\nUse the official API docs for request formats and required parameters:\n- https://bazaar.abuse.ch/api/\n\nIn practice you’ll:\n- query by hash/family/tag\n- retrieve metadata\n- download samples only when needed (and only into a sandboxed environment)\n\n## Defensive use cases\n- Detection engineering: generate and test YARA/Sigma/EDR logic.\n- Threat intel enrichment: pivot by family, signer, hashes, and campaign tags.\n- Incident response: validate if a suspicious hash is known and what it’s associated with.\n\n## Practical tips\n- Keep a local “quarantine” storage with strict permissions.\n- Record provenance (hash, time, source query) for reproducibility.",
    "tags": [
      "database",
      "post-exploitation",
      "credential access"
    ]
  },
  {
    "name": "URLHaus",
    "url": "https://urlhaus.abuse.ch/",
    "website": "https://urlhaus.abuse.ch/",
    "source": "https://github.com/abusech/URLhaus",
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "High-signal feed of malware distribution URLs + bulk API for ingestion.",
    "details": "## What it is\nURLHaus tracks malware distribution URLs and provides APIs/feeds you can ingest into security controls.\n\n## How to use (setup + ingestion)\n### 1) Get an Auth-Key (for API use)\nURLHaus API access commonly uses an abuse.ch Auth-Key.\n\n### 2) Use reference scripts\n- GitHub examples: https://github.com/abusech/URLhaus\n\n### 3) Integrate into controls\nCommon patterns:\n- SIEM enrichment: tag HTTP/DNS events if destination matches URLHaus.\n- Proxy/DNS blocks: push to blocklists with *expiry + revalidation*.\n- Email security: enrich click-time URLs.\n\n## Recommended operational approach\n- **Do not** permanently block everything from the feed.\n- Use a TTL (e.g., 7–30 days) and re-check periodically because infra changes fast.\n- Track false positives and whitelist carefully (with review dates).\n\n## Practical use cases\n- Early warning: alert when endpoints contact known distribution URLs.\n- Hunting: retro-hunt last 30–90 days of proxy/DNS logs for URLHaus hits.\n- IR scoping: identify additional compromised hosts by shared URL contacts.",
    "tags": [
      "database",
      "web",
      "dns"
    ]
  },
  {
    "name": "PhishTank",
    "url": "https://phishtank.org/",
    "website": "https://phishtank.org/",
    "source": null,
    "binaries": null,
    "cat": "blue",
    "type": "database",
    "desc": "Community-maintained phishing URL verification database + API for lookups.",
    "details": "## What it is\nPhishTank provides community-reported phishing URLs and status (verified/unknown). It’s useful as a lightweight reputation/enrichment signal.\n\n## How to use (API lookups)\nPhishTank documents a simple API intended for lookups (commonly via POST):\n- https://phishtank.net/api_info.php\n\nTypical workflow:\n- when a URL is observed in email/proxy logs, query PhishTank\n- if confirmed phishing, tag/alert/block depending on your policy\n\n## Defensive use cases\n- Enrich email telemetry (clicked links) and web proxy logs.\n- Triage suspicious URLs reported by users (“is this known?”).\n- Build detections: repeated hits to known phishing URLs → investigate endpoints and accounts.\n\n## Practical tips\n- Use time-based expiry and revalidation; phishing URLs churn rapidly.\n- Combine with your own detections (brand impersonation, domain age, URL structure heuristics) rather than relying on a single feed.\n\n## Alternatives / complements\n- URLHaus (more malware distribution oriented)\n- Commercial URL reputation feeds (often broader coverage, paid)",
    "tags": [
      "database",
      "web",
      "malware analysis"
    ]
  }
);
