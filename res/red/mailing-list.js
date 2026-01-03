window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "Full Disclosure Mailing List",
    "url": "https://seclists.org/fulldisclosure/",
    "website": "https://seclists.org/fulldisclosure/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "mailing-list",
    "desc": "Public vuln/research discussion list; useful for tracking disclosures, PoCs, and historical context.",
    "details": "## Overview\nFull Disclosure is a long-running public list. Practically, it’s useful as (1) a near-real-time stream of disclosures/PoCs and (2) an archive you can mine for older endpoints, affected versions, and researcher writeups.\n\n## How to follow it\nUse the Seclists web archive for browsing/searching and the RSS feed for monitoring.\nRSS: https://seclists.org/rss/fulldisclosure.rss\nIf you need to subscribe/post, the list info page is: https://nmap.org/mailman/listinfo/fulldisclosure\n\n## How it helps (practical)\nFor authorized work, it’s a good input for “what should we test next”: filter by vendor/product keywords, pull references to advisories/CVEs/PoCs, then translate posts into test cases and patch-verification checks. The archive is also handy to validate timelines and find older technical details that disappear from vendor pages.\n\n## Alternatives\nVendor advisories, CERT/CSIRT feeds, CVE/NVD (slower but structured)."
  },
  {
    "name": "Bugtraq (historical)",
    "url": "https://seclists.org/bugtraq/",
    "website": "https://seclists.org/bugtraq/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "mailing-list",
    "desc": "Historic vulnerability list; valuable mainly as an archive for research and timeline reconstruction.",
    "details": "## Overview\nBugtraq is best treated as a historical dataset: older vulns, exploit techniques, vendor responses, and the evolution of mitigations are all searchable via the Seclists archive.\n\n## How to use it\nBrowse by month/thread/author when you’re doing retroactive analysis (e.g., validating when a class of bugs was first discussed) or when modern advisories omit details. For monitoring, the RSS feed exists but the list is largely historical.\nRSS: https://seclists.org/rss/bugtraq.rss\n\n## Alternatives\nFull Disclosure for newer discussions; vendor advisories and CVE/NVD for structured tracking."
  }
);
