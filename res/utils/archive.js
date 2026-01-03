window.CYBER_RESOURCES_UTILS = window.CYBER_RESOURCES_UTILS || [];
window.CYBER_RESOURCES_UTILS.push(
  {
    "name": "Cybersecurity Map (Awesome Security index)",
    "url": "https://github.com/sbilly/awesome-security",
    "website": null,
    "source": "https://github.com/sbilly/awesome-security",
    "binaries": null,
    "cat": "utils",
    "type": "archive",
    "desc": "Huge curated index of security resources (start point)",
    "details": "## Use\nTreat it as a discovery catalog: find 1–2 high-quality items per domain (web, cloud, IR, detection), then move them into your team’s own “golden set” so you don’t depend on a giant list.\n\n## Quick pull + local search\n```bash\nwget -c https://github.com/sbilly/awesome-security/archive/refs/heads/master.zip -O awesome-security.zip && unzip -q awesome-security.zip && rm -f awesome-security.zip\nrg -n \"(incident response|detection|threat hunting|cloud|mobile|reverse)\" awesome-security-master/README.md\n```\n\n## Tip\nPin your curated subset with owners and review cadence; most value comes from keeping *your* shortlist current.",
    "tags": [
      "archive",
      "enumeration",
      "web"
    ]
  },
  {
    "name": "Wayback Machine",
    "url": "https://web.archive.org/",
    "website": "https://web.archive.org/",
    "source": "https://github.com/internetarchive/wayback",
    "binaries": null,
    "cat": "utils",
    "type": "archive",
    "desc": "Historical snapshots of public URLs (find legacy pages/assets)",
    "details": "## Use\nUseful for authorized recon/investigations when you need to see how an app looked in the past, recover removed pages, or enumerate old JS/CSS assets that may reveal legacy endpoints.\n\n## Quick use (UI)\nOpen a URL, pick a capture date, then browse. For broad browsing, use a wildcard capture list:\n`https://web.archive.org/web/*/https://example.com/*`\n\n## Programmatic (CDX index)\nGet unique archived URLs for a domain:\n```bash\ncurl -s 'https://web.archive.org/cdx/search/cdx?url=example.com/*&output=txt&fl=original&collapse=urlkey'\n```\nFocus on archived JavaScript (often the fastest way to surface old API routes):\n```bash\ncurl -s 'https://web.archive.org/cdx/search/cdx?url=example.com/*&output=txt&fl=original,mimetype,statuscode&filter=mimetype:application/javascript&filter=statuscode:200&collapse=urlkey'\n```\nFetch a specific archived resource once you have a timestamp:\n```bash\nwget -qO- 'https://web.archive.org/web/<TIMESTAMP>/https://example.com/app.js'\n```\n\n## Save a page (if allowed)\n```bash\ncurl -s 'https://web.archive.org/save/https://example.com/page' > /dev/null\n```\n\n## Caveats\nCaptures can be partial (blocked assets, missing API calls, JS-heavy apps), and robots/takedowns/exclusions can remove snapshots.",
    "tags": [
      "archive",
      "enumeration",
      "web"
    ]
  }
);
