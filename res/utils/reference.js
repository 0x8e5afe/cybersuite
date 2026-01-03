window.CYBER_RESOURCES_UTILS = window.CYBER_RESOURCES_UTILS || [];
window.CYBER_RESOURCES_UTILS.push(
  {
    "name": "Team Cymru IP to ASN",
    "url": "https://www.team-cymru.com/ip-asn-mapping",
    "website": "https://www.team-cymru.com/ip-asn-mapping",
    "source": null,
    "binaries": null,
    "cat": "utils",
    "type": "reference",
    "desc": "Fast IP→ASN enrichment (DNS/WHOIS)",
    "details": "## Use\nHandy for threat-intel enrichment, scoping (cloud vs ISP), and grouping indicators by network owner.\n\n## Quick lookups\nWHOIS-style query:\n```bash\nwhois -h whois.cymru.com \" -v 1.1.1.1\"\n```\nDNS TXT query (often convenient in scripts):\n```bash\ndig +short TXT 1.1.1.1.origin.asn.cymru.com\n```\nBulk lookups (file of IPs):\n```bash\n# one IP per line in ips.txt\nsed 's/^/ -v /' ips.txt | nc whois.cymru.com 43\n```\n\n## Tip\nUse ASN results to pivot: map multiple IPs to the same ASN to see if activity clusters in one provider/organization.",
    "tags": [
      "reference",
      "post-exploitation",
      "network"
    ]
  },
  {
    "name": "RDAP",
    "url": "https://www.icann.org/rdap",
    "website": "https://www.icann.org/rdap",
    "source": null,
    "binaries": null,
    "cat": "utils",
    "type": "reference",
    "desc": "Structured WHOIS replacement (JSON)",
    "details": "## Use\nRDAP replaces legacy WHOIS with structured responses (JSON), making it easier to automate ownership/enrichment for domains and IPs.\n\n## Practical workflow\nUse RDAP when you want machine-readable registration data in pipelines (ticket enrichment, IR notes, asset inventory).\n\n## Example (HTTP)\nMany registries expose RDAP endpoints; query with JSON accept headers:\n```bash\ncurl -s -H 'Accept: application/rdap+json' 'https://<RDAP-SERVER>/domain/example.com' | jq .\n```\nIP example:\n```bash\ncurl -s -H 'Accept: application/rdap+json' 'https://<RDAP-SERVER>/ip/8.8.8.8' | jq .\n```\n\n## Tip\nPrefer RDAP over scraping WHOIS output: fewer parsing edge-cases and cleaner automation.",
    "tags": [
      "reference",
      "web",
      "network"
    ]
  },
  {
    "name": "tldr pages",
    "url": "https://tldr.sh/",
    "website": "https://tldr.sh/",
    "source": "https://github.com/tldr-pages/tldr",
    "binaries": null,
    "cat": "utils",
    "type": "reference",
    "desc": "Command examples you can copy fast",
    "details": "## Use\nWhen you already know the tool but need the *exact* flag combo under time pressure, tldr is faster than manpages.\n\n## Setup (pick one client)\n```bash\n# Node client\nnpm i -g tldr\n\n# Python client\npython3 -m pip install --user tldr\n\n# Homebrew\nbrew install tldr\n```\n\n## Examples\n```bash\n# Show examples for tar\ntldr tar\n\n# Update local cache (client-dependent)\ntldr --update\n\n# Force platform examples (client-dependent)\ntldr -p linux ssh\n```\n\n## Tip\nKeep it installed on jump boxes/dev VMs; it’s a “muscle-memory refresher” more than a learning resource.",
    "tags": [
      "reference",
      "forensics"
    ]
  },
  {
    "name": "CyberChef Recipes (community)",
    "url": "https://gchq.github.io/CyberChef/",
    "website": "https://gchq.github.io/CyberChef/",
    "source": "https://github.com/mattnotmax/cyberchef-recipes",
    "binaries": null,
    "cat": "utils",
    "type": "reference",
    "desc": "Drop-in recipes for fast decode/triage",
    "details": "## Use\nSpeeds up common transformations during IR/malware triage (decode layers, extract IOCs, normalize data) without rewriting the same pipeline each time.\n\n## How to use\nOpen CyberChef → load/paste input → import a recipe (JSON) → run “Bake” → save output + recipe alongside your case notes for repeatability.\n\n## Quick pull (recipes repo)\n```bash\nwget -c https://github.com/mattnotmax/cyberchef-recipes/archive/refs/heads/master.zip -O cyberchef-recipes.zip && unzip -q cyberchef-recipes.zip && rm -f cyberchef-recipes.zip\n```\n\n## Tip\nBuild a small internal “approved recipes” folder (base64/url/hex, JWT decode, defang/refang, gzip/zlib, regex extract) so analysts reuse the same transformations consistently.",
    "tags": [
      "reference",
      "web",
      "malware analysis"
    ]
  }
);
