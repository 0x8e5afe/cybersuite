window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "Shodan",
    "url": "https://www.shodan.io/",
    "website": "https://www.shodan.io/",
    "source": "https://github.com/achillean/shodan-python",
    "binaries": null,
    "cat": "red",
    "type": "search",
    "desc": "Search engine for internet-exposed services; strong for exposure verification and ASM on assets you own/monitor.",
    "details": "## Overview\nShodan indexes banners and metadata from publicly reachable services. The high-value use case is fast exposure confirmation (what is actually visible from the Internet) and trend monitoring over time.\n\n## Setup (API + CLI)\nCreate an account, copy your API key, then install the official CLI (bundled with the Python library):\n```bash\npip install -U --user shodan\nshodan init YOUR_API_KEY\n```\n\n## Practical use (authorized)\nUse the web UI to iterate on queries, then move repeatable checks into the CLI/API for automation and reporting. A good workflow is: start from your known footprint (domains, IP ranges, ASNs), identify unexpected open services, then validate findings with controlled direct checks because banners can be stale or misleading.\n\nThe filter reference is worth keeping open while you build coverage-focused queries (e.g., net/asn/org/port, SSL-related filters, screenshots where relevant).\n\n## Notes\nTreat results as “potential exposure” until you confirm from your own test vantage point and with your authorization boundaries.\n\n## Alternatives\nCensys, BinaryEdge."
  },
  {
    "name": "Censys",
    "url": "https://search.censys.io/",
    "website": "https://search.censys.io/",
    "source": "https://github.com/censys/cencli",
    "binaries": "https://github.com/censys/cencli/releases",
    "cat": "red",
    "type": "search",
    "desc": "Internet scan index for asset discovery and exposure management; good for inventories and repeatable monitoring.",
    "details": "## Overview\nCensys provides indexed scan data you can use to inventory what’s exposed and to track changes across time. It’s particularly useful when you want repeatable queries that become part of an exposure-monitoring pipeline.\n\n## Setup (CLI binaries)\nDownload the correct `cencli` binary for your OS/arch from the GitHub Releases page, put it on your PATH, then authenticate using your Platform/API access (follow the official Platform CLI documentation for the exact auth flow).\n\n## Practical use\nUse the web UI to build and refine queries, then run the same logic via `cencli` for automation (scheduled inventories, diffing changes, producing CSV/JSON for reports). As with any scan index, use findings to prioritize validation rather than treating them as ground truth.\n\n## Alternatives\nShodan, ZoomEye."
  },
  {
    "name": "FOFA",
    "url": "https://en.fofa.info/",
    "website": "https://en.fofa.info/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "search",
    "desc": "Cyberspace asset search engine; useful for authorized discovery, exposure review, and impact/range analysis.",
    "details": "## Overview\nFOFA is used for internet-facing asset discovery and research. The most productive way to use it is starting from assets you control (domains/IP ranges/org identifiers), then expanding to find forgotten hosts, old deployments, and unexpected exposed services.\n\n## Setup (API)\nIf you need automation, use the official FOFA API and keep your queries versioned as part of your ASM runbooks so the same checks can be repeated during every assessment cycle.\n\n## Practical use\nTreat FOFA as a hypothesis generator: what might be exposed, where, and how it clusters. Follow up with controlled validation (your own scans/requests) before you report anything as confirmed exposure."
  },
  {
    "name": "crt.sh",
    "url": "https://crt.sh/",
    "website": "https://crt.sh/",
    "source": "https://github.com/crtsh/certwatch_db",
    "binaries": null,
    "cat": "red",
    "type": "search",
    "desc": "Certificate Transparency search to enumerate certificate subjects/SANs and spot subdomains for domains you own/monitor.",
    "details": "## Overview\ncrt.sh is a fast way to mine Certificate Transparency logs for names that appear in issued certificates. It’s great for domain inventory because certificates often include hostnames that never made it into DNS docs or asset registers.\n\n## How to use (UI + JSON)\nIn the UI, search for patterns like `%.example.com`. For scripting, crt.sh supports JSON output:\n```bash\ncurl -s 'https://crt.sh/?q=%.example.com&output=json'\n```\nFrom there, extract `name_value`, normalize it (split newlines, lower-case, dedupe), then feed the resulting host list into your validation pipeline (DNS resolution, HTTP(S) probing, ownership checks).\n\n## Notes\nCT data can include internal/test names, re-used certs, and stale entries; use it to expand inventory, not as proof that a host is live."
  },
  {
    "name": "PublicWWW",
    "url": "https://publicwww.com/",
    "website": "https://publicwww.com/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "search",
    "desc": "Search engine for website source code; useful for finding repeated snippets, trackers, or leaked patterns across your web estate.",
    "details": "## Overview\nPublicWWW indexes HTML/JS/CSS so you can search for specific strings across many sites. The practical security use is hunting for things that should not be public or should be consistent: leaked tokens/identifiers, forgotten dev banners, outdated third-party includes, or “this exact snippet exists on these unexpected hosts”.\n\n## How to use it effectively\nStart with safe, high-signal markers you own: unique headers, analytics/telemetry IDs, SSO endpoints, CDN bucket names, build identifiers, or distinctive JS bundle paths. When you find matches, pivot into asset verification (is this actually yours, is it current, does it expose anything sensitive) and then remediate by removing the pattern at the source.\n\n## Notes\nAPI access depends on plan and requires an API key; treat it as an enrichment source that feeds your existing validation and ticketing workflow."
  }
);
