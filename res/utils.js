window.CYBER_RESOURCES_UTILS = [
  {
    "name": "CyberChef",
    "url": "https://gchq.github.io/CyberChef/",
    "cat": "utils",
    "type": "tool",
    "desc": "Data transformation and decoding toolbox",
    "details": "## Overview\nCyberChef helps decode/encode/transform data (base64, JWT, hashes, compression, crypto primitives) using “recipes”. Great for IR and CTF-style triage.\n\n## Example (recipe idea)\nChain operations: From Base64 → Gunzip → Extract URLs → Defang → Export indicators.\n\n## Alternatives\n- `jq`/`python` one-liners (more reproducible in code)\n- Online decoders (less flexible)",
    "source": "https://github.com/gchq/CyberChef"
  },
  {
    "name": "jq",
    "url": "https://jqlang.github.io/jq/",
    "cat": "utils",
    "type": "tool",
    "desc": "JSON processor for CLI pipelines",
    "details": "## Overview\n`jq` is essential for manipulating JSON logs and API outputs during investigations.\n\n## Example\n```bash\n# Extract fields from JSON lines\ncat events.jsonl | jq -r '.timestamp, .event_type, .user'\n```\n\n## Alternatives\n- Python (`json` module)\n- Miller (`mlr`) for structured text"
  },
  {
    "name": "yq",
    "url": "https://github.com/mikefarah/yq",
    "cat": "utils",
    "type": "tool",
    "desc": "YAML processor (like jq for YAML)",
    "details": "## Overview\n`yq` transforms YAML (Kubernetes manifests, CI configs) reliably in pipelines.\n\n## Example\n```bash\nyq '.spec.template.spec.containers[].image' deployment.yaml\n```\n\n## Alternatives\n- `python -c` with PyYAML\n- `kubectl` jsonpath (K8s specific)",
    "source": "https://github.com/mikefarah/yq"
  },
  {
    "name": "ripgrep (rg)",
    "url": "https://github.com/BurntSushi/ripgrep",
    "cat": "utils",
    "type": "tool",
    "desc": "Fast recursive search",
    "details": "## Overview\n`rg` is a fast search tool for codebases and forensic triage directories.\n\n## Example\n```bash\nrg -n \"AKIA[0-9A-Z]{16}\" .  # AWS access key pattern (tune for false positives)\n```\n\n## Alternatives\n- `grep -R` (slower)\n- `ag` (the_silver_searcher)",
    "source": "https://github.com/BurntSushi/ripgrep"
  },
  {
    "name": "fzf",
    "url": "https://github.com/junegunn/fzf",
    "cat": "utils",
    "type": "tool",
    "desc": "Fuzzy finder for CLI workflows",
    "details": "## Overview\n`fzf` speeds up navigation through logs, command history, and file lists during investigations.\n\n## Example\n```bash\n# Pick a file interactively\nfind . -type f | fzf\n```\n\n## Alternatives\n- `peco`\n- Shell completion + `ripgrep`",
    "source": "https://github.com/junegunn/fzf"
  },
  {
    "name": "Wireshark",
    "url": "https://www.wireshark.org/",
    "cat": "utils",
    "type": "tool",
    "desc": "Packet analysis GUI",
    "details": "## Overview\nInspect PCAPs, follow streams, and export objects to understand network behaviors.\n\n## Alternatives\n- tshark\n- tcpdump"
  },
  {
    "name": "tshark",
    "url": "https://www.wireshark.org/docs/man-pages/tshark.html",
    "cat": "utils",
    "type": "tool",
    "desc": "Wireshark CLI",
    "details": "## Overview\ntshark provides scripted packet analysis for automation and pipelines.\n\n## Example\n```bash\ntshark -r traffic.pcap -Y \"http.request\" -T fields -e ip.src -e http.host -e http.request.uri\n```\n\n## Alternatives\n- Zeek (higher-level logs)\n- tcpdump (capture focused)"
  },
  {
    "name": "tcpdump",
    "url": "https://www.tcpdump.org/",
    "cat": "utils",
    "type": "tool",
    "desc": "Packet capture CLI",
    "details": "## Overview\ntcpdump is lightweight and ideal for quick captures on servers and network troubleshooting.\n\n## Example\n```bash\nsudo tcpdump -i eth0 -nn -s0 -w capture.pcap 'host 10.0.0.5 and tcp'\n```\n\n## Alternatives\n- Wireshark (GUI)\n- tshark"
  },
  {
    "name": "OpenSSL",
    "url": "https://www.openssl.org/",
    "cat": "utils",
    "type": "tool",
    "desc": "TLS/crypto swiss army knife",
    "details": "## Overview\nOpenSSL is used for certificate inspection, key operations, TLS troubleshooting, and crypto primitives.\n\n## Example (inspect a certificate chain)\n```bash\nopenssl s_client -connect example.com:443 -servername example.com </dev/null\n```\n\n## Alternatives\n- `step` (Smallstep)\n- `cfssl`"
  },
  {
    "name": "JWT.io Debugger",
    "url": "https://jwt.io/",
    "cat": "utils",
    "type": "tool",
    "desc": "JWT inspection and decoding",
    "details": "## Overview\nJWT.io helps decode and inspect JWT headers/payloads (do not paste real secrets in public tools).\n\n## Alternatives\n- CyberChef JWT decode\n- Local scripts (`python-jose`)"
  },
  {
    "name": "Regex101",
    "url": "https://regex101.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Regex builder and debugger",
    "details": "## Overview\nBuild and test regex patterns with explanations; handy for log parsing, detections, and data sanitization.\n\n## Alternatives\n- RegExr\n- Unit tests in your language"
  },
  {
    "name": "crontab.guru",
    "url": "https://crontab.guru/",
    "cat": "utils",
    "type": "tool",
    "desc": "Cron schedule translator",
    "details": "## Overview\nQuickly understand and generate cron expressions when building scheduled jobs (backups, scans, report automation).\n\n## Alternatives\n- `systemd` timers\n- Quartz schedulers"
  },
  {
    "name": "IPinfo",
    "url": "https://ipinfo.io/",
    "cat": "utils",
    "type": "tool",
    "desc": "IP/ASN enrichment",
    "details": "## Overview\nIPinfo provides ASN/org/geolocation data useful for enrichment (validate accuracy).\n\n## Alternatives\n- MaxMind GeoIP\n- Team Cymru WHOIS"
  },
  {
    "name": "Team Cymru IP to ASN",
    "url": "https://www.team-cymru.com/ip-asn-mapping",
    "cat": "utils",
    "type": "reference",
    "desc": "ASN mapping references",
    "details": "## Overview\nTeam Cymru provides IP-to-ASN mapping services and references often used in threat intel enrichment.\n\n## Alternatives\n- RIPEstat\n- IPinfo"
  },
  {
    "name": "RIPEstat",
    "url": "https://stat.ripe.net/",
    "cat": "utils",
    "type": "tool",
    "desc": "Internet resource analysis (BGP, whois, ASNs)",
    "details": "## Overview\nRIPEstat provides BGP routing, whois, and network resource analysis for IPs/ASNs/prefixes.\n\n## Alternatives\n- bgp.he.net\n- Team Cymru mapping"
  },
  {
    "name": "bgp.he.net",
    "url": "https://bgp.he.net/",
    "cat": "utils",
    "type": "tool",
    "desc": "BGP prefix/ASN lookup",
    "details": "## Overview\nHurricane Electric’s BGP toolkit provides ASN/prefix exploration useful for attribution and network investigations.\n\n## Alternatives\n- RIPEstat\n- RouteViews"
  },
  {
    "name": "whois",
    "url": "https://linux.die.net/man/1/whois",
    "cat": "utils",
    "type": "tool",
    "desc": "Domain/IP registration lookup",
    "details": "## Overview\n`whois` provides registration data; note that GDPR/redaction can limit results.\n\n## Alternatives\n- RDAP queries\n- Registrar portals"
  },
  {
    "name": "RDAP",
    "url": "https://www.icann.org/rdap",
    "cat": "utils",
    "type": "reference",
    "desc": "Modern replacement for WHOIS",
    "details": "## Overview\nRDAP is the standardized protocol replacing WHOIS, with structured responses and authentication support.\n\n## Alternatives\n- WHOIS (legacy)\n- Registrar APIs"
  },
  {
    "name": "VirusTotal",
    "url": "https://www.virustotal.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Reputation and metadata enrichment",
    "details": "## Overview\nUse VirusTotal to enrich suspicious files/URLs/domains (avoid uploading sensitive data without policy).\n\n## Alternatives\n- urlscan.io\n- Hybrid Analysis"
  },
  {
    "name": "Hybrid Analysis",
    "url": "https://www.hybrid-analysis.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Malware sandbox and reports",
    "details": "## Overview\nHybrid Analysis executes samples in sandboxes and provides behavioral reports. Handle samples safely.\n\n## Alternatives\n- Any.Run\n- Cuckoo sandbox (self-hosted)"
  },
  {
    "name": "Any.Run",
    "url": "https://any.run/",
    "cat": "utils",
    "type": "tool",
    "desc": "Interactive malware sandbox",
    "details": "## Overview\nInteractive sandbox useful for quick triage and observing behaviors. Be mindful of data sensitivity and terms.\n\n## Alternatives\n- Hybrid Analysis\n- Self-hosted sandboxes"
  },
  {
    "name": "Cuckoo Sandbox",
    "url": "https://github.com/cuckoosandbox/cuckoo",
    "cat": "utils",
    "type": "tool",
    "desc": "Self-hosted malware analysis sandbox",
    "details": "## Overview\nCuckoo is a framework to automate malware analysis in an isolated environment.\n\n## Notes\n- Maintain isolation, snapshots, and safe egress controls.\n\n## Alternatives\n- CAPE sandbox (Cuckoo fork for malware)\n- Commercial sandboxes",
    "source": "https://github.com/cuckoosandbox/cuckoo"
  },
  {
    "name": "CyberGordon (Quick IOC report)",
    "url": "https://cybergordon.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Quick IOC report generation",
    "details": "## Overview\nPaste IOCs (hashes/domains/IPs) to generate enriched reports (avoid sensitive data).\n\n## Alternatives\n- MISP enrichment\n- Local enrichment scripts"
  },
  {
    "name": "Explainshell",
    "url": "https://explainshell.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Explain shell commands",
    "details": "## Overview\nExplainshell helps decode unfamiliar shell commands during incident response reviews and post-mortems.\n\n## Alternatives\n- `man` pages\n- tldr pages"
  },
  {
    "name": "tldr pages",
    "url": "https://tldr.sh/",
    "cat": "utils",
    "type": "reference",
    "desc": "Concise command examples",
    "details": "## Overview\nCommunity-maintained short examples for common CLI tools (useful under pressure).\n\n## Alternatives\n- `man`\n- cheat.sh"
  },
  {
    "name": "cheat.sh",
    "url": "https://cheat.sh/",
    "cat": "utils",
    "type": "tool",
    "desc": "Command-line cheat sheets",
    "details": "## Overview\nQuery cheat sheets from your terminal (languages, commands). Useful when building quick IR scripts.\n\n## Alternatives\n- tldr\n- local notes/wiki"
  },
  {
    "name": "Cybersecurity Map (Awesome lists index)",
    "url": "https://github.com/sbilly/awesome-security",
    "cat": "utils",
    "type": "archive",
    "desc": "Large curated security list",
    "details": "## Overview\nAwesome Security is a broad curated list of security resources across domains.\n\n## Tip\nUse it as a discovery index, then curate your own “golden set” for your team.\n\n## Alternatives\n- Awesome Incident Response\n- Awesome Threat Detection",
    "source": "https://github.com/sbilly/awesome-security"
  },
  {
    "name": "Wayback Machine",
    "url": "https://archive.org/web/",
    "cat": "utils",
    "type": "archive",
    "desc": "Historical web snapshots",
    "details": "## Overview\nArchive.org snapshots are useful for investigating removed content, old JS, and verifying claims about past site states.\n\n## Alternatives\n- Common Crawl\n- Cached copies (limited)"
  },
  {
    "name": "curl",
    "url": "https://curl.se/",
    "cat": "utils",
    "type": "tool",
    "desc": "HTTP client and data transfer",
    "details": "## Overview\n`curl` is ubiquitous for interacting with APIs, reproducing requests, and downloading artifacts during investigations.\n\n## Example\n```bash\ncurl -sS https://api.example.com/status | jq .\n```\n\n## Alternatives\n- httpie (friendlier output)\n- wget (downloads)"
  },
  {
    "name": "httpie",
    "url": "https://httpie.io/",
    "cat": "utils",
    "type": "tool",
    "desc": "Human-friendly HTTP client",
    "details": "## Overview\nhttpie makes API calls readable and is convenient in IR automation scripts.\n\n## Example\n```bash\nhttp GET https://api.example.com/status\n```\n\n## Alternatives\n- curl\n- Postman/Insomnia (GUI)"
  },
  {
    "name": "wget",
    "url": "https://www.gnu.org/software/wget/",
    "cat": "utils",
    "type": "tool",
    "desc": "Downloader for scripts and artifacts",
    "details": "## Overview\n`wget` is useful for mirroring content and fetching resources. Prefer `-O` to control filenames and keep artifacts organized.\n\n## Example\n```bash\nwget -O artifact.bin https://example.com/download.bin\n```\n\n## Alternatives\n- curl -L -o\n- aria2c (parallel)"
  },
  {
    "name": "Wappalyzer",
    "url": "https://www.wappalyzer.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Technology fingerprinting",
    "details": "## Overview\nWappalyzer identifies technologies used by a website; useful for asset inventory and risk triage (verify accuracy).\n\n## Alternatives\n- BuiltWith\n- WhatWeb"
  },
  {
    "name": "BuiltWith",
    "url": "https://builtwith.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "Website technology profiling",
    "details": "## Overview\nBuiltWith provides technology profiling and historical changes for websites.\n\n## Alternatives\n- Wappalyzer\n- httpx tech-detect"
  },
  {
    "name": "DNSDumpster",
    "url": "https://dnsdumpster.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "DNS recon visualization (authorized)",
    "details": "## Overview\nDNSDumpster provides DNS records and basic mapping. Use for your own domains/monitoring and respect privacy policies.\n\n## Alternatives\n- SecurityTrails\n- Amass (CLI)"
  },
  {
    "name": "MXToolbox",
    "url": "https://mxtoolbox.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "DNS/MX/blacklist diagnostics",
    "details": "## Overview\nMXToolbox helps diagnose mail/DNS issues and check common blacklists, useful during phishing incidents and mail delivery issues.\n\n## Alternatives\n- dig + manual checks\n- Vendor email security portals"
  },
  {
    "name": "CyberChef Recipes (community)",
    "url": "https://github.com/mattnotmax/cyberchef-recipes",
    "cat": "utils",
    "type": "reference",
    "desc": "Reusable CyberChef recipes",
    "details": "## Overview\nCommunity recipe collections to speed up decoding common formats and malware triage transformations.\n\n## Alternatives\n- Your internal recipe library\n- Python notebooks",
    "source": "https://github.com/mattnotmax/cyberchef-recipes"
  },
  {
    "name": "ExifTool",
    "url": "https://exiftool.org/",
    "cat": "utils",
    "type": "tool",
    "desc": "Metadata extraction and editing",
    "details": "## Overview\nExifTool reads metadata from many file types (images, documents). Useful for OSINT and DFIR triage.\n\n## Example\n```bash\nexiftool suspicious.jpg\n```\n\n## Alternatives\n- `file` + `strings` (limited)\n- GUI metadata viewers"
  },
  {
    "name": "oletools",
    "url": "https://github.com/decalage2/oletools",
    "cat": "utils",
    "type": "tool",
    "desc": "Analyze suspicious Office documents",
    "details": "## Overview\noletools helps analyze OLE/Office files for macros and embedded objects in phishing triage.\n\n## Example\n```bash\nolevba document.doc\n```\n\n## Alternatives\n- Office sandboxing\n- Commercial email security tooling",
    "source": "https://github.com/decalage2/oletools"
  },
  {
    "name": "pdfid",
    "url": "https://blog.didierstevens.com/programs/pdf-tools/",
    "cat": "utils",
    "type": "tool",
    "desc": "Quick PDF structure inspection",
    "details": "## Overview\npdfid (Didier Stevens) provides a quick look at PDF elements (JS, actions) helpful for triage.\n\n## Alternatives\n- peepdf\n- pdf-parser"
  },
  {
    "name": "7-Zip",
    "url": "https://www.7-zip.org/",
    "cat": "utils",
    "type": "tool",
    "desc": "Archive handling (7z/zip/rar)",
    "details": "## Overview\n7-Zip is useful for handling incident artifacts packaged in archives, including encrypted archives (follow policy).\n\n## Alternatives\n- unzip/tar (built-in)\n- p7zip (Linux)"
  },
  {
    "name": "age",
    "url": "https://github.com/FiloSottile/age",
    "cat": "utils",
    "type": "tool",
    "desc": "Simple file encryption for sharing artifacts",
    "details": "## Overview\n`age` provides modern, simple file encryption—useful for securely sharing incident artifacts internally.\n\n## Example\n```bash\nage -r <RECIPIENT> -o artifact.txt.age artifact.txt\n```\n\n## Alternatives\n- GPG (more complex)\n- S/MIME encrypted email",
    "source": "https://github.com/FiloSottile/age"
  },
  {
    "name": "GnuPG (GPG)",
    "url": "https://gnupg.org/",
    "cat": "utils",
    "type": "tool",
    "desc": "Encryption and signing",
    "details": "## Overview\nGPG supports encryption and signing for secure artifact sharing and integrity verification.\n\n## Alternatives\n- age (simpler)\n- OS-native keychains"
  },
  {
    "name": "Postman",
    "url": "https://www.postman.com/",
    "cat": "utils",
    "type": "tool",
    "desc": "API testing and collections",
    "details": "## Overview\nPostman helps build repeatable API requests and collections—useful for reproducing security findings or IR enrichment calls.\n\n## Alternatives\n- Insomnia\n- httpie/curl + scripts"
  },
  {
    "name": "Insomnia",
    "url": "https://insomnia.rest/",
    "cat": "utils",
    "type": "tool",
    "desc": "API client",
    "details": "## Overview\nInsomnia is a lightweight API client; useful for reproducing HTTP workflows and documenting requests.\n\n## Alternatives\n- Postman\n- httpie/curl"
  },
  {
    "name": "binwalk",
    "url": "https://github.com/ReFirmLabs/binwalk",
    "cat": "utils",
    "type": "tool",
    "desc": "Firmware analysis tool",
    "details": "## Overview\nbinwalk analyzes firmware images for embedded files and signatures; useful in IoT/embedded investigations.\n\n## Alternatives\n- firmware-mod-kit (legacy)\n- manual extraction tools",
    "source": "https://github.com/ReFirmLabs/binwalk"
  },
  {
    "name": "strings",
    "url": "https://linux.die.net/man/1/strings",
    "cat": "utils",
    "type": "tool",
    "desc": "Extract printable strings from binaries",
    "details": "## Overview\n`strings` is a simple but powerful triage tool to spot URLs, paths, and suspicious markers in binaries and documents.\n\n## Example\n```bash\nstrings -n 8 suspicious.bin | head\n```\n\n## Alternatives\n- `floss` for decoded strings\n- Reverse engineering tools (Ghidra)"
  },
  {
    "name": "FLOSS",
    "url": "https://github.com/mandiant/flare-floss",
    "cat": "utils",
    "type": "tool",
    "desc": "Extract obfuscated strings from malware",
    "details": "## Overview\nFLOSS (FLARE) extracts and deobfuscates strings from binaries; useful in malware triage.\n\n## Alternatives\n- capa (capabilities)\n- Ghidra (manual analysis)",
    "source": "https://github.com/mandiant/flare-floss"
  }
];
