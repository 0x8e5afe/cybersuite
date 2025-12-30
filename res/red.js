window.CYBER_RESOURCES_RED = [
  {
    "name": "OWASP Web Security Testing Guide (WSTG)",
    "url": "https://owasp.org/www-project-web-security-testing-guide/",
    "cat": "red",
    "type": "guide",
    "desc": "Comprehensive web testing methodology",
    "details": "## Overview\nOWASP WSTG is a detailed guide for planning and executing web application security testing.\n\n## How to use it (authorized testing)\nUse it as a checklist: map your scope to modules (auth, session, input validation), then capture evidence and remediation guidance.\n\n## Alternatives\n- PTES (broader pentest standard)\n- NIST SP 800-115"
  },
  {
    "name": "PTES",
    "url": "http://www.pentest-standard.org/",
    "cat": "red",
    "type": "framework",
    "desc": "Penetration Testing Execution Standard",
    "details": "## Overview\nPTES describes phases of a penetration test from pre-engagement through reporting.\n\n## Notes\n- Pair with written rules of engagement and legal authorization.\n\n## Alternatives\n- OSSTMM\n- NIST SP 800-115"
  },
  {
    "name": "NIST SP 800-115",
    "url": "https://csrc.nist.gov/publications/detail/sp/800-115/final",
    "cat": "red",
    "type": "guide",
    "desc": "Technical guide to information security testing",
    "details": "## Overview\nNIST 800-115 provides guidance on planning and conducting technical security assessments.\n\n## Alternatives\n- PTES\n- OWASP WSTG"
  },
  {
    "name": "GTFOBins",
    "url": "https://gtfobins.github.io/",
    "cat": "red",
    "type": "reference",
    "desc": "Unix binaries for privilege escalation techniques",
    "details": "## Overview\nGTFOBins documents how common Unix binaries can be abused in misconfigurations (e.g., sudo rules) during authorized assessments.\n\n## Defensive angle\nUse it to harden sudoers and to write detections for LOL behaviors.\n\n## Alternatives\n- LOLBAS (Windows)\n- WADComs (Windows AD commands)"
  },
  {
    "name": "LOLBAS",
    "url": "https://lolbas-project.github.io/",
    "cat": "red",
    "type": "reference",
    "desc": "Living-off-the-land binaries (Windows)",
    "details": "## Overview\nLOLBAS catalogs Windows binaries, scripts, and libraries that can be abused by attackers and testers.\n\n## Defensive angle\nUse it to prioritize application control rules and detection logic for suspicious usage patterns.\n\n## Alternatives\n- GTFOBins\n- LOLDrivers (vulnerable drivers)"
  },
  {
    "name": "HackTricks",
    "url": "https://book.hacktricks.xyz/",
    "cat": "red",
    "type": "reference",
    "desc": "Offensive security techniques (use responsibly)",
    "details": "## Overview\nHackTricks is a large collection of offensive security notes and methodology. Treat it as a reference during authorized work and for defensive awareness.\n\n## Notes\n- Validate techniques in isolated labs; do not apply to systems you do not own/operate or lack permission to test.\n\n## Alternatives\n- PayloadsAllTheThings\n- PortSwigger Academy"
  },
  {
    "name": "PayloadsAllTheThings",
    "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
    "cat": "red",
    "type": "reference",
    "desc": "Payloads and bypasses (authorized testing)",
    "details": "## Overview\nLarge repository of payloads and notes for many vulnerability classes (XSS, SSRF, deserialization, etc.).\n\n## Defensive use\nUse payloads to build regression tests, WAF validation, and unit tests for parsers/filters.\n\n## Alternatives\n- HackTricks\n- OWASP WSTG",
    "source": "https://github.com/swisskyrepo/PayloadsAllTheThings"
  },
  {
    "name": "nmap",
    "url": "https://nmap.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Network discovery and service enumeration",
    "details": "## Overview\nnmap is a staple for discovering hosts and enumerating services during authorized security assessments and for internal asset discovery.\n\n## Example (authorized / lab)\n```bash\n# Scan a private lab subnet for common services\nnmap -sV -O -T3 10.0.0.0/24\n```\n\n## Notes\n- Coordinate with ops; scanning can trigger IDS/IPS and affect fragile services.\n\n## Alternatives\n- rustscan (fast port discovery)\n- masscan (very fast; higher risk of disruption)"
  },
  {
    "name": "masscan",
    "url": "https://github.com/robertdavidgraham/masscan",
    "cat": "red",
    "type": "tool",
    "desc": "High-speed port scanner",
    "details": "## Overview\nmasscan is designed for extremely fast scanning. Use carefully and only with explicit authorization and rate limits.\n\n## Example (rate-limited, authorized)\n```bash\nmasscan 10.0.0.0/24 -p80,443 --rate 1000\n```\n\n## Alternatives\n- nmap (richer service detection)\n- rustscan",
    "source": "https://github.com/robertdavidgraham/masscan"
  },
  {
    "name": "rustscan",
    "url": "https://github.com/RustScan/RustScan",
    "cat": "red",
    "type": "tool",
    "desc": "Fast port scanner with nmap integration",
    "details": "## Overview\nrustscan rapidly discovers open ports and can hand them to nmap for deeper enumeration.\n\n## Example (authorized)\n```bash\nrustscan -a 10.0.0.5 -- -sV\n```\n\n## Alternatives\n- nmap\n- masscan",
    "source": "https://github.com/RustScan/RustScan"
  },
  {
    "name": "amass",
    "url": "https://github.com/owasp-amass/amass",
    "cat": "red",
    "type": "tool",
    "desc": "Attack surface mapping and DNS enumeration",
    "details": "## Overview\nOWASP Amass performs subdomain enumeration and maps relationships using DNS/OSINT sources. Use within scope.\n\n## Example (authorized recon for your domain)\n```bash\namass enum -d example.com -o amass.txt\n```\n\n## Alternatives\n- subfinder\n- assetfinder",
    "source": "https://github.com/owasp-amass/amass"
  },
  {
    "name": "subfinder",
    "url": "https://github.com/projectdiscovery/subfinder",
    "cat": "red",
    "type": "tool",
    "desc": "Fast subdomain enumeration",
    "details": "## Overview\nsubfinder enumerates subdomains using multiple passive sources. Keep within written scope.\n\n## Example\n```bash\nsubfinder -d example.com -silent\n```\n\n## Alternatives\n- amass\n- findomain",
    "source": "https://github.com/projectdiscovery/subfinder"
  },
  {
    "name": "httpx",
    "url": "https://github.com/projectdiscovery/httpx",
    "cat": "red",
    "type": "tool",
    "desc": "HTTP probing and tech fingerprinting",
    "details": "## Overview\nhttpx probes a list of hosts and gathers HTTP metadata (status, titles, tech fingerprints). Useful for inventory and triage.\n\n## Example\n```bash\ncat hosts.txt | httpx -title -status-code -tech-detect -silent\n```\n\n## Alternatives\n- httprobe\n- aquatone",
    "source": "https://github.com/projectdiscovery/httpx"
  },
  {
    "name": "naabu",
    "url": "https://github.com/projectdiscovery/naabu",
    "cat": "red",
    "type": "tool",
    "desc": "Fast port discovery",
    "details": "## Overview\nnaabu performs fast port scanning and is often used to reduce scope before deeper enumeration.\n\n## Example (authorized)\n```bash\nnaabu -host 10.0.0.5 -top-ports 1000\n```\n\n## Alternatives\n- nmap\n- rustscan",
    "source": "https://github.com/projectdiscovery/naabu"
  },
  {
    "name": "nuclei",
    "url": "https://github.com/projectdiscovery/nuclei",
    "cat": "red",
    "type": "tool",
    "desc": "Template-based vulnerability scanning",
    "details": "## Overview\nnuclei runs community and custom templates to detect exposures and misconfigurations. Validate findings before reporting.\n\n## Example (authorized scanning)\n```bash\nnuclei -u https://app.example.com -severity medium,high,critical\n```\n\n## Notes\n- Use conservative rate limits and safe templates; avoid disruptive checks in production without coordination.\n\n## Alternatives\n- OpenVAS/Nessus (broader scanners)\n- ZAP/Burp (interactive testing)",
    "source": "https://github.com/projectdiscovery/nuclei"
  },
  {
    "name": "ffuf",
    "url": "https://github.com/ffuf/ffuf",
    "cat": "red",
    "type": "tool",
    "desc": "Fast web fuzzer and content discovery",
    "details": "## Overview\nffuf fuzzes parameters and discovers content/directories. Use only on systems you are authorized to test.\n\n## Example (directory discovery in a lab)\n```bash\nffuf -u https://example.com/FUZZ -w wordlist.txt -fc 404\n```\n\n## Alternatives\n- gobuster\n- feroxbuster",
    "source": "https://github.com/ffuf/ffuf"
  },
  {
    "name": "gobuster",
    "url": "https://github.com/OJ/gobuster",
    "cat": "red",
    "type": "tool",
    "desc": "Directory/DNS/VHost brute forcing",
    "details": "## Overview\ngobuster brute-forces web directories, DNS subdomains, and virtual hosts with wordlists (authorized usage only).\n\n## Example\n```bash\ngobuster dir -u https://example.com -w common.txt -t 20\n```\n\n## Alternatives\n- ffuf\n- feroxbuster",
    "source": "https://github.com/OJ/gobuster"
  },
  {
    "name": "feroxbuster",
    "url": "https://github.com/epi052/feroxbuster",
    "cat": "red",
    "type": "tool",
    "desc": "Recursive content discovery",
    "details": "## Overview\nferoxbuster performs recursive directory discovery and is useful for mapping a web app’s surface quickly.\n\n## Example\n```bash\nferoxbuster -u https://example.com -w common.txt -x php,txt,html\n```\n\n## Alternatives\n- ffuf\n- dirsearch",
    "source": "https://github.com/epi052/feroxbuster"
  },
  {
    "name": "dirsearch",
    "url": "https://github.com/maurosoria/dirsearch",
    "cat": "red",
    "type": "tool",
    "desc": "Web path brute forcing",
    "details": "## Overview\ndirsearch brute-forces directories and files on web servers with many extensions and tuning options.\n\n## Example\n```bash\npython3 dirsearch.py -u https://example.com -w common.txt -e php,aspx,txt\n```\n\n## Alternatives\n- feroxbuster\n- ffuf",
    "source": "https://github.com/maurosoria/dirsearch"
  },
  {
    "name": "Burp Suite",
    "url": "https://portswigger.net/burp",
    "cat": "red",
    "type": "tool",
    "desc": "Web testing proxy and toolkit",
    "details": "## Overview\nBurp Suite is a web security testing platform (proxy, repeater, intruder, scanner in Pro). Use with authorization.\n\n## Example (safe workflow)\nProxy browser traffic through Burp, mark targets in-scope, use Repeater for manual request replay, and document evidence.\n\n## Alternatives\n- OWASP ZAP (open-source)\n- mitmproxy (scriptable)"
  },
  {
    "name": "OWASP ZAP",
    "url": "https://www.zaproxy.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Open-source web proxy and scanner",
    "details": "## Overview\nZAP is an open-source web proxy with passive/active scanning and automation features.\n\n## Example (automation idea)\nRun ZAP baseline scan in CI against staging to catch obvious misconfigurations and headers issues.\n\n## Alternatives\n- Burp Suite\n- Nikto (basic checks)"
  },
  {
    "name": "mitmproxy",
    "url": "https://mitmproxy.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Scriptable intercepting proxy",
    "details": "## Overview\nmitmproxy is a programmable HTTP(S) proxy useful for testing, debugging, and building repeatable traffic manipulations in authorized environments.\n\n## Example (capture requests to file)\n```bash\nmitmproxy -w flows.mitm\n```\n\n## Alternatives\n- Burp Suite\n- ZAP"
  },
  {
    "name": "sqlmap",
    "url": "https://github.com/sqlmapproject/sqlmap",
    "cat": "red",
    "type": "tool",
    "desc": "SQL injection testing automation",
    "details": "## Overview\nsqlmap automates many SQLi tests. It is powerful; use only with explicit authorization and safe settings.\n\n## Example (non-destructive, authorized)\n```bash\npython3 sqlmap.py -u \"https://app.example.com/item?id=1\" --batch --risk 1 --level 1\n```\n\n## Notes\n- Start with low risk/level; validate manually; avoid production disruption.\n\n## Alternatives\n- Manual testing with Burp/ZAP\n- Commercial DAST",
    "source": "https://github.com/sqlmapproject/sqlmap"
  },
  {
    "name": "nikto",
    "url": "https://github.com/sullo/nikto",
    "cat": "red",
    "type": "tool",
    "desc": "Web server scanner (misconfigurations)",
    "details": "## Overview\nNikto scans web servers for known misconfigurations, default files, and outdated components. Use within scope.\n\n## Example\n```bash\nnikto -h https://app.example.com\n```\n\n## Alternatives\n- ZAP baseline scan\n- Nuclei templates",
    "source": "https://github.com/sullo/nikto"
  },
  {
    "name": "Metasploit Framework",
    "url": "https://github.com/rapid7/metasploit-framework",
    "cat": "red",
    "type": "tool",
    "desc": "Exploit framework (authorized testing only)",
    "details": "## Overview\nMetasploit is a modular framework used in penetration testing labs and authorized engagements for exploitation and post-exploitation simulation.\n\n## Safe use guidance\nPrefer using it in isolated test environments to validate exposures and to generate detection telemetry for defenders.\n\n## Alternatives\n- Caldera (adversary emulation, more defensive-friendly)\n- Manual PoC validation with vendor advisories",
    "source": "https://github.com/rapid7/metasploit-framework"
  },
  {
    "name": "BloodHound",
    "url": "https://github.com/SpecterOps/BloodHound",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory attack path analysis",
    "details": "## Overview\nBloodHound visualizes relationships in Active Directory to identify privilege escalation paths. Use for authorized security assessments and internal hardening.\n\n## Defensive use\nUse it to find misconfigurations (delegations, ACLs) and prioritize remediation of risky paths.\n\n## Alternatives\n- PingCastle (AD health)\n- AD security posture tools (vendor-specific)",
    "source": "https://github.com/SpecterOps/BloodHound"
  },
  {
    "name": "PingCastle",
    "url": "https://www.pingcastle.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory security assessment",
    "details": "## Overview\nPingCastle assesses AD security posture and provides reports useful for remediation planning.\n\n## Alternatives\n- BloodHound (graph/path analysis)\n- Microsoft Defender for Identity"
  },
  {
    "name": "Responder",
    "url": "https://github.com/lgandx/Responder",
    "cat": "red",
    "type": "tool",
    "desc": "LLMNR/NBT-NS/mDNS poisoning (lab/authorized)",
    "details": "## Overview\nResponder can simulate name-resolution poisoning in Windows networks. This is disruptive and risky; use only in controlled labs or explicitly authorized test windows.\n\n## Defensive use\nUse it to validate that LLMNR/NBT-NS are disabled and to ensure detection/containment works.\n\n## Alternatives\n- Inveigh (PowerShell-based)\n- Pure configuration hardening (disable LLMNR/NBT-NS)",
    "source": "https://github.com/lgandx/Responder"
  },
  {
    "name": "Impacket",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Network protocol tooling (lab/authorized)",
    "details": "## Overview\nImpacket provides Python classes and tools for working with network protocols (SMB, Kerberos, etc.). It is dual-use; use only for authorized testing and for defensive research.\n\n## Defensive use\nUse it to reproduce authentication flows in a lab and to generate telemetry for detection engineering.\n\n## Alternatives\n- Samba tooling (for SMB troubleshooting)\n- Native OS utilities + packet captures",
    "source": "https://github.com/fortra/impacket"
  },
  {
    "name": "WiFi Pineapple (concept)",
    "url": "https://shop.hak5.org/products/wifi-pineapple",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless assessment platform (hardware)",
    "details": "## Overview\nHardware platform used in authorized wireless security assessments. Prefer using it in controlled environments.\n\n## Alternatives\n- Aircrack-ng suite (open-source)\n- Native Wi-Fi adapters + monitoring mode"
  },
  {
    "name": "Aircrack-ng",
    "url": "https://www.aircrack-ng.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless auditing suite (authorized only)",
    "details": "## Overview\nAircrack-ng is a suite for Wi-Fi auditing. Wireless testing must have explicit permission and legal authorization.\n\n## Defensive use\nUse it to validate WPA2/WPA3 configurations and to verify monitoring/detection of rogue AP behavior.\n\n## Alternatives\n- Kismet (monitoring)\n- Commercial wireless assessment tools"
  },
  {
    "name": "Kismet",
    "url": "https://www.kismetwireless.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless network detector and sniffer",
    "details": "## Overview\nKismet passively detects wireless networks and devices for inventory and rogue AP detection.\n\n## Alternatives\n- Wireshark (with captures)\n- Vendor wireless IDS"
  },
  {
    "name": "Shodan",
    "url": "https://www.shodan.io/",
    "cat": "red",
    "type": "search",
    "desc": "Internet-connected device search engine",
    "details": "## Overview\nShodan indexes publicly reachable services and banners. Useful for attack surface management and exposure checks for your own assets.\n\n## Notes\n- Treat results as “potential exposure”; validate with controlled checks.\n\n## Alternatives\n- Censys\n- BinaryEdge"
  },
  {
    "name": "Censys",
    "url": "https://search.censys.io/",
    "cat": "red",
    "type": "search",
    "desc": "Internet scanning and asset discovery",
    "details": "## Overview\nCensys provides indexed internet scan data for exposure management and research.\n\n## Alternatives\n- Shodan\n- ZoomEye"
  },
  {
    "name": "FOFA",
    "url": "https://fofa.info/",
    "cat": "red",
    "type": "search",
    "desc": "Internet asset search",
    "details": "## Overview\nFOFA is a search engine for internet-facing assets. Use for authorized asset discovery and risk management.\n\n## Alternatives\n- Shodan\n- Censys"
  },
  {
    "name": "crt.sh",
    "url": "https://crt.sh/",
    "cat": "red",
    "type": "search",
    "desc": "Certificate transparency search",
    "details": "## Overview\ncrt.sh allows searching certificate transparency logs to discover subdomains and issued certificates for domains you own/monitor.\n\n## Example (domain inventory)\nSearch for `%.example.com` to find issued certs that may reveal forgotten hosts.\n\n## Alternatives\n- CertSpotter\n- Amass (integrates CT)"
  },
  {
    "name": "TruffleHog",
    "url": "https://github.com/trufflesecurity/trufflehog",
    "cat": "red",
    "type": "tool",
    "desc": "Secret scanning for repos and files",
    "details": "## Overview\nTruffleHog finds credentials/secrets in git history and other sources. Useful for internal SDLC security.\n\n## Example (repo scan)\n```bash\ntrufflehog git file://./repo --only-verified\n```\n\n## Alternatives\n- Gitleaks\n- GitHub secret scanning",
    "source": "https://github.com/trufflesecurity/trufflehog"
  },
  {
    "name": "Gitleaks",
    "url": "https://github.com/gitleaks/gitleaks",
    "cat": "red",
    "type": "tool",
    "desc": "Secret detection for codebases",
    "details": "## Overview\nGitleaks scans repos and commits for secrets and sensitive patterns; easy to integrate in CI.\n\n## Example\n```bash\ngitleaks detect -s . --redact\n```\n\n## Alternatives\n- TruffleHog\n- Detect-secrets (Yelp)",
    "source": "https://github.com/gitleaks/gitleaks"
  },
  {
    "name": "Semgrep",
    "url": "https://semgrep.dev/",
    "cat": "red",
    "type": "tool",
    "desc": "Lightweight static analysis (SAST)",
    "details": "## Overview\nSemgrep provides fast pattern-based static analysis; great for appsec automation and custom rules.\n\n## Example (scan code)\n```bash\nsemgrep scan --config auto\n```\n\n## Alternatives\n- CodeQL\n- SonarQube"
  },
  {
    "name": "CodeQL",
    "url": "https://codeql.github.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Semantic code analysis and query language",
    "details": "## Overview\nCodeQL enables deep code analysis via a query language and is integrated with GitHub Advanced Security.\n\n## Alternatives\n- Semgrep\n- Commercial SAST"
  },
  {
    "name": "SecLists",
    "url": "https://github.com/danielmiessler/SecLists",
    "cat": "red",
    "type": "wordlist",
    "desc": "Large collection of security testing lists",
    "details": "## Overview\nSecLists is a widely used collection of wordlists for discovery, fuzzing, usernames/passwords, patterns, and more.\n\n## Download\n```bash\n# Option A: clone\ngit clone --depth 1 https://github.com/danielmiessler/SecLists.git\n\n# Option B: zip\nwget -O seclists.zip https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip\nunzip seclists.zip\n```\n\n## Tips\nStart with smaller lists (`Discovery/Web-Content/common.txt`) to reduce noise and load.\n\n## Alternatives\n- assetnote wordlists\n- FuzzDB",
    "source": "https://github.com/danielmiessler/SecLists"
  },
  {
    "name": "Assetnote Wordlists",
    "url": "https://github.com/assetnote/wordlists",
    "cat": "red",
    "type": "wordlist",
    "desc": "Curated content discovery lists",
    "details": "## Overview\nAssetnote wordlists are curated for modern web content discovery (paths, parameters).\n\n## Download\n```bash\ngit clone --depth 1 https://github.com/assetnote/wordlists.git\n```\n\n## Alternatives\n- SecLists\n- raft wordlists",
    "source": "https://github.com/assetnote/wordlists"
  },
  {
    "name": "FuzzDB",
    "url": "https://github.com/fuzzdb-project/fuzzdb",
    "cat": "red",
    "type": "wordlist",
    "desc": "Attack patterns and fuzzing payloads",
    "details": "## Overview\nFuzzDB contains fuzzing patterns and payloads. Use to build test cases for filters and parsers in authorized environments.\n\n## Download\n```bash\ngit clone --depth 1 https://github.com/fuzzdb-project/fuzzdb.git\n```\n\n## Alternatives\n- SecLists\n- PayloadsAllTheThings",
    "source": "https://github.com/fuzzdb-project/fuzzdb"
  },
  {
    "name": "raft wordlists",
    "url": "https://github.com/Averroes/raft",
    "cat": "red",
    "type": "wordlist",
    "desc": "High-quality directory and file lists",
    "details": "## Overview\nraft provides wordlists commonly used for web content discovery (various sizes and extensions).\n\n## Download\n```bash\ngit clone --depth 1 https://github.com/Averroes/raft.git\n```\n\n## Alternatives\n- SecLists Web-Content lists\n- Assetnote wordlists",
    "source": "https://github.com/Averroes/raft"
  },
  {
    "name": "Probable Wordlists",
    "url": "https://github.com/berzerk0/Probable-Wordlists",
    "cat": "red",
    "type": "wordlist",
    "desc": "Password-focused wordlists",
    "details": "## Overview\nProbable Wordlists focuses on password lists and patterns for auditing in authorized contexts.\n\n## Download\n```bash\ngit clone --depth 1 https://github.com/berzerk0/Probable-Wordlists.git\n```\n\n## Alternatives\n- SecLists (Passwords)\n- rockyou (commonly referenced; handle licensing/source carefully)",
    "source": "https://github.com/berzerk0/Probable-Wordlists"
  },
  {
    "name": "PortSwigger Web Security Academy",
    "url": "https://portswigger.net/web-security",
    "cat": "red",
    "type": "training",
    "desc": "Hands-on web security labs",
    "details": "## Overview\nFree, hands-on labs covering modern web vulnerabilities and exploitation concepts in a safe training environment.\n\n## How to use it\nMap labs to OWASP Top 10 or your skill goals and keep notes of root causes + fixes.\n\n## Alternatives\n- Hack The Box Academy\n- PentesterLab"
  },
  {
    "name": "Hack The Box",
    "url": "https://www.hackthebox.com/",
    "cat": "red",
    "type": "training",
    "desc": "Offensive security labs",
    "details": "## Overview\nPlatform for practicing authorized hacking skills in sandboxed environments (boxes, challenges, academy).\n\n## Alternatives\n- TryHackMe\n- VulnHub"
  },
  {
    "name": "TryHackMe",
    "url": "https://tryhackme.com/",
    "cat": "red",
    "type": "training",
    "desc": "Guided security learning paths",
    "details": "## Overview\nTryHackMe offers guided labs for beginners through advanced topics in a controlled environment.\n\n## Alternatives\n- Hack The Box\n- OverTheWire"
  },
  {
    "name": "OverTheWire",
    "url": "https://overthewire.org/wargames/",
    "cat": "red",
    "type": "training",
    "desc": "Wargames for fundamentals",
    "details": "## Overview\nOverTheWire wargames teach fundamentals (Linux, crypto, web) in safe, gamified challenges.\n\n## Alternatives\n- picoCTF\n- Root-Me"
  },
  {
    "name": "picoCTF",
    "url": "https://picoctf.org/",
    "cat": "red",
    "type": "training",
    "desc": "CTF challenges (beginner friendly)",
    "details": "## Overview\npicoCTF provides beginner-friendly CTF challenges to learn security concepts safely.\n\n## Alternatives\n- OverTheWire\n- Root-Me"
  },
  {
    "name": "Awesome Pentest",
    "url": "https://github.com/enaqx/awesome-pentest",
    "cat": "red",
    "type": "reference",
    "desc": "Curated pentesting resources",
    "details": "## Overview\nCollection of tools, papers, and resources for penetration testing across domains.\n\n## Alternatives\n- Awesome Hacking\n- Awesome AppSec",
    "source": "https://github.com/enaqx/awesome-pentest"
  },
  {
    "name": "OWASP Top 10",
    "url": "https://owasp.org/www-project-top-ten/",
    "cat": "red",
    "type": "guide",
    "desc": "Top web application risks",
    "details": "## Overview\nOWASP Top 10 is a high-level list of common web application risks and categories.\n\n## Use it well\nTreat it as a communication tool; use WSTG/ASVS for actionable test and requirement detail.\n\n## Alternatives\n- ASVS (requirements)\n- WSTG (testing guide)"
  },
  {
    "name": "SSRF Bible",
    "url": "https://github.com/jdonsec/AllThingsSSRF",
    "cat": "red",
    "type": "reference",
    "desc": "SSRF techniques and defenses",
    "details": "## Overview\nCollection of SSRF payloads, bypasses, and defensive notes. Use to build secure allowlists, egress controls, and regression tests.\n\n## Alternatives\n- PayloadsAllTheThings SSRF\n- PortSwigger SSRF labs",
    "source": "https://github.com/jdonsec/AllThingsSSRF"
  },
  {
    "name": "theHarvester",
    "url": "https://github.com/laramies/theHarvester",
    "cat": "red",
    "type": "tool",
    "desc": "Email/subdomain/OSINT collection",
    "details": "## Overview\ntheHarvester gathers emails, subdomains and hostnames from public sources for authorized recon and monitoring.\n\n## Example (your org)\n```bash\ntheHarvester -d example.com -b all\n```\n\n## Alternatives\n- Amass (DNS/ASN focus)\n- SpiderFoot (broader OSINT)",
    "source": "https://github.com/laramies/theHarvester"
  },
  {
    "name": "SpiderFoot",
    "url": "https://github.com/smicallef/spiderfoot",
    "cat": "red",
    "type": "tool",
    "desc": "Automated OSINT collection",
    "details": "## Overview\nSpiderFoot automates OSINT collection across many data sources. Keep scans within scope and privacy policies.\n\n## Alternatives\n- theHarvester\n- Maltego (commercial)",
    "source": "https://github.com/smicallef/spiderfoot"
  },
  {
    "name": "sqlfluff",
    "url": "https://github.com/sqlfluff/sqlfluff",
    "cat": "red",
    "type": "tool",
    "desc": "SQL linter/formatter (data security hygiene)",
    "details": "## Overview\nWhile not a security tool per se, consistent SQL formatting and linting helps code review and reduces injection-prone patterns when combined with secure coding practices.\n\n## Alternatives\n- SQLfmt\n- Internal style guides",
    "source": "https://github.com/sqlfluff/sqlfluff"
  },
  {
    "name": "LinPEAS / WinPEAS",
    "url": "https://github.com/peass-ng/PEASS-ng",
    "cat": "red",
    "type": "tool",
    "desc": "Privilege escalation audit scripts (authorized)",
    "details": "## Overview\nPEASS-ng provides enumeration scripts for Linux/Windows/macOS to identify common misconfigurations in authorized assessments.\n\n## Example (lab)\n```bash\n# Run locally and review findings\n./linpeas.sh\n```\n\n## Defensive use\nUse it to baseline hardening gaps and to validate remediation effectiveness.\n\n## Alternatives\n- manual enumeration checklists\n- CIS Benchmarks + auditing",
    "source": "https://github.com/peass-ng/PEASS-ng"
  },
  {
    "name": "pspy",
    "url": "https://github.com/DominicBreuker/pspy",
    "cat": "red",
    "type": "tool",
    "desc": "Monitor processes without root (Linux)",
    "details": "## Overview\npspy monitors process executions to spot scheduled jobs or unexpected activity (useful in lab troubleshooting and authorized assessments).\n\n## Alternatives\n- auditd (requires config/root)\n- Sysdig/Falco (runtime monitoring)",
    "source": "https://github.com/DominicBreuker/pspy"
  },
  {
    "name": "John the Ripper",
    "url": "https://www.openwall.com/john/",
    "cat": "red",
    "type": "tool",
    "desc": "Password audit and recovery",
    "details": "## Overview\nJohn the Ripper is used for offline password auditing and recovery. Use only on password hashes you are authorized to test.\n\n## Example (offline audit)\n```bash\njohn --wordlist=wordlist.txt hashes.txt\n```\n\n## Alternatives\n- hashcat\n- Passphrase policies + MFA (defensive)"
  },
  {
    "name": "hashcat",
    "url": "https://hashcat.net/hashcat/",
    "cat": "red",
    "type": "tool",
    "desc": "GPU password auditing tool",
    "details": "## Overview\nhashcat performs high-performance offline password auditing. Use only on authorized hashes and follow your organization’s policy.\n\n## Example (offline audit concept)\nIdentify the hash mode, then test a curated wordlist + rules; report weak password patterns to improve controls.\n\n## Alternatives\n- John the Ripper\n- Password managers + MFA (preferred defenses)"
  },
  {
    "name": "CrackStation wordlist",
    "url": "https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm",
    "cat": "red",
    "type": "wordlist",
    "desc": "Large password dictionary (terms + passwords)",
    "details": "## Overview\nCrackStation provides a large password dictionary used for offline password strength audits.\n\n## Download\n```bash\n# Follow the page’s distribution method and verify checksums where provided.\n# Keep the file encrypted at rest if policy requires.\n```\n\n## Alternatives\n- SecLists passwords\n- Probable Wordlists"
  },
  {
    "name": "Enum4linux-ng",
    "url": "https://github.com/cddmp/enum4linux-ng",
    "cat": "red",
    "type": "tool",
    "desc": "SMB enumeration helper (authorized)",
    "details": "## Overview\nenum4linux-ng automates SMB enumeration. Use only on in-scope systems with permission.\n\n## Defensive use\nUse results to harden SMB exposure and reduce anonymous info leakage.\n\n## Alternatives\n- smbclient + manual checks\n- Active Directory hardening tools",
    "source": "https://github.com/cddmp/enum4linux-ng"
  },
  {
    "name": "Kerbrute",
    "url": "https://github.com/ropnop/kerbrute",
    "cat": "red",
    "type": "tool",
    "desc": "Kerberos user enumeration (authorized)",
    "details": "## Overview\nkerbrute can test for valid usernames via Kerberos pre-auth behaviors. This is sensitive; use in controlled, authorized tests.\n\n## Defensive use\nValidate that authentication telemetry and rate-limits detect/mitigate enumeration attempts.\n\n## Alternatives\n- Harden auth (MFA, lockout policies)\n- Monitor KDC events",
    "source": "https://github.com/ropnop/kerbrute"
  },
  {
    "name": "Certipy",
    "url": "https://github.com/ly4k/Certipy",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory Certificate Services assessment (authorized)",
    "details": "## Overview\nCertipy assesses AD CS configurations to identify misconfigurations in authorized engagements.\n\n## Defensive use\nUse it to inventory templates and fix dangerous enrollment rights and ESC paths.\n\n## Alternatives\n- AD CS auditing scripts\n- Vendor AD posture tools",
    "source": "https://github.com/ly4k/Certipy"
  },
  {
    "name": "Ghidra",
    "url": "https://ghidra-sre.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse engineering suite",
    "details": "## Overview\nGhidra is a free reverse engineering tool for analyzing binaries, useful for malware analysis and exploit research in a lab.\n\n## Alternatives\n- IDA Free\n- radare2"
  },
  {
    "name": "radare2",
    "url": "https://rada.re/n/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse engineering framework",
    "details": "## Overview\nradare2 is a powerful reverse engineering framework with CLI-first workflows.\n\n## Alternatives\n- Ghidra\n- Cutter (GUI for r2)"
  },
  {
    "name": "Frida",
    "url": "https://frida.re/",
    "cat": "red",
    "type": "tool",
    "desc": "Dynamic instrumentation (mobile/app testing)",
    "details": "## Overview\nFrida injects instrumentation into running processes; commonly used for authorized mobile/app security testing and debugging.\n\n## Notes\n- Use only on apps/devices you own or have permission to test.\n\n## Alternatives\n- LLDB/GDB (debuggers)\n- Objection (Frida-based helper)"
  },
  {
    "name": "MobSF",
    "url": "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
    "cat": "red",
    "type": "tool",
    "desc": "Mobile security testing framework",
    "details": "## Overview\nMobSF automates static/dynamic analysis for Android/iOS apps in controlled environments.\n\n## Alternatives\n- jadx + manual review\n- Frida-based dynamic analysis",
    "source": "https://github.com/MobSF/Mobile-Security-Framework-MobSF"
  },
  {
    "name": "OWASP MASVS",
    "url": "https://owasp.org/www-project-mobile-app-security/",
    "cat": "red",
    "type": "framework",
    "desc": "Mobile App Security Verification Standard",
    "details": "## Overview\nMASVS defines security requirements for mobile apps and includes a testing guide (MSTG).\n\n## Alternatives\n- ASVS (web/general)\n- Platform-specific security guidelines"
  },
  {
    "name": "OWASP MSTG",
    "url": "https://mas.owasp.org/MASTG/",
    "cat": "red",
    "type": "guide",
    "desc": "Mobile Security Testing Guide",
    "details": "## Overview\nMSTG provides detailed methodology for testing mobile applications, including code review and runtime analysis guidance.\n\n## Alternatives\n- Vendor platform guides\n- MASVS checklists"
  },
  {
    "name": "Wayback Machine",
    "url": "https://archive.org/web/",
    "cat": "red",
    "type": "archive",
    "desc": "Historical snapshots of websites",
    "details": "## Overview\nInternet Archive’s Wayback Machine can reveal historical pages, JS files, endpoints, and subdomains for authorized reconnaissance and investigations.\n\n## Alternatives\n- Common Crawl\n- Google cache (limited)"
  },
  {
    "name": "PublicWWW",
    "url": "https://publicwww.com/",
    "cat": "red",
    "type": "search",
    "desc": "Search source code of websites",
    "details": "## Overview\nPublicWWW indexes web page source code; useful for finding exposed keys/patterns in your own properties and third-party dependencies.\n\n## Alternatives\n- GitHub code search\n- Grep.app"
  },
  {
    "name": "Regex101",
    "url": "https://regex101.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Regex tester and debugger",
    "details": "## Overview\nRegex101 helps build and debug regexes with explanations; useful for WAF rules, log parsing, and detections.\n\n## Alternatives\n- RegExr\n- Your language’s regex unit tests"
  },
  {
    "name": "gowitness",
    "url": "https://github.com/sensepost/gowitness",
    "cat": "red",
    "type": "tool",
    "desc": "Screenshot and report web targets",
    "details": "## Overview\ngowitness takes screenshots of web targets and extracts basic metadata for triage (great for internal asset inventories).\n\n## Example (authorized inventory)\n```bash\ngowitness file -f urls.txt\n```\n\n## Alternatives\n- EyeWitness\n- Aquatone",
    "source": "https://github.com/sensepost/gowitness"
  },
  {
    "name": "EyeWitness",
    "url": "https://github.com/FortyNorthSecurity/EyeWitness",
    "cat": "red",
    "type": "tool",
    "desc": "Web target screenshotting and reporting",
    "details": "## Overview\nEyeWitness captures screenshots and generates reports to help triage large sets of web targets (authorized inventories).\n\n## Alternatives\n- gowitness\n- Aquatone",
    "source": "https://github.com/FortyNorthSecurity/EyeWitness"
  },
  {
    "name": "WhatWeb",
    "url": "https://github.com/urbanadventurer/WhatWeb",
    "cat": "red",
    "type": "tool",
    "desc": "Website fingerprinting",
    "details": "## Overview\nWhatWeb fingerprints web technologies to assist asset inventory and risk triage (authorized use).\n\n## Example\n```bash\nwhatweb https://example.com\n```\n\n## Alternatives\n- Wappalyzer\n- httpx tech-detect",
    "source": "https://github.com/urbanadventurer/WhatWeb"
  },
  {
    "name": "testssl.sh",
    "url": "https://testssl.sh/",
    "cat": "red",
    "type": "tool",
    "desc": "TLS/SSL configuration tester",
    "details": "## Overview\ntestssl.sh checks TLS configurations, ciphers, and common misconfigurations. Great for internal hardening audits.\n\n## Example (authorized)\n```bash\n./testssl.sh https://example.com\n```\n\n## Alternatives\n- SSL Labs (online)\n- sslyze"
  },
  {
    "name": "sslyze",
    "url": "https://github.com/nabla-c0d3/sslyze",
    "cat": "red",
    "type": "tool",
    "desc": "Fast TLS configuration scanner",
    "details": "## Overview\nsslyze scans TLS endpoints to identify weak ciphers, protocol versions, and certificate issues.\n\n## Example\n```bash\npython -m sslyze --regular example.com:443\n```\n\n## Alternatives\n- testssl.sh\n- SSL Labs",
    "source": "https://github.com/nabla-c0d3/sslyze"
  },
  {
    "name": "SSH Audit",
    "url": "https://github.com/jtesta/ssh-audit",
    "cat": "red",
    "type": "tool",
    "desc": "SSH server/client configuration audit",
    "details": "## Overview\nssh-audit checks SSH configurations for weak algorithms and best-practice settings.\n\n## Example (authorized hardening check)\n```bash\nssh-audit example.com\n```\n\n## Alternatives\n- Manual sshd_config reviews\n- Vendor hardening guides",
    "source": "https://github.com/jtesta/ssh-audit"
  },
  {
    "name": "OWASP Juice Shop",
    "url": "https://owasp.org/www-project-juice-shop/",
    "cat": "red",
    "type": "training",
    "desc": "Intentionally insecure web app for practice",
    "details": "## Overview\nOWASP Juice Shop is a deliberately vulnerable application for training and awareness in a safe environment.\n\n## Alternatives\n- DVWA\n- WebGoat"
  },
  {
    "name": "DVWA",
    "url": "https://github.com/digininja/DVWA",
    "cat": "red",
    "type": "training",
    "desc": "Damn Vulnerable Web Application",
    "details": "## Overview\nDVWA is a PHP/MySQL web app designed for learning common web vulnerabilities in a controlled lab.\n\n## Alternatives\n- Juice Shop\n- WebGoat",
    "source": "https://github.com/digininja/DVWA"
  },
  {
    "name": "WebGoat",
    "url": "https://owasp.org/www-project-webgoat/",
    "cat": "red",
    "type": "training",
    "desc": "Hands-on insecure web app lessons",
    "details": "## Overview\nWebGoat provides lessons and vulnerable components to learn web security issues safely.\n\n## Alternatives\n- Juice Shop\n- PortSwigger Academy"
  },
  {
    "name": "Caldera",
    "url": "https://github.com/mitre/caldera",
    "cat": "red",
    "type": "tool",
    "desc": "Adversary emulation (use for purple teaming)",
    "details": "## Overview\nMITRE Caldera is an adversary emulation platform used to run ATT&CK-mapped operations in controlled environments to validate detections.\n\n## Notes\n- Use in lab/staging first; coordinate change windows.\n\n## Alternatives\n- Atomic Red Team (smaller tests)\n- Prelude Operator (commercial/community)",
    "source": "https://github.com/mitre/caldera"
  },
  {
    "name": "NetExec (nxc)",
    "url": "https://github.com/Pennyw0rth/NetExec",
    "cat": "red",
    "type": "tool",
    "desc": "SMB/AD assessment framework (authorized)",
    "details": "## Overview\nNetExec is a framework for authorized SMB/AD assessments and auditing. It is dual-use; use only with explicit permission.\n\n## Defensive use\nUse it to validate hardening (SMB signing, credential hygiene) and generate detection telemetry in a lab.\n\n## Alternatives\n- Native admin tools for audits\n- BloodHound (path analysis)",
    "source": "https://github.com/Pennyw0rth/NetExec"
  },
  {
    "name": "CrackMapExec (CME) (legacy)",
    "url": "https://github.com/byt3bl33d3r/CrackMapExec",
    "cat": "red",
    "type": "tool",
    "desc": "SMB/AD post-exploitation framework (authorized)",
    "details": "## Overview\nCrackMapExec is widely referenced for AD assessment workflows. Prefer maintained successors where possible and use only in authorized contexts.\n\n## Alternatives\n- NetExec (actively maintained successor)\n- BloodHound (graph analysis)",
    "source": "https://github.com/byt3bl33d3r/CrackMapExec"
  },
  {
    "name": "evil-winrm",
    "url": "https://github.com/Hackplayers/evil-winrm",
    "cat": "red",
    "type": "tool",
    "desc": "WinRM client for Windows administration (authorized)",
    "details": "## Overview\nevil-winrm is a WinRM client used in authorized assessments. From a defensive perspective, it highlights why securing WinRM and credentials matters.\n\n## Defensive angle\nEnsure WinRM is limited, audited, and protected with strong auth and network controls.\n\n## Alternatives\n- Native PowerShell remoting with proper controls\n- RDP with MFA + conditional access",
    "source": "https://github.com/Hackplayers/evil-winrm"
  },
  {
    "name": "ldapdomaindump",
    "url": "https://github.com/dirkjanm/ldapdomaindump",
    "cat": "red",
    "type": "tool",
    "desc": "Dump AD LDAP info (authorized)",
    "details": "## Overview\nldapdomaindump exports LDAP information for authorized assessments and auditing.\n\n## Defensive use\nValidate that sensitive directory information isn’t broadly readable and that monitoring catches unusual directory queries.\n\n## Alternatives\n- AD administrative reporting tools\n- BloodHound data collection (different view)",
    "source": "https://github.com/dirkjanm/ldapdomaindump"
  },
  {
    "name": "ScoutSuite",
    "url": "https://github.com/nccgroup/ScoutSuite",
    "cat": "red",
    "type": "tool",
    "desc": "Multi-cloud security auditing",
    "details": "## Overview\nScoutSuite audits cloud configurations (AWS/Azure/GCP) and generates reports for posture review—useful for red/purple teams and cloud hardening.\n\n## Alternatives\n- Prowler\n- Cloud provider security posture tools",
    "source": "https://github.com/nccgroup/ScoutSuite"
  },
  {
    "name": "Prowler",
    "url": "https://github.com/prowler-cloud/prowler",
    "cat": "red",
    "type": "tool",
    "desc": "AWS security auditing and checks",
    "details": "## Overview\nProwler runs AWS security checks and best-practice audits. Works well for internal cloud assessment and continuous compliance.\n\n## Alternatives\n- ScoutSuite\n- AWS Security Hub",
    "source": "https://github.com/prowler-cloud/prowler"
  }
];
