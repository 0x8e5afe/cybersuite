window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
{
    "name": "SecLists",
    "url": "https://github.com/danielmiessler/SecLists",
    "website": null,
    "source": "https://github.com/danielmiessler/SecLists",
    "binaries": null,
    "cat": "red",
    "type": "wordlist",
    "desc": "Wordlists for discovery, fuzzing, creds, and patterns",
    "details": "## Use\nGood default set for web content discovery, parameter fuzzing, username/password auditing (authorized), and pattern matching.\n\n## Download\n```bash\nwget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O seclists.zip && unzip -q seclists.zip && rm -f seclists.zip\n```\n\n## Practical examples\n```bash\n# Web content discovery\nffuf -u https://target/FUZZ -w SecLists-master/Discovery/Web-Content/common.txt -fc 404\n\n# DNS/subdomain brute (only where explicitly allowed)\ngobuster dns -d example.com -w SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt\n```\n\n## Tip\nStart small (e.g., `Discovery/Web-Content/common.txt`) before moving to larger lists to reduce noise and load."
  },
  {
    "name": "Assetnote Wordlists",
    "url": "https://wordlists.assetnote.io/",
    "website": "https://wordlists.assetnote.io/",
    "source": "https://github.com/assetnote/wordlists",
    "binaries": null,
    "cat": "red",
    "type": "wordlist",
    "desc": "Modern content/parameter discovery wordlists",
    "details": "## Use\nStrong for modern web paths/params (often higher signal than generic lists). Useful to quickly surface hidden endpoints, APIs, and common parameter names in authorized testing.\n\n## Download (bulk from CDN)\n```bash\nwget -r --no-parent -R \"index.html*\" -e robots=off https://wordlists-cdn.assetnote.io/data/ -nH\n```\n\n## Practical example\n```bash\n# Parameter discovery (example)\nffuf -u 'https://target/search?FUZZ=test' -w wordlists-cdn.assetnote.io/data/params.txt -fs 0\n```\n\n## Tip\nPrefer their smaller, technology-focused lists first; expand only if you’re missing coverage."
  },
  {
    "name": "FuzzDB",
    "url": "https://github.com/fuzzdb-project/fuzzdb",
    "website": null,
    "source": "https://github.com/fuzzdb-project/fuzzdb",
    "binaries": null,
    "cat": "red",
    "type": "wordlist",
    "desc": "Fuzzing payloads and attack-pattern dictionaries",
    "details": "## Use\nGreat for building negative test cases: inputs that stress parsers/filters and help validate WAF rules, sanitizers, and error handling (authorized).\n\n## Download\n```bash\nwget -c https://github.com/fuzzdb-project/fuzzdb/archive/refs/heads/master.zip -O fuzzdb.zip && unzip -q fuzzdb.zip && rm -f fuzzdb.zip\n```\n\n## Practical example\n```bash\n# Fuzz a parameter with a payload list (authorized)\nffuf -u 'https://target/page?item=FUZZ' -w fuzzdb-master/attack/sql-injection/detect/* -mc all -fs 0\n```\n\n## Tip\nTreat results as “interesting responses,” then manually confirm root cause to avoid false positives."
  },
  {
    "name": "raft wordlists (SecLists RAFT lists)",
    "url": "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content",
    "website": null,
    "source": "https://github.com/danielmiessler/SecLists",
    "binaries": null,
    "cat": "red",
    "type": "wordlist",
    "desc": "High-signal web paths/files/directories lists",
    "details": "## Use\nCommonly used for web content discovery (directories/files). The RAFT lists are a solid middle ground between “too small” and “too noisy.”\n\n## Download (direct file)\n```bash\nwget -O raft-medium-directories.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt\n```\n\n## Practical example\n```bash\nferoxbuster -u https://target -w raft-medium-directories.txt -x php,txt,html\n```\n\n## Tip\nIf you’re getting lots of 403s/redirects, tune filters (`-fc`, `-fr`, `-fs`) and normalize trailing slashes."
  },
  {
    "name": "Probable Wordlists",
    "url": "https://github.com/berzerk0/Probable-Wordlists",
    "website": null,
    "source": "https://github.com/berzerk0/Probable-Wordlists",
    "binaries": null,
    "cat": "red",
    "type": "wordlist",
    "desc": "Password lists sorted by likelihood (offline auditing)",
    "details": "## Use\nDesigned for offline password audits (authorized hashes only). Because entries are ordered by likelihood, you often get faster coverage than alphabetical lists.\n\n## Download\n```bash\nwget -c https://github.com/berzerk0/Probable-Wordlists/archive/refs/heads/master.zip -O probable.zip && unzip -q probable.zip && rm -f probable.zip\n```\n\n## Practical example (offline audit)\n```bash\njohn --wordlist=Probable-Wordlists-master/Real-Passwords/*.txt hashes.txt\n```\n\n## Tip\nUse it to report patterns (e.g., common bases + mangling) and drive policy improvements (MFA, banned-password lists, password managers)."
  },
  {
    "name": "CrackStation wordlist",
    "url": "https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm",
    "website": "https://crackstation.net/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "wordlist",
    "desc": "Large password dictionary for offline audits",
    "details": "## Use\nUseful for offline password strength audits (authorized). It’s huge, so it’s best for longer-running checks or when you need broad coverage.\n\n## Download (HTTP mirror)\n```bash\nwget -O crackstation.txt.gz https://crackstation.net/files/crackstation.txt.gz\n```\n\n## Verify (recommended)\nCompare against the publisher’s checksum before using:\n```bash\necho 'a6dc17d27d0a34f57c989741acdd485b8aee45a6e9796daf8c9435370dc61612  crackstation.txt.gz' | sha256sum -c -\n```\n\n## Tip\nBecause it contains leaked passwords, store it appropriately (disk encryption/access controls) and follow your org’s data-handling policy."
  }
);
