window.CYBER_RESOURCES_RED = window.CYBER_RESOURCES_RED || [];
window.CYBER_RESOURCES_RED.push(
  {
    "name": "PortSwigger Web Security Academy",
    "url": "https://portswigger.net/web-security",
    "website": "https://portswigger.net/web-security",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Free hands-on web vulns labs",
    "details": "## Use\nCreate a free account, pick a topic (e.g., auth, XSS, SSRF), then alternate: read → solve the lab → write a short note with root cause + fix + detection idea.\n\n## Good workflow\nTreat it like a checklist: reproduce, explain impact, then write the remediation pattern you’d apply in real code/reviews.",
    "tags": [
      "training",
      "web",
      "detection"
    ]
  },
  {
    "name": "Hack The Box",
    "url": "https://www.hackthebox.com/",
    "website": "https://www.hackthebox.com/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Sandboxed boxes + challenges",
    "details": "## Use\nPick a path (Academy modules) or a single machine, timebox your attempt, then do a structured writeup: entry point, pivot(s), privesc, and the controls that would have prevented each step.",
    "tags": [
      "training",
      "privilege escalation",
      "post-exploitation"
    ]
  },
  {
    "name": "TryHackMe",
    "url": "https://tryhackme.com/",
    "website": "https://tryhackme.com/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Guided security learning rooms",
    "details": "## Use\nFollow learning paths when you want a guided ramp-up. Keep notes as reusable playbooks (commands are less valuable than: what signal made you try it, what you expected, what you observed).",
    "tags": [
      "training"
    ]
  },
  {
    "name": "OverTheWire",
    "url": "https://overthewire.org/wargames/",
    "website": "https://overthewire.org/wargames/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Fundamentals-first wargames",
    "details": "## Use\nGreat for sharpening Linux/crypto basics. The payoff comes from writing down the general technique (not the answer) and reusing it later: file discovery, permissions, encodings, simple crypto pitfalls.",
    "tags": [
      "training",
      "enumeration"
    ]
  },
  {
    "name": "picoCTF",
    "url": "https://picoctf.org/",
    "website": "https://picoctf.org/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Beginner-friendly CTF practice",
    "details": "## Use\nIdeal for quick reps across categories (web, pwn, rev, crypto). Build a “pattern library” of common moves and what evidence triggered them (error messages, protocol behavior, file format hints).",
    "tags": [
      "training",
      "web"
    ]
  },
  {
    "name": "OWASP Juice Shop",
    "url": "https://owasp.org/www-project-juice-shop/",
    "website": "https://juice-shop.github.io/juice-shop/",
    "source": "https://github.com/juice-shop/juice-shop",
    "binaries": "https://github.com/juice-shop/juice-shop/releases",
    "cat": "red",
    "type": "training",
    "desc": "Modern intentionally vulnerable web app",
    "details": "## Setup (local lab)\nFastest is Docker (recommended for repeatability):\n```bash\ndocker run --rm -p 3000:3000 bkimminich/juice-shop\n```\nThen open `http://localhost:3000`.\n\n## Use\nWork challenge-by-challenge, but write down the *defense*: exact fix, validation test you’d add, and a detection/telemetry idea.",
    "tags": [
      "training",
      "web",
      "detection"
    ]
  },
  {
    "name": "DVWA",
    "url": "https://github.com/digininja/DVWA",
    "website": null,
    "source": "https://github.com/digininja/DVWA",
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Classic vulnerable PHP web app",
    "details": "## Setup (local lab)\nRun it with a local LAMP stack or containers (preferred). In DVWA’s config, set DB creds, then initialize the database from the UI.\n\n## Use\nUse it for fundamentals: input handling, auth/session mistakes, and safe exploitation-to-fix loops (prove, patch, retest).",
    "tags": [
      "training",
      "exploitation",
      "web"
    ]
  },
  {
    "name": "WebGoat",
    "url": "https://owasp.org/www-project-webgoat/",
    "website": "https://owasp.org/www-project-webgoat/",
    "source": "https://github.com/WebGoat/WebGoat",
    "binaries": "https://github.com/WebGoat/WebGoat/releases",
    "cat": "red",
    "type": "training",
    "desc": "Lesson-driven vulnerable web training",
    "details": "## Setup (standalone)\nDownload the latest release JAR, then run it locally:\n```bash\njava -jar webgoat-*.jar\n```\nFollow the console output to open the UI.\n\n## Use\nBecause it’s lesson-based, treat each module like a mini code review: what the anti-pattern is, what the correct pattern is, and how you’d test it in CI.",
    "tags": [
      "training",
      "web"
    ]
  },
  {
    "name": "Offensive Security (OffSec) Training",
    "url": "https://www.offsec.com/courses/",
    "website": "https://www.offsec.com/",
    "source": null,
    "binaries": null,
    "cat": "red",
    "type": "training",
    "desc": "Professional pentest training + certs",
    "details": "## Use\nPick a course that matches your job tasks (web, internal AD, evasion, etc.). Get the most value by running it like a project: weekly goals, short retros, and a “what would I automate/monitor” note for every technique you learn.",
    "tags": [
      "training",
      "web"
    ]
  }
);
