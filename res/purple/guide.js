window.CYBER_RESOURCES_PURPLE = window.CYBER_RESOURCES_PURPLE || [];
window.CYBER_RESOURCES_PURPLE.push(
  {
    "name": "SANS: Purple Team Exercise guidance",
    "url": "https://www.sans.org/blog/building-internal-red-team-go-purple-first/",
    "website": "https://www.sans.org/",
    "source": null,
    "binaries": null,
    "cat": "purple",
    "type": "guide",
    "desc": "SANS guidance on running Purple Team Exercises with a focus on collaboration, learning, and measurable defensive improvements (not just “finding issues”).",
    "details": "Purple teaming works best when you treat each technique as a short, observable experiment: the attacker explains what will happen, defenders verify what they actually see, and both sides adjust instrumentation and detections until the expected evidence appears.\n\n## Use\nStart by writing a one-page exercise plan: objective (what capability you’re improving), a small set of ATT&CK techniques to simulate, the exact evidence you expect (process, network, auth, cloud events), and success criteria (what alert, enrichment, ticket, or response should occur).\n\nRun the exercise in tight cycles: execute one technique, immediately compare “what should have happened” vs “what telemetry we captured,” then fix gaps on the spot (logging config, parsing, field normalization, detection logic, response playbook). Keep the output as concrete artifacts: the ATT&CK mapping, the KQL/SPL queries used, the log sources required, and a short list of changes merged into production.\n\n## Practical tip\nIf you can’t write down the exact log fields that prove the technique occurred, the exercise will drift. Define the evidence first, then simulate.",
    "tags": [
      "guide",
      "network",
      "detection"
    ]
  },
  {
    "name": "Microsoft Sentinel threat hunting (KQL) guidance",
    "url": "https://learn.microsoft.com/en-us/azure/sentinel/hunting",
    "website": "https://learn.microsoft.com/",
    "source": "https://github.com/MicrosoftDocs/azure-docs",
    "binaries": null,
    "cat": "purple",
    "type": "guide",
    "desc": "Official Microsoft guidance for hunting in Microsoft Sentinel: using KQL to proactively search for threats, turn hunts into detections, and operationalize findings.",
    "details": "This is the canonical “how hunting works in Sentinel” doc: where to run queries, how to structure a hunt workflow, and how to convert what you find into repeatable detection/response.\n\n## Use\nIn Sentinel, go to the **Hunting** experience and run KQL queries against your workspace tables. Treat each hunt as a hypothesis (“if TTP X happened, I should see Y evidence”), then iteratively tighten the query until it reliably separates benign from suspicious activity.\n\nOnce a query consistently finds meaningful signal, operationalize it: save it as a hunting query for reuse, create follow-up steps for investigation (entity pivots, joins to identity/device context), and when appropriate convert it into a scheduled analytic rule so it alerts automatically instead of staying manual.\n\n## Practical KQL workflow\nStart with time-bounding and a narrow dataset (last 1–24h, one table), then expand using joins and enrichment only after you confirm the core signal exists. If performance becomes an issue, reduce the scanned data early (filters first), project only needed columns, and avoid expensive joins until late in the pipeline.",
    "tags": [
      "guide",
      "detection",
      "database"
    ]
  }
);
