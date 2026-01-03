window.CYBER_RESOURCES_PURPLE = window.CYBER_RESOURCES_PURPLE || [];
window.CYBER_RESOURCES_PURPLE.push(
  {
    "name": "OSSEM",
    "url": "https://ossemproject.com/intro.html",
    "website": "https://ossemproject.com/",
    "source": "https://github.com/OTRF/OSSEM",
    "binaries": null,
    "cat": "purple",
    "type": "framework",
    "desc": "Open Source Security Events Metadata (OSSEM): documentation + schemas to standardize security logging, field naming, and event modeling for normalization and portable detections.",
    "details": "OSSEM helps you turn “logs from many places” into “one consistent event language”, so the same detection logic can work across sources.\n\n## Use\nStart from the OSSEM docs, then choose what you’re standardizing: **Data Dictionaries (DD)** for source-specific fields, **Common Data Model (CDM)** for normalized entities/attributes, and **Detection Model (DM)** for relationships that detections can rely on.\n\n## Adoption workflow (what to actually do)\nPick one log source you care about (e.g., Windows Security, Sysmon, Okta, AWS CloudTrail). Build a mapping from the raw fields into OSSEM/CDM-style entities and attributes, then update your pipeline so every event is emitted in the normalized shape.\n\nOnce normalized, detections become simpler: they target the normalized fields/entities instead of vendor-specific names, and you can compare coverage across platforms because the semantics are aligned.\n\n## Practical tip\nValidate with a small corpus: take 50–100 real events, normalize them, and confirm you can answer basic questions (who/what/where/when) with the same fields across sources before scaling the mapping."
  },
  {
    "name": "Elastic Common Schema (ECS)",
    "url": "https://www.elastic.co/docs/reference/ecs",
    "website": "https://www.elastic.co/",
    "source": "https://github.com/elastic/ecs",
    "binaries": "https://github.com/elastic/ecs/releases",
    "cat": "purple",
    "type": "framework",
    "desc": "Elastic Common Schema (ECS): an open schema for consistent field names/types across logs, metrics, and security telemetry, improving correlation and detection portability.",
    "details": "ECS is a shared field vocabulary so different data sources land in the same structure (for example, every source uses the same `source.ip`, `user.name`, `process.executable`, etc.).\n\n## Use\nChoose ECS when you want your detections/dashboards to survive data-source changes. The practical step is building (or using) an ingest pipeline that maps each source’s fields into ECS.\n\n## Setup\nPrefer official releases for stable versions:\n- Download the release artifacts from GitHub Releases and pin the ECS version in your pipeline so mappings don’t drift.\n\nIf you need the schema sources for tooling or custom generation:\n```bash\ngit clone https://github.com/elastic/ecs\ncd ecs\n```\n\n## Implementation pattern\nNormalize at ingest time (Logstash/Ingest Pipelines/Beats/Agent/custom ETL). After normalization, detections can key off ECS fields rather than vendor-specific ones, and correlation across endpoints/network/cloud becomes much easier."
  },
  {
    "name": "Splunk Common Information Model (CIM)",
    "url": "https://docs.splunk.com/Documentation/CIM/latest/User/Overview",
    "website": "https://www.splunk.com/",
    "source": null,
    "binaries": "https://splunkbase.splunk.com/app/1621",
    "cat": "purple",
    "type": "framework",
    "desc": "Splunk CIM: a normalization model (fields, tags, and data models) widely used to standardize security data for consistent searches, dashboards, and detections.",
    "details": "CIM is useful when you want a stable “common shape” for security events, especially if you build content around data models (Authentication, Network Traffic, Endpoint, etc.).\n\n## Use\nMap your incoming events to the CIM field conventions and apply the expected tags so searches and detections can be written once and reused. Even outside Splunk, CIM is a solid reference for field design and domain modeling.\n\n## Download / install (Splunk)\nGet the **Splunk Common Information Model** add-on from Splunkbase, then install it in Splunk.\n- UI: Splunk Web → **Apps** → **Manage Apps** → **Install app from file** (upload the downloaded `.spl`).\n- CLI (example):\n```bash\n$SPLUNK_HOME/bin/splunk install app /path/to/splunk-common-information-model.spl -auth <user>:<pass>\n$SPLUNK_HOME/bin/splunk restart\n```\n\n## Operational tip\nAfter onboarding a sourcetype, verify it populates the intended CIM data model fields (and not just raw fields). That check is what makes data-model-based detections reliable."
  },
  {
    "name": "MITRE D3FEND",
    "url": "https://d3fend.mitre.org/",
    "website": "https://www.mitre.org/",
    "source": "https://github.com/d3fend/d3fend-ontology",
    "binaries": "https://d3fend.mitre.org/resources/ontology/",
    "cat": "purple",
    "type": "framework",
    "desc": "MITRE D3FEND: a knowledge graph/ontology of defensive countermeasures, useful to map improvements and controls to adversary behaviors and make purple-team outcomes concrete.",
    "details": "D3FEND is built to describe defenses precisely (as techniques/artifacts/relationships) so you can map “what we changed” to “what risk it reduces” in a consistent language.\n\n## Use\nIn a purple-team cycle, start from the behavior you’re emulating (often ATT&CK techniques), then use D3FEND to identify and track the specific defensive countermeasures you improved (hardening, monitoring, isolation, filtering, analysis techniques, etc.). The value is turning exercise outcomes into an explicit backlog of defensive techniques and measurable coverage changes.\n\n## Download the ontology files\nThe ontology resources page provides current and versioned downloads (TTL, OWL, JSON-LD, plus inferred mappings):\n- Open the ontology downloads page and pick the format/version you want.\n\nIf you want a one-liner for TTL (may vary by version):\n```bash\nwget -O d3fend.ttl \"https://d3fend.mitre.org/ontologies/d3fend.ttl\"\n```\n\n## Put it to work (typical)\nLoad TTL/OWL into a semantic store (or parse with RDF tooling) and query relationships to support: gap analysis, control-to-technique mapping, and reporting that ties simulation → countermeasure → implementation work."
  }
);
