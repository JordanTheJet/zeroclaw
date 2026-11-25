**The crate today.** Numbers in boxes are thousands of production lines. Solid arrows are the intended direction of calls. Dotted arrows are the 42 references that point the wrong way, each with its count. `agent` and `tools` refer to each other 26 and 64 times, which is why they stay together.

```mermaid
flowchart TB
  subgraph hosts["Hosts: call the core, are not called by it"]
    rpc["rpc 24.6K"]
    daemon["daemon 3.4K"]
    doctor["doctor 2.1K"]
    hostmisc["service, tunnel, relay, enroll, heartbeat,<br/>restart, integrations, migration"]
  end
  subgraph core["Core: one unit"]
    agent["agent 29.9K"]
    tools["tools 21.5K"]
    skills["skills 7.2K"]
    comp["composition 0.7K"]
    approval["approval 0.5K"]
  end
  subgraph subs["Subsystems the core calls"]
    sop["sop 24.1K"]
    security["security 11.2K"]
    cron["cron 6.3K"]
    obs["observability 3.3K"]
    quick["quickstart 2.4K"]
    plugin["plugin_runtime 1.2K"]
    hooks["hooks 1.0K"]
  end
  subgraph leaves["Leaves: depend on nothing in the crate, or only on each other"]
    leafset["i18n, util, health, live_config_authority,<br/>control_plane, verifiable_intent, identity, and others"]
  end
  hosts --> core
  core --> subs
  subs --> leaves
  agent <-->|"26 / 64"| tools
  sop -.->|"12"| agent
  sop -.->|"1"| tools
  sop -.->|"1"| cron
  cron -.->|"6"| agent
  cron -.->|"8"| comp
  cron -.->|"2"| tools
  obs -.->|"1"| agent
  hooks -.->|"2"| agent
  quick -.->|"4"| agent
  plugin -.->|"3"| tools
  security -.->|"2"| sop
```

**The proposed split.** Arrows read "depends on". A thick border means built and compile-checked. A thick dashed border means partly built. A thin dashed border means proposed and not decided. A dotted border means not designed yet. About 4K lines (`quickstart`, `hooks`, `browse`, `routines`, `trust`) are left for later and not drawn.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 420}}}%%
flowchart TB
  hostcr["Host crates, new<br/>daemon, heartbeat, restart, doctor,<br/>service, tunnel, integrations,<br/>migration, later relay, enroll,<br/>relay_dashboard<br/>about 14.6K<br/>Status: not designed"]
  rt["zeroclaw-runtime after the split<br/>about 107K<br/>agent, tools, skills, composition,<br/>approval, security, rpc, i18n,<br/>plugin_runtime, plugin_state,<br/>live_config_authority, control_plane,<br/>config_application, small helpers<br/>Status: proposed, the RFC decides"]
  obsc["zeroclaw-observability, new<br/>observability, 3.3K<br/>Status: built"]
  cronc["zeroclaw-cron, new<br/>cron, 6.3K<br/>Status: not designed,<br/>design note first"]
  sopc["zeroclaw-sop, new<br/>sop and calendar, 24.3K<br/>Status: not designed"]
  infra["zeroclaw-infra, exists<br/>gains util, health, shell_output<br/>about 0.4K<br/>Status: util built, the rest proposed"]
  prov["zeroclaw-providers, exists<br/>prototype home for redaction<br/>about 0.3K<br/>Status: built in the prototype,<br/>zeroclaw-infra is the alternative"]
  hostcr --> rt
  rt --> obsc
  rt --> cronc
  rt --> sopc
  rt --> infra
  rt --> prov
  obsc --> infra
  obsc --> prov
  classDef built stroke-width:3px;
  classDef partly stroke-width:3px,stroke-dasharray:6 4;
  classDef proposed stroke-dasharray:6 4;
  classDef undesigned stroke-dasharray:2 3;
  class obsc,prov built;
  class infra partly;
  class rt proposed;
  class hostcr,cronc,sopc undesigned;
```
