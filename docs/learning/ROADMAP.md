# DirtyHack Autonomy Roadmap (Implementation Guide)

End goal: DirtyHack as a fully autonomous, multi-agent security researcher that can operate in whitebox, greybox, and blackbox scenarios while reusing the existing core (assessment → threat-modeling → code-review → optional DAST → report-generator) with a mode-aware pentest phase.

## Modes & Pipelines
- **Whitebox (current)**: assessment → threat-modeling → code-review → (optional) DAST → report-generator. (Keep unchanged.)
- **Greybox/Blackbox**: recon/scanner → threat-modeling → pentest → (optional) DAST → report-generator.

## Agents & Roles
- **Recon/Scanner (new, pre–threat-model)**  
  - Inputs: `--target-url`, optional `--test-accounts`.  
  - Tasks: subdomain discovery (subfinder), validation (httpx), port scan (naabu), service fingerprint (nmap -sV), tech detection (httpx -tech-detect), nuclei/NSE quick checks, crawl/pages/endpoints, hidden content checklist (robots.txt, backups, admin URLs, interesting extensions), JS/asset triage for paths/URLs/keys, auth surface notes.  
  - Output: `RECON.json` (targets, services, endpoints, auth states, tech stack, quick findings, evidence).

- **Threat-Modeling (reuse)**  
  - Extend prompt to consume `RECON.json` when present.  
  - Produce mode-aware test cases that downstream agents execute.

- **DAST (existing)**  
  - Reuse current agent; allow it to consume test cases from threat-modeling (including recon-driven ones).  
  - Keep hooks/sandbox: DB blocks, write restrictions, scope confirmations.

- **Pentest Agent (mode default for grey/black)**  
  - Inputs: threat-model test cases + recon endpoints.  
  - Tasks: execute contextual checklists; targeted fuzzing/enumeration only for scoped endpoints; gather evidence, and update/create `VULNERABILITIES.json` for reporting.  
  - Checklists:  
    - Common page checklist (entry points, HTTP/HTTPS, error handling, logic flaws, auth bypass attempts, headers, sessions, brute-force probes within scope).  
    - Special pages (login/register/reset/upload) with safe defaults and rate/lockout awareness.

- **Report-Generator (existing)**  
  - Optionally summarize recon/pentest sections if present; otherwise unchanged.

## Safety & Policies
- Mode-aware tool allowlists (network tools only in grey/blackbox).  
- Scope enforcement: explicit target confirmation; domain/host allowlists; rate limits/timeouts for scans.  
- Sandbox Bash/network where possible; keep DAST hooks intact.  
- Audit/log commands + results for recon/pentest actions.

## CLI & Config
- Add `--mode {whitebox,greybox,blackbox}`; `--target-url`, `--test-accounts`.  
- Map modes to agent sequences:  
  - Whitebox: existing sequence.  
  - Grey/Blackbox: recon → threat-modeling → pentest → (optional DAST) → report-generator.  
- Expose policy presets (tool allowlists, timeouts) per mode.

## Skills
- Consider skills for: hidden content/JS analysis, nuclei/nmap preset runs, form interaction/testing helpers.  
- Keep skill loading via `setting_sources=["project"]`; avoid hardcoding tool glue in agents.

## Implementation Steps
1) **CLI mode switch**: add flags, map sequences, keep whitebox default.  
2) **Recon/Scanner agent**: definition + prompt; produce `RECON.json`; hook into threat-modeling input.  
3) **Threat-Modeling update**: accept recon data; emit mode-aware test cases.  
4) **DAST consumption**: let DAST read test cases; preserve existing hooks/sandbox.  
5) **Pentest agent**: add agent definition + prompt; implement scoped checklist execution; write findings directly to vuln artifact.  
6) **Reporting**: include recon/pentest summaries when artifacts exist.  
7) **Safety/policy**: enforce mode-based tool allowlists, scope confirmations, rate limits; audit logging.  
8) **Docs/Tests**: update docs for modes, inputs, artifacts; add mocked integration tests for new mode flows.
