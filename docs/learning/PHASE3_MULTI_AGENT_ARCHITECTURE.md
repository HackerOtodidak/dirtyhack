# Phase 3: Multi-Agent Architecture

This tutorial teaches you how to build multi-agent systems using the Claude Agent SDK - the core pattern that makes SecureVibes powerful.

---

## Table of Contents

1. [What is Multi-Agent Architecture?](#1-what-is-multi-agent-architecture)
2. [AgentDefinition - Creating Specialized Agents](#2-agentdefinition---creating-specialized-agents)
3. [Orchestration Prompts - Coordinating Agents](#3-orchestration-prompts---coordinating-agents)
4. [Agent Communication via Artifacts](#4-agent-communication-via-artifacts)
5. [The Task Tool - Invoking Subagents](#5-the-task-tool---invoking-subagents)
6. [SecureVibes Agent Pipeline Explained](#6-securevibes-agent-pipeline-explained)
7. [Building Your Own Agent Pipeline](#7-building-your-own-agent-pipeline)
8. [Best Practices](#8-best-practices)
9. [Complete Working Example](#9-complete-working-example)
10. [Exercises](#10-exercises)

---

## 1. What is Multi-Agent Architecture?

Instead of one monolithic AI agent trying to do everything, multi-agent architecture divides work among specialized agents:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR (Main Claude)                    │
│  "Coordinate the security scan by invoking specialized agents"  │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐
    │ Agent A  │        │ Agent B  │        │ Agent C  │
    │ (Expert  │        │ (Expert  │        │ (Expert  │
    │  in X)   │        │  in Y)   │        │  in Z)   │
    └──────────┘        └──────────┘        └──────────┘
```

### Why Multi-Agent?

| Single Agent | Multi-Agent |
|--------------|-------------|
| One long prompt with everything | Focused prompts per task |
| Context window fills up fast | Each agent gets fresh context |
| Hard to maintain/modify | Modular and testable |
| Generic behavior | Specialized expertise |
| All-or-nothing execution | Resume from any point |

### SecureVibes Example

SecureVibes uses 5 specialized agents:

1. **Assessment Agent** - Maps codebase architecture
2. **Threat Modeling Agent** - Identifies threats using STRIDE
3. **Code Review Agent** - Finds vulnerabilities with evidence
4. **Report Generator Agent** - Creates final report
5. **DAST Agent** - Validates via HTTP testing

---

## 2. AgentDefinition - Creating Specialized Agents

### The AgentDefinition Class

Each agent is defined using `AgentDefinition`:

```python
from claude_agent_sdk import AgentDefinition

agent = AgentDefinition(
    description="What this agent does (for orchestrator)",
    prompt="Detailed instructions for this agent...",
    tools=["Read", "Write", ...],  # Allowed tools
    model="sonnet"  # Model to use
)
```

### Parameters Explained

| Parameter | Purpose | Example |
|-----------|---------|---------|
| `description` | Short description for orchestrator to understand when to use this agent | `"Analyzes code for security vulnerabilities"` |
| `prompt` | Full instructions defining the agent's behavior, methodology, output format | The complete agent prompt |
| `tools` | List of tools this agent can use | `["Read", "Grep", "Write"]` |
| `model` | Claude model to use | `"sonnet"`, `"haiku"`, `"opus"` |

### Real Example: Assessment Agent

**File: `packages/core/securevibes/agents/definitions.py`**

```python
from claude_agent_sdk import AgentDefinition
from securevibes.prompts.loader import load_all_agent_prompts
from securevibes.config import config

# Load prompts from files
AGENT_PROMPTS = load_all_agent_prompts()

def create_agent_definitions(cli_model=None, dast_target_url=None):
    return {
        "assessment": AgentDefinition(
            description="Analyzes codebase architecture and creates comprehensive security documentation",
            prompt=AGENT_PROMPTS["assessment"],
            tools=["Read", "Grep", "Glob", "LS", "Write"],
            model=config.get_agent_model("assessment", cli_override=cli_model)
        ),
        
        "threat-modeling": AgentDefinition(
            description="Performs architecture-driven STRIDE threat modeling",
            prompt=AGENT_PROMPTS["threat_modeling"],
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("threat_modeling", cli_override=cli_model)
        ),
        
        "code-review": AgentDefinition(
            description="Finds vulnerabilities with concrete evidence",
            prompt=AGENT_PROMPTS["code_review"],
            tools=["Read", "Grep", "Glob", "Write"],
            model=config.get_agent_model("code_review", cli_override=cli_model)
        ),
        
        "report-generator": AgentDefinition(
            description="Compiles final scan report",
            prompt=AGENT_PROMPTS["report_generator"],
            tools=["Read", "Write"],
            model=config.get_agent_model("report_generator", cli_override=cli_model)
        ),
        
        "dast": AgentDefinition(
            description="Validates vulnerabilities via HTTP testing",
            prompt=AGENT_PROMPTS["dast"].replace("{target_url}", dast_target_url or ""),
            tools=["Read", "Write", "Skill", "Bash"],
            model=config.get_agent_model("dast", cli_override=cli_model)
        )
    }
```

### Tool Selection Strategy

Choose tools based on what the agent needs:

| Agent Type | Typical Tools | Reasoning |
|------------|---------------|-----------|
| **Analysis** | Read, Grep, Glob, LS | Read-only exploration |
| **Writer** | Read, Write | Creates documents |
| **Tester** | Read, Bash, Skill | Executes commands |
| **All-Purpose** | All tools | Maximum capability |

---

## 3. Orchestration Prompts - Coordinating Agents

The orchestration prompt tells the main Claude instance how to coordinate agents.

### Key Components of an Orchestration Prompt

1. **Task Description** - What overall task to accomplish
2. **Phase Definitions** - What each phase does
3. **Execution Order** - Sequential or conditional
4. **Environment Checks** - Skip/resume logic
5. **Completion Criteria** - When to stop

### Real Example: SecureVibes Orchestration

**File: `packages/core/securevibes/prompts/orchestration/main.txt`**

```text
Perform a complete security analysis of this codebase.

EXECUTION MODE CHECK:
- Check if environment variable RUN_ONLY_SUBAGENT is set
- If RUN_ONLY_SUBAGENT is set, run ONLY that sub-agent and skip all others
- Check if environment variable SKIP_SUBAGENTS is set  
- If SKIP_SUBAGENTS is set (comma-separated list), skip those sub-agents
- Otherwise, execute all phases sequentially

Execute these phases SEQUENTIALLY, ONE AT A TIME:

PHASE 1: ASSESSMENT
- Skip if: SKIP_SUBAGENTS contains "assessment" OR (RUN_ONLY_SUBAGENT is set AND != "assessment")
- Announce: "Starting Phase 1: Assessment"
- Use the 'assessment' agent to analyze architecture
- Creates .securevibes/SECURITY.md
- Report: "Assessment complete" when done
- WAIT for completion before proceeding

PHASE 2: THREAT MODELING
- Skip if: SKIP_SUBAGENTS contains "threat-modeling" OR (RUN_ONLY_SUBAGENT is set AND != "threat-modeling")
- Announce: "Starting Phase 2: Threat Modeling"
- Use the 'threat-modeling' agent to search for threat patterns using STRIDE
- Reads .securevibes/SECURITY.md
- Creates .securevibes/THREAT_MODEL.json
- Report: "Threat modeling complete" when done
- WAIT for completion before proceeding

PHASE 3: CODE REVIEW
- Skip if: SKIP_SUBAGENTS contains "code-review" OR (RUN_ONLY_SUBAGENT is set AND != "code-review")
- Announce: "Starting Phase 3: Code Review"
- Use the 'code-review' agent to validate threats with evidence
- Reads .securevibes/THREAT_MODEL.json
- Creates .securevibes/VULNERABILITIES.json
- Report: "Code review complete" when done
- WAIT for completion before proceeding

PHASE 4: REPORT GENERATION
- Skip if: SKIP_SUBAGENTS contains "report-generator" OR (RUN_ONLY_SUBAGENT is set AND != "report-generator")
- Announce: "Starting Phase 4: Report Generation"
- Use the 'report-generator' agent for final report
- Reads all artifacts
- Creates .securevibes/scan_results.json
- Report: "Report generation complete" when done

PHASE 5: DAST VALIDATION (CONDITIONAL)
- Skip if: DAST_ENABLED != "true"
- Check environment variable DAST_ENABLED
- If DAST_ENABLED == "true":
  - Use the 'dast' agent to validate vulnerabilities via HTTP
  - Creates .securevibes/DAST_VALIDATION.json

CRITICAL RULES:
- Execute agents ONE AT A TIME in strict sequential order
- Explicitly announce each phase before starting
- WAIT for each phase to complete before starting the next
- Each agent uses ONLY its assigned tools
```

### Writing Effective Orchestration Prompts

```text
# Template for Orchestration Prompt

You are coordinating a [TASK TYPE] workflow.

## Available Agents
[List agents and their capabilities]

## Execution Flow
Phase 1: [AGENT NAME]
- Input: [What it needs]
- Output: [What it creates]
- Location: [File path]

Phase 2: [AGENT NAME]
- Requires: [Previous output]
- Input: [What it needs]
- Output: [What it creates]

[Continue for all phases...]

## Rules
1. Execute phases in order
2. Wait for each phase to complete
3. Announce progress
4. Handle errors gracefully
```

---

## 4. Agent Communication via Artifacts

Agents communicate through files (artifacts), not direct messages.

### Why File-Based Communication?

```
Agent A ──writes──► ARTIFACT.json ──reads──► Agent B
```

**Benefits:**

| Advantage | Explanation |
|-----------|-------------|
| **Inspectable** | You can read intermediate outputs |
| **Debuggable** | Find where things went wrong |
| **Resumable** | Restart from any phase |
| **Reliable** | No parsing errors between agents |
| **Auditable** | Complete record of agent work |

### SecureVibes Artifact Flow

```
.securevibes/
│
├── SECURITY.md              ← Assessment Agent creates
│   │                           (Architecture documentation)
│   ▼
├── THREAT_MODEL.json        ← Threat Modeling reads SECURITY.md, creates this
│   │                           (STRIDE threats as JSON)
│   ▼
├── VULNERABILITIES.json     ← Code Review reads THREAT_MODEL, creates this
│   │                           (Confirmed vulnerabilities with evidence)
│   ▼
├── scan_results.json        ← Report Generator compiles final results
│   │
│   ▼
└── DAST_VALIDATION.json     ← DAST Agent validates via HTTP
                                (Validation status per vulnerability)
```

### Artifact Format Guidelines

**1. Use JSON for structured data:**

```json
[
  {
    "id": "THREAT-001",
    "category": "Injection",
    "title": "SQL Injection in login",
    "severity": "critical",
    "file_path": "app/views.py",
    "line_number": 42
  }
]
```

**2. Use Markdown for documentation:**

```markdown
# Security Architecture

## Overview
This application is a Django web server...

## Entry Points
- API endpoints at /api/*
- Admin interface at /admin
```

**3. Clear file naming:**

| Pattern | Example |
|---------|---------|
| `PHASE_OUTPUT.ext` | `SECURITY.md`, `THREAT_MODEL.json` |
| Uppercase for visibility | Easy to spot in directory listings |
| Descriptive names | Know contents without opening |

---

## 5. The Task Tool - Invoking Subagents

When the orchestrator needs to invoke a subagent, Claude uses the internal `Task` tool.

### How It Works

```python
# You define agents in options:
options = ClaudeAgentOptions(
    agents={
        "analyzer": AgentDefinition(...),
        "writer": AgentDefinition(...)
    }
)

# The orchestrator prompt says:
# "Use the 'analyzer' agent to review the code"

# Claude internally calls:
# Task(agent_name="analyzer", prompt="Review the code in...")
```

### What Happens During Subagent Execution

```
Orchestrator                    Subagent
     │                              │
     ├──Task(agent="analyzer")─────►│
     │                              │
     │                              ├── Reads files
     │                              │
     │                              ├── Uses grep/glob
     │                              │
     │                              ├── Writes output
     │                              │
     │◄──────Complete──────────────┤
     │                              │
     ├── Continues to next phase    │
```

### Monitoring Subagent Activity

SecureVibes uses hooks to track subagent lifecycle:

```python
# In scanner.py
async def subagent_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    agent_name = input_data.get("agent_name")
    duration_ms = input_data.get("duration_ms", 0)
    
    if agent_name:
        tracker.on_subagent_stop(agent_name, duration_ms)
        print(f"✓ {agent_name} completed in {duration_ms/1000:.1f}s")
    
    return {}

# Register hook
options = ClaudeAgentOptions(
    hooks={
        "SubagentStop": [HookMatcher(hooks=[subagent_hook])]
    }
)
```

---

## 6. SecureVibes Agent Pipeline Explained

Let's trace through a complete SecureVibes scan:

### Step 1: Scanner Initializes

```python
scanner = Scanner(model="sonnet", debug=True)
result = await scanner.scan("/path/to/repo")
```

### Step 2: Options Created

```python
agents = create_agent_definitions(cli_model="sonnet")

options = ClaudeAgentOptions(
    agents=agents,                          # All 5 agents defined
    cwd=str(repo),                          # Working directory
    setting_sources=["project"],            # Enable skills
    allowed_tools=[...],                    # Global tool list
    max_turns=50,                           # Max reasoning steps
    permission_mode='bypassPermissions',    # Auto-accept
    hooks={...}                             # Monitoring
)
```

### Step 3: Orchestration Begins

```python
async with ClaudeSDKClient(options=options) as client:
    await client.query(orchestration_prompt)
```

### Step 4: Assessment Phase

```
Orchestrator: "Starting Phase 1: Assessment"
Orchestrator: Task(agent="assessment", prompt="Analyze architecture...")

Assessment Agent:
  ├── Glob("**/*.py", "**/*.js", ...)     # Find code files
  ├── LS(".")                              # List structure
  ├── Read("package.json")                 # Understand dependencies
  ├── Grep("auth|login|password")          # Find auth patterns
  ├── Read("src/routes.py")                # Analyze entry points
  └── Write(".securevibes/SECURITY.md")    # Output architecture doc

Orchestrator: "Assessment complete"
```

### Step 5: Threat Modeling Phase

```
Orchestrator: "Starting Phase 2: Threat Modeling"
Orchestrator: Task(agent="threat-modeling", prompt="Identify threats...")

Threat Modeling Agent:
  ├── Read(".securevibes/SECURITY.md")     # Load architecture
  ├── [Applies STRIDE methodology]          # Internal reasoning
  └── Write(".securevibes/THREAT_MODEL.json")  # Output threats

Orchestrator: "Threat modeling complete - 28 threats identified"
```

### Step 6: Code Review Phase

```
Orchestrator: "Starting Phase 3: Code Review"
Orchestrator: Task(agent="code-review", prompt="Find vulnerabilities...")

Code Review Agent:
  ├── Read(".securevibes/THREAT_MODEL.json")  # Load threats
  ├── Grep("sql|query|execute")               # Search for patterns
  ├── Read("app/views.py")                    # Analyze suspicious code
  ├── [Validates each threat with evidence]
  └── Write(".securevibes/VULNERABILITIES.json")  # Output findings

Orchestrator: "Code review complete - 21 vulnerabilities validated"
```

### Step 7: Report Generation

```
Orchestrator: "Starting Phase 4: Report Generation"
Orchestrator: Task(agent="report-generator", prompt="Create report...")

Report Generator Agent:
  ├── Read(".securevibes/VULNERABILITIES.json")
  └── Write(".securevibes/scan_results.json")  # Final report

Orchestrator: "Report generation complete"
```

### Step 8: Results Loaded

```python
# Back in Scanner
result = self._load_scan_results(securevibes_dir, ...)
return result  # ScanResult with all issues
```

---

## 7. Building Your Own Agent Pipeline

### Step-by-Step Guide

**1. Define Your Agents**

```python
from claude_agent_sdk import AgentDefinition

my_agents = {
    "reconnaissance": AgentDefinition(
        description="Discovers attack surface",
        prompt="""You are a reconnaissance expert.
        
        Your task: Map the target's attack surface.
        
        1. Find all subdomains
        2. Identify open ports and services
        3. Detect technologies used
        
        Write results to .pentest/RECON.json as:
        {
            "subdomains": [...],
            "services": [...],
            "technologies": [...]
        }
        """,
        tools=["Bash", "Write"],
        model="sonnet"
    ),
    
    "scanner": AgentDefinition(
        description="Scans for vulnerabilities",
        prompt="""You are a vulnerability scanner.
        
        Read .pentest/RECON.json for targets.
        
        For each service:
        1. Check for common vulnerabilities
        2. Test default credentials
        3. Look for misconfigurations
        
        Write findings to .pentest/VULNERABILITIES.json
        """,
        tools=["Read", "Bash", "Write"],
        model="sonnet"
    ),
    
    "reporter": AgentDefinition(
        description="Creates penetration test report",
        prompt="""You are a security report writer.
        
        Read .pentest/VULNERABILITIES.json
        
        Create a professional pentest report with:
        - Executive summary
        - Technical findings
        - Risk ratings
        - Remediation steps
        
        Write to .pentest/REPORT.md
        """,
        tools=["Read", "Write"],
        model="sonnet"
    )
}
```

**2. Create Orchestration Prompt**

```python
orchestration_prompt = """
Perform a penetration test on the target.

Execute phases in order:

PHASE 1: RECONNAISSANCE
- Use 'reconnaissance' agent
- Creates .pentest/RECON.json
- Wait for completion

PHASE 2: VULNERABILITY SCANNING  
- Use 'scanner' agent
- Reads RECON.json
- Creates .pentest/VULNERABILITIES.json
- Wait for completion

PHASE 3: REPORTING
- Use 'reporter' agent
- Reads VULNERABILITIES.json
- Creates .pentest/REPORT.md

Announce each phase. Report findings count after each phase.
"""
```

**3. Run the Pipeline**

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

async def run_pentest(target: str):
    options = ClaudeAgentOptions(
        agents=my_agents,
        cwd=".",
        allowed_tools=["Read", "Write", "Bash"],
        permission_mode='acceptEdits',
        max_turns=100
    )
    
    # Create output directory
    Path(".pentest").mkdir(exist_ok=True)
    
    # Set target as environment variable for agents
    import os
    os.environ["PENTEST_TARGET"] = target
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(orchestration_prompt)
        
        async for message in client.receive_messages():
            # Process messages, track progress
            pass
    
    # Load and return results
    return load_results(".pentest/REPORT.md")
```

---

## 8. Best Practices

### Agent Design

| Do | Don't |
|-----|-------|
| Give each agent ONE clear responsibility | Create jack-of-all-trades agents |
| Write detailed prompts with examples | Use vague instructions |
| Specify exact output formats | Let agents decide format |
| Include error handling instructions | Assume perfect execution |

### Artifact Design

| Do | Don't |
|-----|-------|
| Use structured formats (JSON) | Use unstructured text |
| Include all fields downstream agents need | Require agents to infer data |
| Validate artifacts before next phase | Trust all outputs blindly |
| Use consistent naming conventions | Mix naming styles |

### Orchestration Design

| Do | Don't |
|-----|-------|
| Execute phases sequentially | Run agents in parallel (initially) |
| Check prerequisites before each phase | Skip validation |
| Allow resume from any phase | Require full re-runs |
| Log progress and timing | Silent execution |

### Prompt Engineering

```text
# Good Prompt Structure

1. ROLE: Who is this agent?
   "You are a [specific expert role]..."

2. TASK: What does it do?
   "Your task is to [specific action]..."

3. INPUT: What does it read?
   "Read the following files: ..."

4. METHOD: How should it work?
   "Follow these steps: 1... 2... 3..."

5. OUTPUT: What should it create?
   "Write results to [path] in this format: ..."

6. CONSTRAINTS: What are the limits?
   "Do NOT [prohibited actions]..."
```

---

## 9. Complete Working Example

Here's a minimal but complete multi-agent system:

```python
import asyncio
import json
from pathlib import Path
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, AgentDefinition
from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

# Define agents
agents = {
    "analyzer": AgentDefinition(
        description="Analyzes Python code structure",
        prompt="""You are a code analyst.

Analyze the Python files in this project.

1. Use Glob to find all .py files
2. Read key files to understand structure
3. Write analysis to .analysis/STRUCTURE.json:

{
    "total_files": <number>,
    "main_modules": ["list of key modules"],
    "entry_points": ["list of entry points"],
    "dependencies": ["external packages used"]
}

Focus on understanding the codebase architecture.
""",
        tools=["Read", "Glob", "LS", "Write"],
        model="sonnet"
    ),
    
    "documenter": AgentDefinition(
        description="Creates documentation from analysis",
        prompt="""You are a technical writer.

Read .analysis/STRUCTURE.json

Create a developer guide at .analysis/GUIDE.md:

# Developer Guide

## Project Overview
[Based on analysis]

## Module Structure
[List and describe modules]

## Getting Started
[How to work with this code]

## Key Files
[Important files to know]

Write clear, helpful documentation.
""",
        tools=["Read", "Write"],
        model="sonnet"
    )
}

# Orchestration prompt
orchestration = """
Create documentation for this Python project.

PHASE 1: ANALYSIS
- Use 'analyzer' agent to understand the codebase
- Creates .analysis/STRUCTURE.json
- Announce when complete

PHASE 2: DOCUMENTATION
- Use 'documenter' agent to create guide
- Reads STRUCTURE.json
- Creates .analysis/GUIDE.md
- Announce when complete

Execute phases in order. Wait for each to complete.
"""

async def main():
    # Setup
    Path(".analysis").mkdir(exist_ok=True)
    
    options = ClaudeAgentOptions(
        agents=agents,
        cwd=".",
        allowed_tools=["Read", "Write", "Glob", "LS"],
        permission_mode='acceptEdits',
        max_turns=30
    )
    
    print("🚀 Starting documentation generation...")
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(orchestration)
        
        async for message in client.receive_messages():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        # Print Claude's progress announcements
                        text = block.text.strip()
                        if text:
                            print(f"📝 {text[:100]}...")
            
            elif isinstance(message, ResultMessage):
                print(f"\n✅ Complete! Cost: ${message.total_cost_usd:.4f}")
                break
    
    # Show results
    if Path(".analysis/GUIDE.md").exists():
        print("\n" + "="*50)
        print("Generated Guide:")
        print("="*50)
        print(Path(".analysis/GUIDE.md").read_text()[:500] + "...")
    
if __name__ == "__main__":
    asyncio.run(main())
```

---

## 10. Exercises

### Exercise 1: Bug Hunter Pipeline

Create a 3-agent pipeline:
1. **Recon Agent** - Finds all JavaScript files, identifies frameworks
2. **Security Agent** - Searches for common vulnerabilities (XSS, injection)
3. **Report Agent** - Creates markdown security report

### Exercise 2: Code Review Pipeline

Create agents for:
1. **Style Checker** - Analyzes code style and formatting
2. **Complexity Analyzer** - Finds complex functions
3. **Documentation Checker** - Identifies missing docstrings

### Exercise 3: Modify SecureVibes

Try adding a new agent to SecureVibes:
1. Create a new prompt in `prompts/agents/`
2. Add the agent definition in `definitions.py`
3. Update the orchestration prompt
4. Test the modified pipeline

---

## Summary

| Concept | Key Points |
|---------|------------|
| **AgentDefinition** | Define specialized agents with description, prompt, tools, model |
| **Orchestration** | Meta-prompt that coordinates agent execution |
| **Artifacts** | File-based communication between agents |
| **Task Tool** | How orchestrator invokes subagents |
| **Pipeline Design** | Sequential phases, clear dependencies, resumable |

---

## Next Steps

Now that you understand multi-agent architecture, proceed to:
- **[Phase 4: Advanced Features](PHASE4_ADVANCED_FEATURES.md)** - Hooks, skills, cost tracking

