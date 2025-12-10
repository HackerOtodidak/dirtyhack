# Phase 4: Advanced SDK Features

This tutorial covers advanced Claude Agent SDK features: hooks for security and monitoring, skills for extending capabilities, and cost tracking.

---

## Table of Contents

1. [Hooks System Overview](#1-hooks-system-overview)
2. [PreToolUse Hooks - Security Gates](#2-pretooluse-hooks---security-gates)
3. [PostToolUse Hooks - Monitoring](#3-posttooluse-hooks---monitoring)
4. [SubagentStop Hooks - Phase Tracking](#4-subagentstop-hooks---phase-tracking)
5. [Hook Patterns and Best Practices](#5-hook-patterns-and-best-practices)
6. [Agent Skills Framework](#6-agent-skills-framework)
7. [Creating Custom Skills](#7-creating-custom-skills)
8. [Cost Tracking and Budget Management](#8-cost-tracking-and-budget-management)
9. [Error Handling Strategies](#9-error-handling-strategies)
10. [Advanced Configuration](#10-advanced-configuration)

---

## 1. Hooks System Overview

Hooks let you intercept and control Claude's tool usage. They're async functions that run at specific points in the agent loop.

### Hook Types

| Hook Type | When It Runs | Use Cases |
|-----------|--------------|-----------|
| `PreToolUse` | Before tool executes | Security, validation, modification |
| `PostToolUse` | After tool completes | Logging, metrics, cleanup |
| `SubagentStop` | When subagent finishes | Phase tracking, progress |
| `UserPromptSubmit` | Before prompt sent | Input validation |

### Basic Hook Structure

```python
# All hooks have the same signature
async def my_hook(
    input_data: dict,    # Information about the event
    tool_use_id: str,    # Unique identifier
    ctx: dict            # Context (rarely used)
) -> dict:               # Return {} to allow, or dict to modify/deny
    # Your logic here
    return {}  # Allow the operation
```

### Registering Hooks

```python
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import HookMatcher

options = ClaudeAgentOptions(
    hooks={
        "PreToolUse": [
            HookMatcher(hooks=[my_security_hook]),
            HookMatcher(matcher="Bash", hooks=[bash_only_hook])  # Tool-specific
        ],
        "PostToolUse": [
            HookMatcher(hooks=[logging_hook])
        ],
        "SubagentStop": [
            HookMatcher(hooks=[phase_tracker])
        ]
    }
)
```

---

## 2. PreToolUse Hooks - Security Gates

PreToolUse hooks run BEFORE a tool executes. They can:
- **Allow** - Return `{}`
- **Deny** - Return deny decision
- **Modify** - Change tool input
- **Override** - Provide custom result

### Hook Input Data

```python
async def pre_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    # Available in input_data:
    tool_name = input_data.get("tool_name")      # "Read", "Write", "Bash", etc.
    tool_input = input_data.get("tool_input", {})  # Tool parameters
    
    # Examples of tool_input by tool:
    # Read: {"file_path": "some/file.py"}
    # Write: {"file_path": "out.json", "content": "..."}
    # Bash: {"command": "ls -la"}
    # Grep: {"pattern": "password", "path": "."}
```

### Example: Block Dangerous Commands

**From SecureVibes `hooks.py`:**

```python
def create_dast_security_hook(tracker, console, debug):
    """Block database tools during DAST phase."""
    
    async def dast_security_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        
        # Only apply to DAST phase
        if tracker.current_phase != "dast":
            return {}  # Allow
        
        # Only filter Bash commands
        if tool_name != "Bash":
            return {}
        
        tool_input = input_data.get("tool_input", {})
        command = tool_input.get("command", "")
        
        # Block database CLI tools
        blocked_tools = ["sqlite3", "psql", "mysql", "mongosh", "redis-cli"]
        
        for tool in blocked_tools:
            if tool in command:
                # DENY the operation
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"Cannot use '{tool}' - HTTP testing only",
                        "reason": "Database manipulation not allowed in DAST"
                    }
                }
        
        return {}  # Allow
    
    return dast_security_hook
```

### Example: Block Sensitive File Access

```python
async def sensitive_files_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    """Prevent reading sensitive files."""
    
    tool_name = input_data.get("tool_name")
    
    if tool_name != "Read":
        return {}
    
    file_path = input_data.get("tool_input", {}).get("file_path", "")
    
    # Block sensitive files
    sensitive_patterns = [
        ".env", ".secrets", "credentials",
        "private_key", "id_rsa", ".pem"
    ]
    
    for pattern in sensitive_patterns:
        if pattern in file_path.lower():
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Cannot read sensitive file: {file_path}"
                }
            }
    
    return {}
```

### Example: Override Tool Result

```python
async def skip_infrastructure_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    """Skip infrastructure directories without error."""
    
    tool_name = input_data.get("tool_name")
    if tool_name not in ["Read", "Grep", "Glob"]:
        return {}
    
    file_path = input_data.get("tool_input", {}).get("file_path", "")
    
    # Skip infrastructure directories
    skip_dirs = ["node_modules", "venv", ".git", "__pycache__"]
    
    if any(skip_dir in file_path for skip_dir in skip_dirs):
        # Return a custom result instead of executing
        return {
            "override_result": {
                "content": f"Skipped: Infrastructure directory ({file_path})",
                "is_error": False
            }
        }
    
    return {}
```

---

## 3. PostToolUse Hooks - Monitoring

PostToolUse hooks run AFTER a tool completes. Use them for logging and metrics.

### Hook Input Data

```python
async def post_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    tool_name = input_data.get("tool_name")
    tool_input = input_data.get("tool_input", {})
    tool_response = input_data.get("tool_response", {})
    
    # Check if tool failed
    is_error = tool_response.get("is_error", False)
    content = tool_response.get("content", "")
    
    return {}  # Post hooks usually just observe
```

### Example: Log All Tool Usage

```python
def create_logging_hook(log_file: str):
    """Create hook that logs all tool usage to file."""
    
    async def logging_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        import json
        from datetime import datetime
        
        tool_name = input_data.get("tool_name")
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get("tool_response", {})
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "input": tool_input,
            "success": not tool_response.get("is_error", False)
        }
        
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        return {}
    
    return logging_hook
```

### Real Example from SecureVibes

```python
def create_post_tool_hook(tracker, console, debug):
    """Track tool completion and log in debug mode."""
    
    async def post_tool_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        tool_name = input_data.get("tool_name")
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get("tool_response", {})
        
        is_error = tool_response.get("is_error", False)
        error_msg = tool_response.get("content", "") if is_error else None
        
        # Update tracker
        tracker.on_tool_complete(tool_name, not is_error, error_msg)
        
        # Debug logging
        if debug and not is_error and tool_name in ("Read", "Write"):
            file_path = tool_input.get("file_path", "")
            action = "✅ Read" if tool_name == "Read" else "✅ Wrote"
            console.print(f"  {action} {file_path}", style="dim green")
        
        return {}
    
    return post_tool_hook
```

---

## 4. SubagentStop Hooks - Phase Tracking

SubagentStop hooks fire when a subagent completes. Perfect for progress tracking.

### Hook Input Data

```python
async def subagent_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    agent_name = input_data.get("agent_name")      # "assessment", "code-review", etc.
    duration_ms = input_data.get("duration_ms", 0)  # How long it took
    
    return {}
```

### Real Example from SecureVibes

```python
def create_subagent_hook(tracker):
    """Track subagent completion for progress reporting."""
    
    async def subagent_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
        agent_name = input_data.get("agent_name") or input_data.get("subagent_type")
        duration_ms = input_data.get("duration_ms", 0)
        
        if agent_name:
            tracker.on_subagent_stop(agent_name, duration_ms)
        
        return {}
    
    return subagent_hook

# In ProgressTracker class:
def on_subagent_stop(self, agent_name: str, duration_ms: int):
    """Called when a sub-agent completes."""
    
    duration_sec = duration_ms / 1000
    
    # Show completion summary
    console.print(f"\n✅ Phase {agent_name} Complete", style="bold green")
    console.print(
        f"   Duration: {duration_sec:.1f}s | "
        f"Tools: {self.tool_count} | "
        f"Files: {len(self.files_read)} read, {len(self.files_written)} written",
        style="green"
    )
```

---

## 5. Hook Patterns and Best Practices

### Pattern: Progress Tracker Class

```python
class ProgressTracker:
    """Centralized progress tracking for hooks."""
    
    def __init__(self, console, debug=False):
        self.console = console
        self.debug = debug
        self.current_phase = None
        self.tool_count = 0
        self.files_read = set()
        self.files_written = set()
        self.phase_start_time = None
    
    def on_tool_start(self, tool_name: str, tool_input: dict):
        """Called by PreToolUse hook."""
        self.tool_count += 1
        
        if tool_name == "Read":
            file_path = tool_input.get("file_path", "")
            self.files_read.add(file_path)
            if self.debug:
                self.console.print(f"  📖 Reading: {file_path}", style="dim")
        
        elif tool_name == "Write":
            file_path = tool_input.get("file_path", "")
            self.files_written.add(file_path)
            self.console.print(f"  💾 Writing: {file_path}", style="dim")
    
    def on_tool_complete(self, tool_name: str, success: bool, error: str = None):
        """Called by PostToolUse hook."""
        if not success and error:
            self.console.print(f"  ⚠️ {tool_name} failed: {error[:80]}", style="yellow")
    
    def on_phase_start(self, phase_name: str):
        """Called when subagent starts."""
        self.current_phase = phase_name
        self.phase_start_time = time.time()
        self.tool_count = 0
        self.files_read.clear()
        self.files_written.clear()
        self.console.print(f"\n━━━ Phase: {phase_name} ━━━\n", style="bold cyan")
```

### Pattern: Hook Factory Functions

```python
def create_hooks(tracker, console, debug):
    """Create all hooks with shared state."""
    
    return {
        "PreToolUse": [
            HookMatcher(hooks=[create_security_hook(tracker)]),
            HookMatcher(hooks=[create_progress_hook(tracker, debug)])
        ],
        "PostToolUse": [
            HookMatcher(hooks=[create_logging_hook(console, debug)])
        ],
        "SubagentStop": [
            HookMatcher(hooks=[create_phase_hook(tracker)])
        ]
    }

# Usage
tracker = ProgressTracker(console, debug=True)
options = ClaudeAgentOptions(
    hooks=create_hooks(tracker, console, debug=True)
)
```

### Best Practices

| Do | Don't |
|-----|-------|
| Keep hooks fast (async, non-blocking) | Do heavy processing in hooks |
| Use factories to share state | Create global state |
| Log sparingly in production | Log every tool call in prod |
| Return `{}` for allow (most common) | Forget to return |
| Handle exceptions gracefully | Let exceptions crash the scan |

---

## 6. Agent Skills Framework

Skills are filesystem-based instructions that extend Claude's capabilities. Unlike custom tools (code), skills are documentation that Claude reads and follows.

### What Skills Do

```
Without Skill:
  Claude: "I don't know how to validate IDOR vulnerabilities"

With authorization-testing Skill:
  Claude: [Reads SKILL.md]
  Claude: "I'll follow the test pattern in the skill..."
  Claude: [Executes HTTP tests correctly]
```

### Enabling Skills

```python
options = ClaudeAgentOptions(
    # REQUIRED: Enable filesystem settings
    setting_sources=["project"],  # Load from .claude/skills/
    
    # REQUIRED: Include Skill tool
    allowed_tools=["Skill", "Read", "Write", "Bash"],
    
    # REQUIRED: Set working directory
    cwd="/path/to/project"
)
```

### Skill Directory Structure

```
.claude/
└── skills/
    └── dast/                           # Skill category
        └── authorization-testing/       # Specific skill
            ├── SKILL.md                 # Main skill definition
            ├── examples.md              # Usage examples
            └── reference/               # Reference code
                ├── validate_idor.py
                └── README.md
```

---

## 7. Creating Custom Skills

### SKILL.md Structure

```markdown
---
name: my-custom-skill
description: What this skill does and when to use it. Include trigger words.
---

# Skill Name

## Purpose
[What this skill accomplishes]

## When to Use
[Trigger conditions - Claude uses this to decide when to load the skill]

## Methodology
[Step-by-step process]

## Input Requirements
[What the skill needs]

## Output Format
[Expected output structure]

## Examples
[Concrete examples]
```

### Real Example: Authorization Testing Skill

**File: `.claude/skills/dast/authorization-testing/SKILL.md`**

```markdown
---
name: authorization-testing
description: Validates IDOR and authorization bypass vulnerabilities via HTTP testing. Use when testing CWE-639, CWE-862, or CWE-269 vulnerabilities.
---

# Authorization Testing Skill

## Purpose
Validate authorization vulnerabilities by testing if one user can access another user's resources.

## Applicable CWEs
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-862: Missing Authorization
- CWE-269: Improper Privilege Management

## Test Methodology

### 1. Establish Baseline
```bash
# Authenticate as User A
curl -X POST $TARGET/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "userA@test.com", "password": "testpass"}' \
  -c cookies.txt
```

### 2. Access Own Resource (Should Succeed)
```bash
curl -X GET $TARGET/api/user/123/profile \
  -b cookies.txt
# Expected: 200 OK with User A's data
```

### 3. Access Other User's Resource (Should Fail)
```bash
curl -X GET $TARGET/api/user/456/profile \
  -b cookies.txt
# Expected: 403 Forbidden
# If 200 OK: VULNERABILITY CONFIRMED
```

## Validation Status Codes
- **VALIDATED**: Got 200 when should get 403 - vulnerability confirmed
- **FALSE_POSITIVE**: Got 403/401 as expected - properly protected
- **UNVALIDATED**: Error, timeout, or can't determine
```

### SecureVibes Skill Bundling

SecureVibes automatically copies skills to target projects:

```python
def _setup_dast_skills(self, repo: Path):
    """Copy DAST skills to target project."""
    import shutil
    
    target_skills_dir = repo / ".claude" / "skills" / "dast"
    
    if target_skills_dir.exists():
        return  # Already present
    
    # Get skills from package installation
    package_skills_dir = Path(__file__).parent.parent / "skills" / "dast"
    
    # Copy to target project
    target_skills_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(package_skills_dir, target_skills_dir, dirs_exist_ok=True)
```

---

## 8. Cost Tracking and Budget Management

### Basic Cost Tracking

```python
from claude_agent_sdk.types import ResultMessage

async def track_costs():
    total_cost = 0.0
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        
        async for message in client.receive_messages():
            if isinstance(message, ResultMessage):
                if message.total_cost_usd:
                    total_cost = message.total_cost_usd
                    print(f"💰 Total cost: ${total_cost:.4f}")
                
                if message.usage:
                    print(f"   Input tokens: {message.usage.input_tokens}")
                    print(f"   Output tokens: {message.usage.output_tokens}")
                break
    
    return total_cost
```

### Real-Time Cost Updates (SecureVibes Pattern)

```python
class Scanner:
    def __init__(self):
        self.total_cost = 0.0
    
    async def _execute_scan(self, repo):
        async with ClaudeSDKClient(options=options) as client:
            await client.query(orchestration_prompt)
            
            async for message in client.receive_messages():
                # ... handle other message types ...
                
                elif isinstance(message, ResultMessage):
                    # Update running cost total
                    if message.total_cost_usd:
                        self.total_cost = message.total_cost_usd
                        
                        if self.debug:
                            self.console.print(
                                f"  💰 Cost: ${self.total_cost:.4f}",
                                style="cyan"
                            )
                    break
```

### Budget Management

```python
class BudgetManager:
    """Enforce spending limits."""
    
    def __init__(self, max_budget: float):
        self.max_budget = max_budget
        self.spent = 0.0
    
    async def check_budget(self, message):
        """Call this on each ResultMessage."""
        if isinstance(message, ResultMessage) and message.total_cost_usd:
            self.spent = message.total_cost_usd
            
            if self.spent > self.max_budget:
                raise BudgetExceededError(
                    f"Budget exceeded: ${self.spent:.4f} > ${self.max_budget:.4f}"
                )
    
    def get_remaining(self) -> float:
        return max(0, self.max_budget - self.spent)

# Usage
budget = BudgetManager(max_budget=5.00)

async for message in client.receive_messages():
    await budget.check_budget(message)
    # ... rest of processing
```

### Cost Estimation

Different models have different costs:

| Model | Input Cost | Output Cost | Speed | Quality |
|-------|------------|-------------|-------|---------|
| Haiku | Lowest | Lowest | Fastest | Good |
| Sonnet | Medium | Medium | Medium | Better |
| Opus | Highest | Highest | Slowest | Best |

Strategy for cost optimization:
```python
# Use cheaper models for simple tasks
agents = {
    "assessment": AgentDefinition(
        model="haiku",  # Fast/cheap for exploration
        ...
    ),
    "code-review": AgentDefinition(
        model="opus",   # Thorough for security analysis
        ...
    ),
    "report-generator": AgentDefinition(
        model="haiku",  # Simple formatting task
        ...
    )
}
```

---

## 9. Error Handling Strategies

### SDK Exceptions

```python
from claude_agent_sdk import (
    ClaudeSDKError,      # Base exception
    CLINotFoundError,    # Claude CLI not installed
    CLIConnectionError,  # Connection issues
    ProcessError,        # Process failed
    CLIJSONDecodeError,  # JSON parsing issues
)

async def robust_scan():
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            async for msg in client.receive_messages():
                process(msg)
    
    except CLINotFoundError:
        print("❌ Claude CLI not installed")
        print("   Run: npm install -g @anthropic-ai/claude-code")
    
    except CLIConnectionError as e:
        print(f"❌ Connection failed: {e}")
        print("   Check your API key and network")
    
    except ProcessError as e:
        print(f"❌ Process failed (exit {e.exit_code})")
        print(f"   Error: {e.stderr}")
    
    except ClaudeSDKError as e:
        print(f"❌ SDK error: {e}")
```

### Retry Pattern

```python
import asyncio

async def query_with_retry(prompt: str, max_retries: int = 3):
    """Retry on transient failures."""
    
    for attempt in range(max_retries):
        try:
            async for msg in query(prompt=prompt, options=options):
                yield msg
            return  # Success
        
        except (CLIConnectionError, ProcessError) as e:
            if attempt == max_retries - 1:
                raise  # Final attempt failed
            
            wait = 2 ** attempt  # Exponential backoff
            print(f"⚠️ Retry {attempt + 1}/{max_retries} in {wait}s...")
            await asyncio.sleep(wait)
```

### Graceful Degradation (SecureVibes Pattern)

```python
async def _execute_scan(self, repo):
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(orchestration_prompt)
            
            async for message in client.receive_messages():
                # Process messages
                pass
    
    except Exception as e:
        self.console.print(f"\n❌ Scan failed: {e}", style="bold red")
        raise
    
    # Try to load partial results
    try:
        return self._load_scan_results(securevibes_dir, ...)
    except RuntimeError as e:
        self.console.print(f"❌ Error loading results: {e}", style="bold red")
        raise
```

---

## 10. Advanced Configuration

### Environment Variables

SecureVibes configuration pattern:

```python
import os

class AgentConfig:
    DEFAULTS = {
        "assessment": "sonnet",
        "threat_modeling": "sonnet",
        "code_review": "sonnet",
        "report_generator": "sonnet",
        "dast": "sonnet"
    }
    
    DEFAULT_MAX_TURNS = 50
    
    @classmethod
    def get_agent_model(cls, agent_name: str, cli_override: str = None) -> str:
        """
        Priority:
        1. Environment variable (highest)
        2. CLI override
        3. Default (lowest)
        """
        # Check SECUREVIBES_ASSESSMENT_MODEL, etc.
        env_var = f"SECUREVIBES_{agent_name.upper()}_MODEL"
        env_value = os.getenv(env_var)
        
        if env_value:
            return env_value
        if cli_override:
            return cli_override
        return cls.DEFAULTS.get(agent_name, "sonnet")
    
    @classmethod
    def get_max_turns(cls) -> int:
        """Get from SECUREVIBES_MAX_TURNS or default."""
        try:
            return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
        except ValueError:
            return cls.DEFAULT_MAX_TURNS
```

### Language-Aware Exclusions

```python
class ScanConfig:
    """Smart exclusions based on detected languages."""
    
    EXCLUDED_DIRS_PYTHON = {"venv", ".venv", "__pycache__", ".pytest_cache"}
    EXCLUDED_DIRS_JS = {"node_modules", ".next", ".nuxt"}
    EXCLUDED_DIRS_GO = {"vendor", "bin"}
    EXCLUDED_DIRS_COMMON = {".git", "dist", "build"}
    
    @classmethod
    def get_excluded_dirs(cls, languages: set = None) -> set:
        """Get exclusions based on detected languages."""
        dirs = cls.EXCLUDED_DIRS_COMMON.copy()
        
        if languages is None:
            # Unknown - include all
            dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            dirs.update(cls.EXCLUDED_DIRS_JS)
            dirs.update(cls.EXCLUDED_DIRS_GO)
        else:
            if "python" in languages:
                dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            if "javascript" in languages or "typescript" in languages:
                dirs.update(cls.EXCLUDED_DIRS_JS)
            if "go" in languages:
                dirs.update(cls.EXCLUDED_DIRS_GO)
        
        return dirs
```

### Dynamic Permission Control

```python
class PermissionManager:
    """Runtime permission decisions."""
    
    def __init__(self):
        self.allowed_paths = ["/project/src", "/project/tests"]
        self.blocked_commands = ["rm -rf", "format", "dd"]
    
    async def check_permission(self, tool_name: str, tool_input: dict):
        """Hook-compatible permission checker."""
        
        if tool_name == "Write":
            file_path = tool_input.get("file_path", "")
            if not any(file_path.startswith(p) for p in self.allowed_paths):
                return False, "Write not allowed to this path"
        
        if tool_name == "Bash":
            command = tool_input.get("command", "")
            for blocked in self.blocked_commands:
                if blocked in command:
                    return False, f"Blocked command: {blocked}"
        
        return True, None

# Use in hook
manager = PermissionManager()

async def permission_hook(input_data, tool_use_id, ctx):
    allowed, reason = await manager.check_permission(
        input_data.get("tool_name"),
        input_data.get("tool_input", {})
    )
    
    if not allowed:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }
    return {}
```

---

## Summary

| Feature | Purpose | Key Points |
|---------|---------|------------|
| **PreToolUse Hooks** | Security/validation | Can deny, modify, or override |
| **PostToolUse Hooks** | Monitoring/logging | Observes tool results |
| **SubagentStop Hooks** | Phase tracking | Knows when agents complete |
| **Skills** | Extend capabilities | Filesystem-based instructions |
| **Cost Tracking** | Budget management | Via ResultMessage |
| **Error Handling** | Graceful failures | Specific exception types |

---

## Next Steps

Now that you understand advanced features, proceed to:
- **[Phase 5: SecureVibes Deep Dive](PHASE5_SECUREVIBES_DEEP_DIVE.md)** - Complete flow analysis

