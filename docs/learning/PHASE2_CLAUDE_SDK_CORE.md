# Phase 2: Claude Agent SDK Core Concepts

This tutorial teaches the fundamental concepts of the Claude Agent SDK - the foundation for building AI agents like SecureVibes.

---

## Table of Contents

1. [What is the Claude Agent SDK?](#1-what-is-the-claude-agent-sdk)
2. [Installation and Setup](#2-installation-and-setup)
3. [Authentication](#3-authentication)
4. [The query() Function - Simplest Usage](#4-the-query-function---simplest-usage)
5. [ClaudeAgentOptions - Configuration](#5-claudeagentoptions---configuration)
6. [Message Types Deep Dive](#6-message-types-deep-dive)
7. [Built-in Tools](#7-built-in-tools)
8. [ClaudeSDKClient - Advanced Usage](#8-claudesdkclient---advanced-usage)
9. [Handling Responses](#9-handling-responses)
10. [Practical Examples](#10-practical-examples)

---

## 1. What is the Claude Agent SDK?

The Claude Agent SDK is a Python library that provides programmatic access to Claude Code capabilities. It allows you to:

- **Execute Claude as an autonomous agent** - Claude can use tools, read/write files, run commands
- **Build multi-agent systems** - Define specialized agents that work together
- **Stream responses in real-time** - Get live updates as Claude works
- **Track costs and usage** - Monitor API consumption
- **Control permissions** - Fine-grained control over what Claude can do

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Python Code                         │
├─────────────────────────────────────────────────────────────┤
│                    Claude Agent SDK                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ ClaudeSDKClient │  │ AgentDefinition │  │    Hooks     │ │
│  │                 │  │                 │  │              │ │
│  │ - query()       │  │ - description   │  │ - PreToolUse │ │
│  │ - receive_msgs  │  │ - prompt        │  │ - PostToolUse│ │
│  │ - options       │  │ - tools         │  │ - Subagent   │ │
│  └────────┬────────┘  └─────────────────┘  └──────────────┘ │
│           │                                                  │
├───────────┼─────────────────────────────────────────────────┤
│           ▼                                                  │
│     Claude Code CLI (Node.js)                               │
│     - Manages Claude API connection                         │
│     - Executes tools (Read, Write, Bash, etc.)              │
│     - Handles permissions                                    │
├─────────────────────────────────────────────────────────────┤
│                    Anthropic API                             │
│     - Claude AI model (Sonnet, Haiku, Opus)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Installation and Setup

### Prerequisites

- Python 3.10 or higher
- Node.js (for Claude Code CLI)
- An Anthropic API key

### Installation Steps

```bash
# 1. Install Claude Code CLI globally
npm install -g @anthropic-ai/claude-code

# 2. Install the Python SDK
pip install claude-agent-sdk

# 3. Verify installation
python -c "from claude_agent_sdk import query; print('SDK installed!')"
```

### Verify Claude CLI

```bash
# Check Claude Code version
claude --version
# Should show: Claude Code CLI version 2.x.x
```

---

## 3. Authentication

The SDK supports multiple authentication methods:

### Method 1: API Key (Recommended for Development)

```bash
# Set environment variable
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Windows PowerShell
$env:ANTHROPIC_API_KEY="sk-ant-api03-..."
```

### Method 2: Session-based (Recommended for Personal Use)

```bash
# Run Claude CLI and login interactively
claude
# Then type: /login
# Follow the prompts to authenticate
```

### Verifying Authentication

```python
import asyncio
from claude_agent_sdk import query

async def test_auth():
    async for message in query(prompt="Say hello"):
        print(message)

# If this works, authentication is configured
asyncio.run(test_auth())
```

---

## 4. The query() Function - Simplest Usage

The `query()` function is the simplest way to interact with Claude.

### Basic Query

```python
import asyncio
from claude_agent_sdk import query

async def main():
    # query() returns an async generator
    async for message in query(prompt="What is 2 + 2?"):
        print(message)

asyncio.run(main())
```

### Extracting Text Responses

```python
from claude_agent_sdk import query
from claude_agent_sdk.types import AssistantMessage, TextBlock

async def get_response():
    async for message in query(prompt="Explain Python decorators briefly"):
        # Check if it's Claude's response
        if isinstance(message, AssistantMessage):
            # Extract text blocks
            for block in message.content:
                if isinstance(block, TextBlock):
                    print(block.text)

asyncio.run(get_response())
```

---

## 5. ClaudeAgentOptions - Configuration

`ClaudeAgentOptions` configures how Claude behaves.

### All Available Options

```python
from claude_agent_sdk import ClaudeAgentOptions

options = ClaudeAgentOptions(
    # Working directory for file operations
    cwd="/path/to/project",
    
    # System prompt - Claude's personality/instructions
    system_prompt="You are a security expert.",
    
    # Which tools Claude can use
    allowed_tools=["Read", "Write", "Bash", "Grep", "Glob", "LS"],
    
    # Permission mode
    # 'default' - Ask for permission
    # 'acceptEdits' - Auto-accept file edits
    # 'bypassPermissions' - Allow everything (use carefully!)
    permission_mode='acceptEdits',
    
    # Maximum conversation turns
    max_turns=50,
    
    # Model to use: "sonnet", "haiku", "opus"
    model="sonnet",
    
    # Subagent definitions (covered in Phase 3)
    agents={...},
    
    # Hook functions (covered in Phase 4)
    hooks={...},
    
    # Enable filesystem settings (.claude/settings.json)
    setting_sources=["project"],  # Required for Skills
)
```

### Real Example from SecureVibes

```python
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import HookMatcher

options = ClaudeAgentOptions(
    # Define specialized agents
    agents=agents,
    
    # Set working directory to target repo
    cwd=str(repo),
    
    # Enable skills loading from .claude/skills/
    setting_sources=["project"],
    
    # Tools available globally
    allowed_tools=["Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob", "LS"],
    
    # Max reasoning iterations
    max_turns=config.get_max_turns(),  # Default: 50
    
    # Auto-accept all operations (for automation)
    permission_mode='bypassPermissions',
    
    # Use specified model
    model=self.model,
    
    # Attach monitoring hooks
    hooks={
        "PreToolUse": [
            HookMatcher(hooks=[dast_security_hook]),
            HookMatcher(hooks=[pre_tool_hook])
        ],
        "PostToolUse": [HookMatcher(hooks=[post_tool_hook])],
        "SubagentStop": [HookMatcher(hooks=[subagent_hook])]
    }
)
```

---

## 6. Message Types Deep Dive

The SDK uses strongly-typed messages. Understanding them is crucial.

### Import Message Types

```python
from claude_agent_sdk.types import (
    AssistantMessage,   # Claude's responses
    UserMessage,        # Your prompts
    SystemMessage,      # System instructions
    ResultMessage,      # Final result with usage data
    TextBlock,          # Text content
    ToolUseBlock,       # Tool invocation
    ToolResultBlock,    # Tool result
)
```

### AssistantMessage

Claude's response containing text and/or tool calls:

```python
async for message in client.receive_messages():
    if isinstance(message, AssistantMessage):
        # message.content is a list of blocks
        for block in message.content:
            if isinstance(block, TextBlock):
                # Claude is speaking
                print(f"Claude says: {block.text}")
            
            elif isinstance(block, ToolUseBlock):
                # Claude is using a tool
                print(f"Tool: {block.name}")
                print(f"Input: {block.input}")
                # block.id - unique identifier for this tool use
```

### ResultMessage

Final message with usage statistics:

```python
elif isinstance(message, ResultMessage):
    # Scan is complete
    print(f"Total cost: ${message.total_cost_usd:.4f}")
    
    if message.usage:
        print(f"Input tokens: {message.usage.input_tokens}")
        print(f"Output tokens: {message.usage.output_tokens}")
```

### Message Flow Diagram

```
Your Code                SDK                    Claude API
    │                     │                         │
    ├──query(prompt)─────►│                         │
    │                     ├───────Request──────────►│
    │                     │                         │
    │                     │◄──AssistantMessage──────┤ (Claude speaks)
    │◄──AssistantMessage──┤                         │
    │                     │                         │
    │                     │◄──ToolUseBlock──────────┤ (Claude calls tool)
    │                     │                         │
    │                     │   [SDK executes tool]   │
    │                     │                         │
    │                     │───ToolResultBlock──────►│ (Tool result)
    │                     │                         │
    │                     │◄──AssistantMessage──────┤ (Claude continues)
    │◄──AssistantMessage──┤                         │
    │                     │                         │
    │                     │◄──ResultMessage─────────┤ (Complete)
    │◄──ResultMessage─────┤                         │
    │                     │                         │
```

---

## 7. Built-in Tools

Claude can use these tools to interact with the filesystem and system.

### Tool Reference

| Tool | Purpose | Parameters |
|------|---------|------------|
| `Read` | Read file contents | `file_path: str` |
| `Write` | Create/overwrite file | `file_path: str, content: str` |
| `Edit` | Edit existing file | `file_path: str, changes: ...` |
| `Bash` | Execute shell command | `command: str` |
| `Grep` | Search file contents | `pattern: str, path: str` |
| `Glob` | Find files by pattern | `patterns: List[str]` |
| `LS` | List directory | `directory_path: str` |
| `Skill` | Invoke agent skill | `skill_name: str, ...` |
| `Task` | Invoke subagent | `agent_name: str, prompt: str` |

### Configuring Allowed Tools

```python
# Only allow read-only operations
options = ClaudeAgentOptions(
    allowed_tools=["Read", "Grep", "Glob", "LS"]
)

# Allow file modifications
options = ClaudeAgentOptions(
    allowed_tools=["Read", "Write", "Edit"]
)

# Full system access (use carefully!)
options = ClaudeAgentOptions(
    allowed_tools=["Read", "Write", "Edit", "Bash", "Grep", "Glob", "LS"]
)
```

### Example: Claude Using Tools

When Claude decides to use a tool, you'll see a `ToolUseBlock`:

```python
async for message in client.receive_messages():
    if isinstance(message, AssistantMessage):
        for block in message.content:
            if isinstance(block, ToolUseBlock):
                print(f"Claude is using: {block.name}")
                
                if block.name == "Read":
                    print(f"  Reading file: {block.input.get('file_path')}")
                
                elif block.name == "Bash":
                    print(f"  Running command: {block.input.get('command')}")
                
                elif block.name == "Write":
                    path = block.input.get('file_path')
                    print(f"  Writing to: {path}")
```

---

## 8. ClaudeSDKClient - Advanced Usage

`ClaudeSDKClient` provides full control for interactive, multi-turn conversations.

### Basic Client Usage

```python
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions

async def interactive_session():
    options = ClaudeAgentOptions(
        system_prompt="You are a helpful coding assistant",
        allowed_tools=["Read", "Write", "Bash"],
        permission_mode='acceptEdits'
    )
    
    # Use async context manager for proper cleanup
    async with ClaudeSDKClient(options=options) as client:
        # Send first query
        await client.query("Analyze the security of this codebase")
        
        # Receive all messages
        async for message in client.receive_messages():
            process_message(message)
        
        # Continue the conversation (same context)
        await client.query("Now focus on authentication vulnerabilities")
        
        async for message in client.receive_messages():
            process_message(message)
```

### Real Example from SecureVibes

```python
class Scanner:
    async def _execute_scan(self, repo: Path) -> ScanResult:
        # Build options with agents and hooks
        options = ClaudeAgentOptions(
            agents=agents,
            cwd=str(repo),
            setting_sources=["project"],
            allowed_tools=["Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob", "LS"],
            max_turns=config.get_max_turns(),
            permission_mode='bypassPermissions',
            model=self.model,
            hooks={
                "PreToolUse": [HookMatcher(hooks=[pre_tool_hook])],
                "PostToolUse": [HookMatcher(hooks=[post_tool_hook])],
                "SubagentStop": [HookMatcher(hooks=[subagent_hook])]
            }
        )
        
        # Load the orchestration prompt
        orchestration_prompt = load_prompt("main", category="orchestration")
        
        try:
            # Create client and run scan
            async with ClaudeSDKClient(options=options) as client:
                # Send the orchestration instructions
                await client.query(orchestration_prompt)
                
                # Process all messages until complete
                async for message in client.receive_messages():
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                tracker.on_assistant_text(block.text)
                    
                    elif isinstance(message, ResultMessage):
                        if message.total_cost_usd:
                            self.total_cost = message.total_cost_usd
                        break  # Scan complete
        
        except Exception as e:
            self.console.print(f"\n❌ Scan failed: {e}")
            raise
        
        return self._load_scan_results(...)
```

---

## 9. Handling Responses

### Pattern: Processing All Message Types

```python
from claude_agent_sdk.types import (
    AssistantMessage, ResultMessage, TextBlock, ToolUseBlock
)

async def process_messages(client):
    async for message in client.receive_messages():
        
        if isinstance(message, AssistantMessage):
            for block in message.content:
                
                if isinstance(block, TextBlock):
                    # Claude's text output
                    handle_text(block.text)
                
                elif isinstance(block, ToolUseBlock):
                    # Claude using a tool
                    handle_tool_use(block.name, block.input)
        
        elif isinstance(message, ResultMessage):
            # Conversation complete
            handle_completion(message)
            break
```

### Pattern: Collecting Final Results

```python
async def run_and_collect():
    results = {
        "text_output": [],
        "tools_used": [],
        "total_cost": 0.0
    }
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        
        async for message in client.receive_messages():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        results["text_output"].append(block.text)
                    elif isinstance(block, ToolUseBlock):
                        results["tools_used"].append({
                            "tool": block.name,
                            "input": block.input
                        })
            
            elif isinstance(message, ResultMessage):
                results["total_cost"] = message.total_cost_usd or 0.0
                break
    
    return results
```

---

## 10. Practical Examples

### Example 1: Simple Code Analyzer

```python
import asyncio
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import AssistantMessage, TextBlock, ResultMessage

async def analyze_code(file_path: str):
    """Analyze a Python file for potential issues."""
    
    options = ClaudeAgentOptions(
        system_prompt="You are a code quality expert. Analyze code for bugs and improvements.",
        allowed_tools=["Read"],
        permission_mode='default',
        max_turns=10
    )
    
    prompt = f"Please analyze the code in {file_path} and list any issues you find."
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        
        analysis = []
        async for message in client.receive_messages():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        analysis.append(block.text)
            
            elif isinstance(message, ResultMessage):
                print(f"\n💰 Cost: ${message.total_cost_usd:.4f}")
                break
        
        return "\n".join(analysis)

# Run it
result = asyncio.run(analyze_code("./src/main.py"))
print(result)
```

### Example 2: File Generator

```python
async def generate_readme(project_path: str):
    """Generate a README.md for a project."""
    
    options = ClaudeAgentOptions(
        cwd=project_path,
        system_prompt="You are a technical writer. Create clear, comprehensive documentation.",
        allowed_tools=["Read", "Write", "Glob", "LS"],
        permission_mode='acceptEdits',
        max_turns=20
    )
    
    prompt = """
    Analyze this project and create a README.md with:
    1. Project description
    2. Installation instructions
    3. Usage examples
    4. File structure overview
    
    Write the README.md file when done.
    """
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        
        async for message in client.receive_messages():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        print(f"📝 {block.text[:100]}...")
            
            elif isinstance(message, ResultMessage):
                print(f"\n✅ README.md generated! Cost: ${message.total_cost_usd:.4f}")
                break

asyncio.run(generate_readme("./my-project"))
```

### Example 3: Security Scanner (Simplified)

```python
async def simple_security_scan(repo_path: str):
    """Simple security scan using Claude."""
    
    options = ClaudeAgentOptions(
        cwd=repo_path,
        system_prompt="""You are a security expert. Find vulnerabilities in code.
        Focus on: SQL injection, XSS, hardcoded secrets, insecure configurations.""",
        allowed_tools=["Read", "Grep", "Glob", "LS"],
        permission_mode='default',
        max_turns=30
    )
    
    prompt = """
    Scan this codebase for security vulnerabilities.
    
    1. First, list all source code files
    2. Search for common vulnerability patterns
    3. Read suspicious files and analyze them
    4. Report findings in this format:
       - Title
       - Severity (Critical/High/Medium/Low)
       - File and line number
       - Description
       - Recommendation
    """
    
    findings = []
    
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        
        async for message in client.receive_messages():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        findings.append(block.text)
            
            elif isinstance(message, ResultMessage):
                break
    
    return "\n".join(findings)

# Run the scan
report = asyncio.run(simple_security_scan("./vulnerable-app"))
print(report)
```

---

## Summary

| Concept | Purpose | Key Points |
|---------|---------|------------|
| `query()` | Simple one-shot queries | Returns async generator of messages |
| `ClaudeAgentOptions` | Configure Claude's behavior | Tools, permissions, model, hooks |
| `ClaudeSDKClient` | Advanced interactive sessions | Multi-turn, streaming, full control |
| `AssistantMessage` | Claude's responses | Contains `TextBlock` and `ToolUseBlock` |
| `ResultMessage` | Completion signal | Contains cost and usage data |
| Built-in Tools | Claude's capabilities | Read, Write, Bash, Grep, etc. |

---

## Next Steps

Now that you understand SDK basics, proceed to:
- **[Phase 3: Multi-Agent Architecture](PHASE3_MULTI_AGENT_ARCHITECTURE.md)** - Build systems with multiple specialized agents

