# SecureVibes Knowledge Transfer Guide

A comprehensive learning path from Python fundamentals to building autonomous multi-agent AI systems using the Claude Agent SDK.

---

## Overview

This guide takes you through 6 phases of learning, building upon each phase to help you master:

1. **Python foundations** for agent development
2. **Claude Agent SDK** core concepts
3. **Multi-agent architecture** patterns
4. **Advanced features** (hooks, skills, cost tracking)
5. **SecureVibes implementation** deep dive
6. **Building your own** penetration testing system

---

## Learning Path

```
Phase 1: Python       →  Phase 2: SDK Core  →  Phase 3: Multi-Agent
(Foundations)            (Basic Usage)          (Architecture)
     │                        │                       │
     └────────────────────────┴───────────────────────┘
                              │
                              ▼
Phase 4: Advanced     →  Phase 5: SecureVibes  →  Phase 6: PenTest
(Hooks, Skills)          (Deep Dive)              (Build Your Own)
```

---

## Phase Guides

### [Phase 1: Python Foundations](PHASE1_PYTHON_FOUNDATIONS.md)

**Duration:** ~1 week | **Prerequisites:** None

Learn essential Python concepts:
- Type hints and annotations
- Enums and dataclasses
- Async/await programming
- Path handling and configuration
- Context managers and generators

### [Phase 2: Claude SDK Core](PHASE2_CLAUDE_SDK_CORE.md)

**Duration:** ~1 week | **Prerequisites:** Phase 1

Master SDK fundamentals:
- Installation and authentication
- The `query()` function
- `ClaudeAgentOptions` configuration
- Message types (`AssistantMessage`, `ResultMessage`)
- Built-in tools (Read, Write, Bash, etc.)
- `ClaudeSDKClient` for advanced usage

### [Phase 3: Multi-Agent Architecture](PHASE3_MULTI_AGENT_ARCHITECTURE.md)

**Duration:** ~1-2 weeks | **Prerequisites:** Phases 1-2

Build multi-agent systems:
- `AgentDefinition` structure
- Orchestration prompts
- Agent communication via artifacts
- The Task tool for subagent invocation
- Pipeline design patterns

### [Phase 4: Advanced Features](PHASE4_ADVANCED_FEATURES.md)

**Duration:** ~1 week | **Prerequisites:** Phases 1-3

Master advanced SDK features:
- Hooks system (PreToolUse, PostToolUse, SubagentStop)
- Agent Skills framework
- Custom skill creation
- Cost tracking and budget management
- Error handling strategies

### [Phase 5: SecureVibes Deep Dive](PHASE5_SECUREVIBES_DEEP_DIVE.md)

**Duration:** ~1-2 weeks | **Prerequisites:** Phases 1-4

Complete code walkthrough:
- Project structure analysis
- CLI entry point
- Scanner class internals
- Agent definitions
- Prompt engineering patterns
- Data models
- Configuration system
- Testing approach

### [Phase 6: Build PenTest System](PHASE6_PENTEST_SYSTEM.md)

**Duration:** ~2-3 weeks | **Prerequisites:** All phases

Apply your knowledge:
- System architecture design
- PenTest agent definitions
- Prompt engineering for security testing
- Safety hooks implementation
- Exploitation skills
- Complete implementation code
- Testing and safety guidelines

---

## Quick Reference

### Key SecureVibes Files

| File | Purpose |
|------|---------|
| `cli/main.py` | Entry point |
| `scanner/scanner.py` | Core orchestration |
| `agents/definitions.py` | Agent configs |
| `prompts/agents/*.txt` | Agent prompts |
| `prompts/orchestration/main.txt` | Orchestration |
| `scanner/hooks.py` | Security/monitoring |
| `config.py` | Configuration |
| `models/*.py` | Data structures |

### Essential SDK Imports

```python
from claude_agent_sdk import (
    ClaudeSDKClient,
    ClaudeAgentOptions,
    AgentDefinition,
    query
)

from claude_agent_sdk.types import (
    AssistantMessage,
    TextBlock,
    ToolUseBlock,
    ResultMessage,
    HookMatcher
)
```

### Agent Definition Template

```python
AgentDefinition(
    description="What this agent does",
    prompt="Detailed instructions...",
    tools=["Read", "Write", ...],
    model="sonnet"
)
```

### Hook Template

```python
async def my_hook(input_data: dict, tool_use_id: str, ctx: dict) -> dict:
    tool_name = input_data.get("tool_name")
    tool_input = input_data.get("tool_input", {})
    
    # Return {} to allow
    # Return {"hookSpecificOutput": {...}} to deny/modify
    return {}
```

---

## Recommended Schedule

| Week | Focus | Deliverable |
|------|-------|-------------|
| 1 | Python basics, Phase 1 | Understand SecureVibes models |
| 2 | Claude SDK, Phase 2 | Build "hello world" agent |
| 3 | Multi-agent, Phase 3 | Create 2-agent pipeline |
| 4 | Advanced, Phase 4 | Add hooks to pipeline |
| 5 | SecureVibes, Phase 5 | Run and modify SecureVibes |
| 6-8 | PenTest, Phase 6 | Build working pentest tool |

---

## Additional Resources

### In This Repository

- [Architecture Overview](../ARCHITECTURE.md)
- [Claude SDK Guide](../references/claude-agent-sdk-guide.md)
- [Agent Skills Guide](../references/AGENT_SKILLS_GUIDE.md)
- [DAST Guide](../DAST_GUIDE.md)
- [Example Reports](../example-reports/)

### External Resources

- [Claude Agent SDK Documentation](https://docs.anthropic.com/en/api/agent-sdk/overview)
- [Claude Agent SDK GitHub](https://github.com/anthropics/claude-agent-sdk-python)
- [SecureVibes GitHub](https://github.com/anshumanbh/securevibes)

---

## Getting Help

If you get stuck:

1. **Re-read the relevant phase** - Each phase builds on previous ones
2. **Check the SecureVibes code** - Real examples are the best teachers
3. **Experiment** - Try modifying small parts and observe changes
4. **Run with --debug** - See exactly what Claude is doing

---

## Contributing

Found an error or have suggestions? Contributions welcome!

---

*Happy learning! 🚀*

