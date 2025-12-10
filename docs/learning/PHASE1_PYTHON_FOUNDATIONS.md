# Phase 1: Python Foundations for Agent Development

This tutorial teaches Python concepts essential for understanding SecureVibes and building AI agent systems with the Claude SDK. Each concept is explained with real examples from the SecureVibes codebase.

---

## Table of Contents

1. [Python Modules and Imports](#1-python-modules-and-imports)
2. [Type Hints and Annotations](#2-type-hints-and-annotations)
3. [Enums - Type-Safe Constants](#3-enums---type-safe-constants)
4. [Dataclasses - Structured Data Containers](#4-dataclasses---structured-data-containers)
5. [Path Handling with pathlib](#5-path-handling-with-pathlib)
6. [Environment Variables and Configuration](#6-environment-variables-and-configuration)
7. [Async/Await - Asynchronous Programming](#7-asyncawait---asynchronous-programming)
8. [Context Managers (async with)](#8-context-managers-async-with)
9. [Async Generators (async for)](#9-async-generators-async-for)
10. [Practice Exercises](#10-practice-exercises)

---

## 1. Python Modules and Imports

### What is a Module?

A Python module is simply a `.py` file containing code. When you write `import something`, Python finds and loads that module.

### Import Styles

```python
# Style 1: Import entire module
import os
import json

# Usage: os.getenv("MY_VAR"), json.loads(data)

# Style 2: Import specific items from a module
from pathlib import Path
from typing import Optional, Dict, Any, List

# Usage: Path("/some/path"), Optional[str]

# Style 3: Import with alias
from rich.console import Console as RichConsole

# Usage: RichConsole()
```

### Real Example from SecureVibes

**File: `packages/core/securevibes/scanner/scanner.py`**

```python
# Standard library imports (built into Python)
import os
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

# Third-party imports (installed via pip)
from rich.console import Console

# Claude SDK imports
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    ToolUseBlock,
    ToolResultBlock,
    TextBlock,
    ResultMessage
)

# Local project imports (from securevibes package)
from securevibes.agents.definitions import create_agent_definitions
from securevibes.models.result import ScanResult
from securevibes.models.issue import SecurityIssue, Severity
```

**Key Insight**: Imports are organized in groups:
1. Standard library (built-in Python modules)
2. Third-party packages (installed via pip)
3. Local project modules

---

## 2. Type Hints and Annotations

Type hints tell Python (and developers) what types of values are expected. They don't enforce anything at runtime but help with:
- Code documentation
- IDE autocompletion
- Static analysis tools

### Basic Type Hints

```python
# Simple types
name: str = "SecureVibes"
count: int = 42
is_valid: bool = True
cost: float = 2.5

# Function with type hints
def greet(name: str) -> str:
    return f"Hello, {name}!"

# The -> str means "this function returns a string"
```

### Common Type Constructs

```python
from typing import Optional, Dict, Any, List, Set, Tuple

# Optional[X] means "X or None"
def get_model(name: Optional[str] = None) -> str:
    if name is None:
        return "sonnet"  # default
    return name

# Dict[KeyType, ValueType] - dictionary with specific types
config: Dict[str, Any] = {
    "model": "sonnet",
    "max_turns": 50,
    "debug": True
}

# List[ItemType] - list of specific type
issues: List[str] = ["SQL Injection", "XSS", "CSRF"]

# Set[ItemType] - set of unique items
languages: Set[str] = {"python", "javascript", "go"}

# Tuple[Type1, Type2, ...] - fixed-length sequence
result: Tuple[bool, str] = (True, "Success")
```

### Real Example from SecureVibes

**File: `packages/core/securevibes/config.py`**

```python
from typing import Dict, Optional, Set

class AgentConfig:
    @classmethod
    def get_agent_model(cls, agent_name: str, cli_override: Optional[str] = None) -> str:
        """
        Get the model to use for a specific agent.
        
        Args:
            agent_name: Name of the agent (string, required)
            cli_override: Optional model from CLI (string or None)
            
        Returns:
            Model name as a string
        """
        # agent_name must be a string
        # cli_override can be a string OR None (that's what Optional means)
        # The function always returns a string
        
        env_var = f"SECUREVIBES_{agent_name.upper()}_MODEL"
        env_value = os.getenv(env_var)
        
        if env_value:
            return env_value
        if cli_override:
            return cli_override
        return cls.DEFAULTS.get(agent_name, "sonnet")
```

---

## 3. Enums - Type-Safe Constants

Enums (enumerations) define a fixed set of named values. They're better than plain strings because:
- Typos are caught by the IDE
- All valid values are documented in one place
- You can't accidentally use an invalid value

### Basic Enum

```python
from enum import Enum

# Define an enum
class Color(Enum):
    RED = "red"
    GREEN = "green"
    BLUE = "blue"

# Use it
my_color = Color.RED
print(my_color)        # Color.RED
print(my_color.value)  # "red"
print(my_color.name)   # "RED"

# Compare enums
if my_color == Color.RED:
    print("It's red!")
```

### Real Example from SecureVibes

**File: `packages/core/securevibes/models/issue.py`**

```python
from enum import Enum

class Severity(str, Enum):
    """Issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ValidationStatus(str, Enum):
    """DAST validation status"""
    VALIDATED = "VALIDATED"          # Successfully exploited
    FALSE_POSITIVE = "FALSE_POSITIVE" # Disproven by testing
    UNVALIDATED = "UNVALIDATED"      # Couldn't test
    PARTIAL = "PARTIAL"              # Mixed results
```

**Why `(str, Enum)`?**

By inheriting from both `str` and `Enum`, the enum values can be used like strings:

```python
severity = Severity.CRITICAL
print(severity.value)  # "critical"

# Can be used directly in JSON
import json
data = {"severity": severity.value}  # {"severity": "critical"}

# Can compare with strings
if severity.value == "critical":
    print("Critical issue!")
```

### Using Enums in Code

```python
# Creating from string value
severity_str = "high"
severity = Severity(severity_str)  # Severity.HIGH

# Converting to string
severity_value = severity.value  # "high"

# Iterating all values
for sev in Severity:
    print(f"{sev.name}: {sev.value}")
# Output:
# CRITICAL: critical
# HIGH: high
# MEDIUM: medium
# LOW: low
# INFO: info
```

---

## 4. Dataclasses - Structured Data Containers

Dataclasses automatically generate common methods (`__init__`, `__repr__`, etc.) for classes that primarily store data.

### Basic Dataclass

```python
from dataclasses import dataclass

@dataclass
class Person:
    name: str
    age: int
    email: str

# Python automatically creates __init__ for you
person = Person(name="Alice", age=30, email="alice@example.com")

# Also creates __repr__ for nice printing
print(person)  # Person(name='Alice', age=30, email='alice@example.com')

# And __eq__ for comparison
person2 = Person(name="Alice", age=30, email="alice@example.com")
print(person == person2)  # True
```

### Default Values and Optional Fields

```python
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class Config:
    # Required fields (no default)
    name: str
    
    # Optional fields with defaults
    debug: bool = False
    max_turns: int = 50
    
    # Optional field that can be None
    api_key: Optional[str] = None
    
    # Mutable defaults need field(default_factory=...)
    # WRONG: tags: List[str] = []  # This would share the list!
    # RIGHT:
    tags: List[str] = field(default_factory=list)

# Usage
config1 = Config(name="scanner")  # Uses all defaults
config2 = Config(name="scanner", debug=True, max_turns=100)
```

### Real Example from SecureVibes

**File: `packages/core/securevibes/models/issue.py`**

```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class SecurityIssue:
    """Represents a security vulnerability found in code"""
    
    # Required fields
    id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    
    # Optional fields with defaults
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    
    # DAST validation fields
    validation_status: Optional[ValidationStatus] = None
    dast_evidence: Optional[dict] = None
    exploitability_score: Optional[float] = None
    validated_at: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "id": self.id,
            "severity": self.severity.value,  # .value gets string from enum
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }
    
    @property
    def is_validated(self) -> bool:
        """Check if issue was validated by DAST"""
        return self.validation_status == ValidationStatus.VALIDATED
```

### Properties

The `@property` decorator creates a computed attribute that looks like a regular attribute but is calculated each time:

```python
@dataclass
class ScanResult:
    issues: List[SecurityIssue]
    
    @property
    def critical_count(self) -> int:
        """Count critical issues (computed on access)"""
        return sum(1 for issue in self.issues 
                   if issue.severity.value == "critical")

# Usage
result = ScanResult(issues=[...])
print(result.critical_count)  # Calls the property method
# No () needed - it looks like an attribute
```

---

## 5. Path Handling with pathlib

`pathlib.Path` provides object-oriented filesystem path handling that works across Windows, Mac, and Linux.

### Basic Path Operations

```python
from pathlib import Path

# Create paths
home = Path.home()                    # /Users/username or C:\Users\username
cwd = Path.cwd()                      # Current working directory
repo = Path("/path/to/repo")          # Absolute path
relative = Path("src/main.py")        # Relative path

# Combine paths with /
config_file = repo / "config" / "settings.json"
# Result: /path/to/repo/config/settings.json

# Get parts of a path
file = Path("/home/user/project/src/main.py")
print(file.name)      # "main.py"
print(file.stem)      # "main" (without extension)
print(file.suffix)    # ".py"
print(file.parent)    # /home/user/project/src
print(file.parts)     # ('/', 'home', 'user', 'project', 'src', 'main.py')
```

### Path Methods

```python
from pathlib import Path

path = Path("some/path")

# Check existence
path.exists()        # True/False
path.is_file()       # True if it's a file
path.is_dir()        # True if it's a directory

# Create directories
path.mkdir(parents=True, exist_ok=True)
# parents=True: create parent directories too
# exist_ok=True: don't error if already exists

# Read/Write files
content = path.read_text(encoding="utf-8")  # Read entire file as string
path.write_text("content", encoding="utf-8")  # Write string to file

# Find files
for py_file in Path(".").glob("**/*.py"):  # All .py files recursively
    print(py_file)

# Resolve to absolute path
absolute = path.resolve()
```

### Real Example from SecureVibes

**File: `packages/core/securevibes/scanner/scanner.py`**

```python
from pathlib import Path

async def scan(self, repo_path: str) -> ScanResult:
    # Convert string to Path and resolve to absolute
    repo = Path(repo_path).resolve()
    
    # Check if path exists
    if not repo.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    
    # Create output directory
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(exist_ok=True)
    
    # Find all Python files
    python_files = list(repo.glob("**/*.py"))
    
    # Read a results file
    results_file = securevibes_dir / "scan_results.json"
    if results_file.exists():
        with open(results_file) as f:
            data = json.load(f)
```

---

## 6. Environment Variables and Configuration

Environment variables let you configure applications without changing code. They're perfect for:
- API keys and secrets
- Environment-specific settings (dev vs prod)
- User preferences

### Basic Usage

```python
import os

# Get environment variable (returns None if not set)
api_key = os.getenv("ANTHROPIC_API_KEY")

# Get with default value
model = os.getenv("MODEL", "sonnet")  # "sonnet" if not set

# Check if set
if os.getenv("DEBUG"):
    print("Debug mode enabled")

# Set environment variable (in current process only)
os.environ["MY_VAR"] = "my_value"
```

### Real Example from SecureVibes

**File: `packages/core/securevibes/config.py`**

```python
import os
from typing import Dict, Optional

class AgentConfig:
    """Configuration for agent model selection and behavior"""
    
    # Default models for each agent
    DEFAULTS = {
        "assessment": "sonnet",
        "threat_modeling": "sonnet",
        "code_review": "sonnet",
        "report_generator": "sonnet"
    }
    
    DEFAULT_MAX_TURNS = 50
    
    @classmethod
    def get_agent_model(cls, agent_name: str, cli_override: Optional[str] = None) -> str:
        """
        Get model with priority:
        1. Environment variable (highest)
        2. CLI override
        3. Default value (lowest)
        """
        # Build env var name: SECUREVIBES_ASSESSMENT_MODEL
        env_var = f"SECUREVIBES_{agent_name.upper()}_MODEL"
        env_value = os.getenv(env_var)
        
        if env_value:
            return env_value  # Priority 1: env var
        if cli_override:
            return cli_override  # Priority 2: CLI
        return cls.DEFAULTS.get(agent_name, "sonnet")  # Priority 3: default
    
    @classmethod
    def get_max_turns(cls) -> int:
        """Get max turns from env var or default"""
        try:
            return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
        except ValueError:
            return cls.DEFAULT_MAX_TURNS

# Usage
config = AgentConfig()
model = config.get_agent_model("code_review", cli_override="haiku")
```

---

## 7. Async/Await - Asynchronous Programming

### Why Async?

The Claude SDK makes API calls over the internet. Without async:

```python
# Synchronous (blocking) - BAD for API calls
result1 = call_api()  # Wait 2 seconds
result2 = call_api()  # Wait 2 seconds
# Total: 4 seconds, blocked the whole time
```

With async:

```python
# Asynchronous (non-blocking) - GOOD for API calls
result1, result2 = await asyncio.gather(
    call_api(),  # Start call 1
    call_api()   # Start call 2 immediately
)
# Total: ~2 seconds, both run concurrently
```

### Basic Async Syntax

```python
import asyncio

# Define an async function with 'async def'
async def fetch_data(url: str) -> str:
    # Simulate API call (await suspends until complete)
    await asyncio.sleep(1)  # Non-blocking sleep
    return f"Data from {url}"

# Call async functions with 'await'
async def main():
    result = await fetch_data("https://api.example.com")
    print(result)

# Run the async function
asyncio.run(main())
```

### Key Rules

1. **`async def`** creates an async function (coroutine)
2. **`await`** pauses execution until the awaited thing completes
3. You can only use `await` inside an `async def` function
4. You need `asyncio.run()` to start the async event loop

### Real Example from SecureVibes

**File: `packages/core/securevibes/scanner/scanner.py`**

```python
import asyncio

class Scanner:
    async def scan(self, repo_path: str) -> ScanResult:
        """
        Run complete security scan with real-time progress streaming.
        """
        repo = Path(repo_path).resolve()
        
        # ... setup code ...
        
        # Execute scan with SDK client
        async with ClaudeSDKClient(options=options) as client:
            # Send query (await the async operation)
            await client.query(orchestration_prompt)
            
            # Process messages as they arrive
            async for message in client.receive_messages():
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            tracker.on_assistant_text(block.text)
                
                elif isinstance(message, ResultMessage):
                    if message.total_cost_usd:
                        self.total_cost = message.total_cost_usd
                    break  # Scan complete
        
        return self._load_scan_results(...)

# In CLI, run the async function
result = asyncio.run(scanner.scan("/path/to/repo"))
```

---

## 8. Context Managers (async with)

Context managers handle setup and cleanup automatically. The `with` statement ensures cleanup happens even if errors occur.

### Synchronous Context Manager

```python
# Without context manager - error-prone
file = open("data.txt", "r")
try:
    content = file.read()
finally:
    file.close()  # Must remember to close!

# With context manager - automatic cleanup
with open("data.txt", "r") as file:
    content = file.read()
# File automatically closed after the block
```

### Async Context Manager

For async resources (like network connections), use `async with`:

```python
# The SDK client is an async context manager
async with ClaudeSDKClient(options=options) as client:
    # client is connected and ready
    await client.query("Hello!")
    async for message in client.receive_messages():
        print(message)
# client is automatically cleaned up here
```

### Real Example from SecureVibes

```python
async def _execute_scan(self, repo: Path, ...) -> ScanResult:
    # Setup options
    options = ClaudeAgentOptions(
        agents=agents,
        cwd=str(repo),
        allowed_tools=["Read", "Write", "Bash", ...],
        max_turns=config.get_max_turns(),
        permission_mode='bypassPermissions',
        hooks={...}
    )
    
    # async with ensures proper connection handling
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(orchestration_prompt)
            
            async for message in client.receive_messages():
                # Process each message
                pass
                
    except Exception as e:
        self.console.print(f"\n❌ Scan failed: {e}")
        raise
    # Client connection is cleaned up automatically
```

---

## 9. Async Generators (async for)

An async generator yields values over time (like streaming API responses).

### Basic Async Generator

```python
async def count_slowly():
    """Async generator that yields numbers slowly"""
    for i in range(5):
        await asyncio.sleep(1)  # Wait 1 second
        yield i  # Yield (return) value and continue

async def main():
    # Consume with async for
    async for number in count_slowly():
        print(f"Got: {number}")
    # Output (one per second):
    # Got: 0
    # Got: 1
    # Got: 2
    # Got: 3
    # Got: 4
```

### Real Example: Processing SDK Messages

The Claude SDK streams messages as they arrive:

```python
async def _execute_scan(self, repo: Path) -> ScanResult:
    async with ClaudeSDKClient(options=options) as client:
        await client.query(orchestration_prompt)
        
        # client.receive_messages() is an async generator
        # Messages arrive as Claude processes the request
        async for message in client.receive_messages():
            
            # Check message type
            if isinstance(message, AssistantMessage):
                # Claude is speaking or using tools
                for block in message.content:
                    if isinstance(block, TextBlock):
                        # Claude's text response
                        print(f"Claude: {block.text}")
                    
                    elif isinstance(block, ToolUseBlock):
                        # Claude is calling a tool
                        print(f"Tool: {block.name}")
            
            elif isinstance(message, ResultMessage):
                # Final message with usage/cost data
                print(f"Cost: ${message.total_cost_usd}")
                break  # Exit the loop
```

---

## 10. Practice Exercises

### Exercise 1: Create a Security Finding Dataclass

Create a dataclass that represents a bug bounty finding:

```python
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

class BugSeverity(Enum):
    # Define severity levels: P1, P2, P3, P4, P5
    pass

@dataclass
class BugBountyFinding:
    # Required: title, severity, url, description
    # Optional: steps_to_reproduce, impact, cwe_id, bounty_amount
    pass
```

### Exercise 2: Configuration System

Create a config class that reads from environment variables:

```python
class BugBountyConfig:
    @classmethod
    def get_target_scope(cls) -> List[str]:
        """Read TARGETS env var (comma-separated) or return default"""
        pass
    
    @classmethod
    def get_api_key(cls) -> Optional[str]:
        """Read HACKERONE_API_KEY env var"""
        pass
```

### Exercise 3: Async File Scanner

Create an async function that scans files:

```python
import asyncio
from pathlib import Path

async def scan_files(directory: str) -> List[str]:
    """
    Scan directory for interesting files.
    Return list of file paths containing 'password' or 'secret'.
    """
    results = []
    path = Path(directory)
    
    for file in path.glob("**/*.py"):
        content = file.read_text()
        # Check for patterns...
    
    return results

# Run it
findings = asyncio.run(scan_files("./target"))
```

---

## Summary

| Concept | What It Does | SecureVibes Example |
|---------|--------------|---------------------|
| Type Hints | Document expected types | `def scan(path: str) -> ScanResult` |
| Enums | Type-safe constants | `Severity.CRITICAL`, `ValidationStatus.VALIDATED` |
| Dataclasses | Auto-generate data containers | `SecurityIssue`, `ScanResult` |
| pathlib.Path | Cross-platform file paths | `repo / ".securevibes" / "results.json"` |
| os.getenv | Read environment variables | `os.getenv("ANTHROPIC_API_KEY")` |
| async/await | Non-blocking operations | `await client.query(prompt)` |
| async with | Async resource management | `async with ClaudeSDKClient() as client` |
| async for | Stream processing | `async for msg in client.receive_messages()` |

---

## Next Steps

Now that you understand Python foundations, proceed to:
- **[Phase 2: Claude SDK Core](PHASE2_CLAUDE_SDK_CORE.md)** - Learn the Claude Agent SDK

