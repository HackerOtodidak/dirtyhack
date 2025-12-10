# Phase 5: SecureVibes Deep Dive

This tutorial provides a comprehensive code walkthrough of SecureVibes, tracing execution from CLI command to final report.

---

## Table of Contents

1. [Project Structure Overview](#1-project-structure-overview)
2. [Entry Point: CLI](#2-entry-point-cli)
3. [Scanner Class - The Core](#3-scanner-class---the-core)
4. [Agent Definitions](#4-agent-definitions)
5. [Prompt Engineering](#5-prompt-engineering)
6. [The Scan Execution Flow](#6-the-scan-execution-flow)
7. [Data Models](#7-data-models)
8. [Reporters and Output](#8-reporters-and-output)
9. [Configuration System](#9-configuration-system)
10. [Testing Approach](#10-testing-approach)

---

## 1. Project Structure Overview

```
packages/core/securevibes/
├── __init__.py                 # Package exports (Scanner, __version__)
├── agents/
│   ├── __init__.py
│   └── definitions.py          # AgentDefinition for all 5 agents
├── cli/
│   ├── __init__.py
│   └── main.py                 # Click CLI commands (scan, report)
├── config.py                   # Configuration classes
├── models/
│   ├── __init__.py
│   ├── issue.py                # SecurityIssue, Severity, ValidationStatus
│   └── result.py               # ScanResult dataclass
├── prompts/
│   ├── __init__.py
│   ├── loader.py               # Prompt loading utilities
│   ├── agents/                 # Individual agent prompts
│   │   ├── assessment.txt
│   │   ├── threat_modeling.txt
│   │   ├── code_review.txt
│   │   ├── report_generator.txt
│   │   └── dast.txt
│   └── orchestration/
│       └── main.txt            # Main orchestration prompt
├── reporters/
│   ├── __init__.py
│   ├── json_reporter.py        # JSON output
│   └── markdown_reporter.py    # Markdown output
├── scanner/
│   ├── __init__.py
│   ├── scanner.py              # Main Scanner class
│   ├── hooks.py                # Hook implementations
│   └── subagent_manager.py     # Artifact validation & resume
└── skills/
    └── dast/
        └── authorization-testing/
            ├── SKILL.md
            └── reference/
```

### Key File Responsibilities

| File | Purpose |
|------|---------|
| `cli/main.py` | Entry point, argument parsing, output formatting |
| `scanner/scanner.py` | Core orchestration, SDK integration |
| `agents/definitions.py` | Agent configurations |
| `prompts/agents/*.txt` | Agent behavior instructions |
| `prompts/orchestration/main.txt` | How to coordinate agents |
| `models/issue.py` | Vulnerability data structure |
| `models/result.py` | Scan result data structure |
| `config.py` | Model selection, exclusions |
| `scanner/hooks.py` | Security, progress tracking |

---

## 2. Entry Point: CLI

**File: `packages/core/securevibes/cli/main.py`**

The CLI uses the `click` library for argument parsing and `rich` for beautiful output.

### Main CLI Group

```python
import click
from rich.console import Console

console = Console()

@click.group()
@click.version_option(version=__version__, prog_name="securevibes")
def cli():
    """
    🛡️ SecureVibes - AI-Native Platform to Secure Vibecoded Applications
    """
    pass
```

### The `scan` Command

```python
@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--model', '-m', default='sonnet', help='Claude model to use')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['markdown', 'json', 'text', 'table']), 
              default='markdown')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low']))
@click.option('--debug', is_flag=True, help='Show verbose output')
@click.option('--dast', is_flag=True, help='Enable DAST validation')
@click.option('--target-url', type=str, help='Target URL for DAST')
@click.option('--subagent', type=click.Choice([...]), help='Run specific sub-agent')
@click.option('--resume-from', type=click.Choice([...]), help='Resume from sub-agent')
def scan(path, model, output, format, severity, debug, dast, target_url, 
         subagent, resume_from, ...):
    """Scan a repository for security vulnerabilities."""
    
    # Validate options
    if subagent and resume_from:
        console.print("[bold red]❌ Error:[/bold red] --subagent and --resume-from are mutually exclusive")
        sys.exit(1)
    
    # Show banner
    if not quiet:
        console.print("[bold cyan]🛡️ SecureVibes Security Scanner[/bold cyan]")
    
    # Run the scan
    result = asyncio.run(_run_scan(path, model, debug, dast, target_url, ...))
    
    # Filter by severity
    if severity:
        min_severity = Severity(severity)
        result.issues = [i for i in result.issues if ...]
    
    # Output results
    if format == 'markdown':
        MarkdownReporter.save(result, output_path)
    elif format == 'json':
        output_path.write_text(json.dumps(result.to_dict(), indent=2))
    elif format == 'table':
        _display_table_results(result, quiet)
```

### The Async Runner

```python
async def _run_scan(path, model, save_results, quiet, debug, dast, target_url, ...):
    """Run the actual scan with progress indicator."""
    
    repo_path = Path(path).absolute()
    
    # DAST reachability check
    if dast and target_url:
        if not _check_target_reachability(target_url):
            console.print(f"[yellow]⚠️ Target not reachable[/yellow]")
    
    # Create scanner instance
    scanner = Scanner(model=model, debug=debug)
    
    # Configure DAST if enabled
    if dast:
        scanner.configure_dast(
            target_url=target_url,
            timeout=dast_timeout,
            accounts_path=dast_accounts
        )
    
    # Run appropriate scan mode
    if subagent:
        result = await scanner.scan_subagent(str(repo_path), subagent, ...)
    elif resume_from:
        result = await scanner.scan_resume(str(repo_path), resume_from, ...)
    else:
        result = await scanner.scan(str(repo_path))
    
    return result
```

---

## 3. Scanner Class - The Core

**File: `packages/core/securevibes/scanner/scanner.py`**

The `Scanner` class orchestrates the entire security analysis.

### Initialization

```python
class Scanner:
    """Security scanner using ClaudeSDKClient with real-time progress tracking."""
    
    def __init__(self, model: str = "sonnet", debug: bool = False):
        self.model = model
        self.debug = debug
        self.total_cost = 0.0
        self.console = Console()
        
        # DAST configuration
        self.dast_enabled = False
        self.dast_config = {}
```

### Main Scan Method

```python
async def scan(self, repo_path: str) -> ScanResult:
    """Run complete security scan."""
    
    repo = Path(repo_path).resolve()
    if not repo.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    
    # Configure DAST environment variables if enabled
    if self.dast_enabled:
        os.environ["DAST_ENABLED"] = "true"
        os.environ["DAST_TARGET_URL"] = self.dast_config["target_url"]
    
    return await self._execute_scan(repo)
```

### The Execute Scan Method (Heart of SecureVibes)

```python
async def _execute_scan(self, repo: Path, single_subagent=None, resume_from=None) -> ScanResult:
    """Internal method to execute scan."""
    
    # 1. Create output directory
    securevibes_dir = repo / ".securevibes"
    securevibes_dir.mkdir(exist_ok=True)
    
    # 2. Track timing
    scan_start_time = time.time()
    
    # 3. Detect languages for smart exclusions
    detected_languages = LanguageConfig.detect_languages(repo)
    
    # 4. Count files for reporting
    all_code_files = []
    for lang, extensions in LanguageConfig.SUPPORTED_LANGUAGES.items():
        for ext in extensions:
            files = list(repo.glob(f'**/*{ext}'))
            all_code_files.extend(files)
    files_scanned = len(all_code_files)
    
    # 5. Setup DAST skills if needed
    if needs_dast:
        self._setup_dast_skills(repo)
    
    # 6. Initialize progress tracker
    tracker = ProgressTracker(self.console, debug=self.debug)
    
    # 7. Create hooks
    dast_security_hook = create_dast_security_hook(tracker, self.console, self.debug)
    pre_tool_hook = create_pre_tool_hook(tracker, self.console, self.debug, detected_languages)
    post_tool_hook = create_post_tool_hook(tracker, self.console, self.debug)
    subagent_hook = create_subagent_hook(tracker)
    
    # 8. Create agent definitions
    agents = create_agent_definitions(cli_model=self.model, dast_target_url=dast_url)
    
    # 9. Configure SDK options
    options = ClaudeAgentOptions(
        agents=agents,
        cwd=str(repo),
        setting_sources=["project"],  # Enable skills
        allowed_tools=["Skill", "Read", "Write", "Edit", "Bash", "Grep", "Glob", "LS"],
        max_turns=config.get_max_turns(),
        permission_mode='bypassPermissions',
        model=self.model,
        hooks={
            "PreToolUse": [
                HookMatcher(hooks=[dast_security_hook]),
                HookMatcher(hooks=[pre_tool_hook])
            ],
            "PostToolUse": [HookMatcher(hooks=[post_tool_hook])],
            "SubagentStop": [HookMatcher(hooks=[subagent_hook])]
        }
    )
    
    # 10. Load orchestration prompt
    orchestration_prompt = load_prompt("main", category="orchestration")
    
    # 11. Execute scan
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(orchestration_prompt)
            
            # Stream and process messages
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
    
    # 12. Load and return results
    return self._load_scan_results(securevibes_dir, repo, files_scanned, scan_start_time)
```

---

## 4. Agent Definitions

**File: `packages/core/securevibes/agents/definitions.py`**

### Loading Prompts

```python
from securevibes.prompts.loader import load_all_agent_prompts

# Load all prompts at module import
AGENT_PROMPTS = load_all_agent_prompts()
# Returns: {"assessment": "...", "threat_modeling": "...", ...}
```

### Creating Agent Definitions

```python
def create_agent_definitions(cli_model=None, dast_target_url=None) -> Dict[str, AgentDefinition]:
    """
    Create agent definitions with model override support.
    
    Priority: env var > CLI model > default
    """
    
    # Handle DAST URL substitution
    dast_prompt = AGENT_PROMPTS["dast"]
    if dast_target_url:
        dast_prompt = dast_prompt.replace("{target_url}", dast_target_url)
    
    return {
        "assessment": AgentDefinition(
            description="Analyzes codebase architecture and creates security documentation",
            prompt=AGENT_PROMPTS["assessment"],
            tools=["Read", "Grep", "Glob", "LS", "Write"],
            model=config.get_agent_model("assessment", cli_override=cli_model)
        ),
        
        "threat-modeling": AgentDefinition(
            description="Performs STRIDE threat modeling",
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
            prompt=dast_prompt,
            tools=["Read", "Write", "Skill", "Bash"],
            model=config.get_agent_model("dast", cli_override=cli_model)
        )
    }
```

---

## 5. Prompt Engineering

### Assessment Agent Prompt

**File: `packages/core/securevibes/prompts/agents/assessment.txt`**

```text
You are a software architect specializing in security documentation.

<critical_rules>
NEVER scan these directories:
- .claude/ - SecureVibes infrastructure
- env/, venv/, .venv/ - Python virtual environments  
- node_modules/ - Node.js dependencies
...

When using Grep, Glob, LS, or Read tools:
1. ALWAYS check file paths BEFORE reading
2. SKIP any file in the directories above
3. Focus ONLY on application source code
</critical_rules>

<instructions>
Workflow:
1. INVESTIGATION PHASE:
   - Use Read, Grep, Glob, and LS tools to explore
   - Analyze architecture, data flows, authentication
   
2. OUTPUT PHASE:
   - Write clean markdown to .securevibes/SECURITY.md
   - Do NOT include investigation notes in the file
</instructions>

Document structure:
# Security Architecture
## Overview
## Architecture
## Technology Stack
## Entry Points
## Authentication & Authorization
## Data Flow
## Sensitive Data
## External Dependencies
## Security Controls
## Notes
```

### Code Review Agent Prompt

**File: `packages/core/securevibes/prompts/agents/code_review.txt`**

Key sections:

```text
You are a security code reviewer who validates threats with concrete evidence.

<critical_output_format>
CRITICAL: The VULNERABILITIES.json file MUST be a flat JSON array.

CORRECT FORMAT:
[
  {"threat_id": "THREAT-001", "title": "...", ...}
]

INCORRECT FORMATS (DO NOT USE):
❌ {"vulnerabilities": [...]}
❌ Any wrapper object
</critical_output_format>

<security_analysis_methodology>
1. UNDERSTAND CONTEXT
   - What is this code's purpose?
   - What data does it process?

2. IDENTIFY TRUST BOUNDARIES
   - Where does untrusted data enter?
   - How is data validated?

3. TRACE DATA FLOWS
   - Follow untrusted data from entry → processing → output
   - Look for gaps in security controls

4. THINK LIKE AN ATTACKER
   - What's the most valuable target?
   - How would I bypass controls?

5. EVALUATE SYSTEMATICALLY
   - OWASP Top 10
   - STRIDE
   - CWE Top 25

6. LOOK BEYOND COMMON PATTERNS
   - Business logic flaws
   - Framework-specific vulnerabilities
   - Configuration issues
</security_analysis_methodology>

<critical_questions>
- "Can an attacker control this input?"
- "Is this authorization check sufficient?"
- "What happens in edge cases?"
...
</critical_questions>

Required JSON structure:
{
  "threat_id": "THREAT-XXX",
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low",
  "file_path": "string",
  "line_number": number,
  "code_snippet": "string",
  "cwe_id": "CWE-XXX",
  "recommendation": "string",
  "evidence": "string"
}
```

---

## 6. The Scan Execution Flow

### Complete Sequence Diagram

```
User                CLI                Scanner             SDK              Claude
  │                  │                    │                  │                  │
  │──scan .─────────►│                    │                  │                  │
  │                  │                    │                  │                  │
  │                  │──Scanner(model)───►│                  │                  │
  │                  │                    │                  │                  │
  │                  │──scan(path)───────►│                  │                  │
  │                  │                    │                  │                  │
  │                  │                    │──options─────────►│                  │
  │                  │                    │──query(orch)─────►│                  │
  │                  │                    │                  │──Orchestration──►│
  │                  │                    │                  │                  │
  │                  │                    │                  │◄─"Phase 1..."────│
  │                  │                    │                  │                  │
  │                  │                    │                  │◄─Task(assess)────│
  │                  │                    │                  │  │               │
  │                  │                    │                  │  │   Assessment  │
  │                  │                    │                  │  │   Agent Runs  │
  │                  │                    │                  │  │               │
  │                  │                    │                  │◄─SubagentStop────│
  │                  │                    │                  │                  │
  │                  │                    │                  │◄─"Phase 2..."────│
  │                  │                    │                  │◄─Task(threat)────│
  │                  │                    │                  │  │               │
  │                  │                    │                  │  │  Threat Model │
  │                  │                    │                  │  │   Agent Runs  │
  │                  │                    │                  │  │               │
  │                  │                    │                  │◄─SubagentStop────│
  │                  │                    │                  │                  │
  │                  │                    │                  │◄─"Phase 3..."────│
  │                  │                    │                  │◄─Task(review)────│
  │                  │                    │                  │  │               │
  │                  │                    │                  │  │  Code Review  │
  │                  │                    │                  │  │   Agent Runs  │
  │                  │                    │                  │  │               │
  │                  │                    │                  │◄─SubagentStop────│
  │                  │                    │                  │                  │
  │                  │                    │                  │◄─"Phase 4..."────│
  │                  │                    │                  │◄─Task(report)────│
  │                  │                    │                  │◄─SubagentStop────│
  │                  │                    │                  │                  │
  │                  │                    │                  │◄─ResultMessage───│
  │                  │                    │                  │                  │
  │                  │                    │◄─────────────────│                  │
  │                  │                    │                  │                  │
  │                  │                    │──load_results────│                  │
  │                  │◄──ScanResult───────│                  │                  │
  │                  │                    │                  │                  │
  │◄──Display────────│                    │                  │                  │
```

### Phase Details

**Phase 1: Assessment**
```
Input: Repository
Actions: Glob, LS, Read, Grep
Output: .securevibes/SECURITY.md
```

**Phase 2: Threat Modeling**
```
Input: SECURITY.md
Actions: Read, internal STRIDE analysis
Output: .securevibes/THREAT_MODEL.json
```

**Phase 3: Code Review**
```
Input: THREAT_MODEL.json
Actions: Read threats, Grep for patterns, Read files, validate
Output: .securevibes/VULNERABILITIES.json
```

**Phase 4: Report Generation**
```
Input: VULNERABILITIES.json
Actions: Read, format
Output: .securevibes/scan_results.json
```

**Phase 5: DAST (Optional)**
```
Input: VULNERABILITIES.json, target URL
Actions: Read vulnerabilities, execute HTTP tests via Bash
Output: .securevibes/DAST_VALIDATION.json
```

---

## 7. Data Models

### SecurityIssue

**File: `packages/core/securevibes/models/issue.py`**

```python
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"        # Exploit confirmed
    FALSE_POSITIVE = "FALSE_POSITIVE"  # Properly protected
    UNVALIDATED = "UNVALIDATED"    # Couldn't test
    PARTIAL = "PARTIAL"            # Mixed results

@dataclass
class SecurityIssue:
    """Represents a security vulnerability."""
    
    # Required fields
    id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    
    # Optional fields
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None
    
    # DAST validation fields
    validation_status: Optional[ValidationStatus] = None
    dast_evidence: Optional[dict] = None
    exploitability_score: Optional[float] = None
    validated_at: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        base = {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }
        
        if self.validation_status:
            base.update({
                "validation_status": self.validation_status.value,
                "dast_evidence": self.dast_evidence,
                "exploitability_score": self.exploitability_score,
            })
        
        return base
    
    @property
    def is_validated(self) -> bool:
        return self.validation_status == ValidationStatus.VALIDATED
```

### ScanResult

**File: `packages/core/securevibes/models/result.py`**

```python
@dataclass
class ScanResult:
    """Results from a security scan."""
    
    repository_path: str
    issues: List[SecurityIssue] = field(default_factory=list)
    files_scanned: int = 0
    scan_time_seconds: float = 0.0
    total_cost_usd: float = 0.0
    
    # DAST metrics
    dast_enabled: bool = False
    dast_validation_rate: float = 0.0
    dast_false_positive_rate: float = 0.0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "critical")
    
    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "high")
    
    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "medium")
    
    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity.value == "low")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "repository_path": self.repository_path,
            "issues": [issue.to_dict() for issue in self.issues],
            "files_scanned": self.files_scanned,
            "scan_time_seconds": self.scan_time_seconds,
            "total_cost_usd": self.total_cost_usd,
            "summary": {
                "total": len(self.issues),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            }
        }
        
        if self.dast_enabled:
            result["dast_metrics"] = {...}
        
        return result
```

---

## 8. Reporters and Output

### Markdown Reporter

**File: `packages/core/securevibes/reporters/markdown_reporter.py`**

```python
class MarkdownReporter:
    """Generates markdown security reports."""
    
    @staticmethod
    def generate(result: ScanResult) -> str:
        """Generate markdown report content."""
        lines = [
            "# Security Scan Report",
            "",
            f"**Repository:** {result.repository_path}",
            f"**Scan Time:** {result.scan_time_seconds}s",
            f"**Files Scanned:** {result.files_scanned}",
            f"**Total Cost:** ${result.total_cost_usd:.4f}",
            "",
            "## Summary",
            "",
            f"- 🔴 Critical: {result.critical_count}",
            f"- 🟠 High: {result.high_count}",
            f"- 🟡 Medium: {result.medium_count}",
            f"- 🟢 Low: {result.low_count}",
            "",
            "## Findings",
            ""
        ]
        
        for issue in result.issues:
            lines.extend([
                f"### [{issue.severity.value.upper()}] {issue.title}",
                "",
                f"**File:** `{issue.file_path}:{issue.line_number}`",
                f"**CWE:** {issue.cwe_id}",
                "",
                issue.description,
                "",
                "```",
                issue.code_snippet,
                "```",
                "",
                f"**Recommendation:** {issue.recommendation}",
                "",
                "---",
                ""
            ])
        
        return "\n".join(lines)
    
    @staticmethod
    def save(result: ScanResult, path: Path):
        """Save report to file."""
        content = MarkdownReporter.generate(result)
        path.write_text(content, encoding="utf-8")
```

### JSON Reporter

```python
class JSONReporter:
    @staticmethod
    def save(result: ScanResult, path: Path):
        """Save results as JSON."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2)
    
    @staticmethod
    def load(path: str) -> dict:
        """Load results from JSON."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
```

---

## 9. Configuration System

**File: `packages/core/securevibes/config.py`**

### Language Detection

```python
class LanguageConfig:
    SUPPORTED_LANGUAGES = {
        'python': ['.py'],
        'javascript': ['.js', '.jsx'],
        'typescript': ['.ts', '.tsx'],
        'go': ['.go'],
        'ruby': ['.rb'],
        'java': ['.java'],
        'php': ['.php'],
        'csharp': ['.cs'],
        'rust': ['.rs'],
        'kotlin': ['.kt'],
        'swift': ['.swift']
    }
    
    @classmethod
    def detect_languages(cls, repo: Path, sample_size: int = 100) -> Set[str]:
        """Detect languages in repository."""
        languages = set()
        
        sample_files = list(repo.glob('**/*'))[:sample_size]
        
        for file in sample_files:
            if not file.is_file():
                continue
            ext = file.suffix.lower()
            for lang, extensions in cls.SUPPORTED_LANGUAGES.items():
                if ext in extensions:
                    languages.add(lang)
                    break
        
        return languages
```

### Smart Exclusions

```python
class ScanConfig:
    EXCLUDED_DIRS_COMMON = {'.claude', '.git', 'dist', 'build'}
    EXCLUDED_DIRS_PYTHON = {'env', 'venv', '.venv', '__pycache__'}
    EXCLUDED_DIRS_JS = {'node_modules', '.next', '.nuxt'}
    EXCLUDED_DIRS_GO = {'vendor', 'bin'}
    
    @classmethod
    def get_excluded_dirs(cls, languages: Set[str] = None) -> Set[str]:
        """Get exclusions based on detected languages."""
        dirs = cls.EXCLUDED_DIRS_COMMON.copy()
        
        if languages is None:
            # Include all to be safe
            dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            dirs.update(cls.EXCLUDED_DIRS_JS)
            dirs.update(cls.EXCLUDED_DIRS_GO)
        else:
            if 'python' in languages:
                dirs.update(cls.EXCLUDED_DIRS_PYTHON)
            if 'javascript' in languages or 'typescript' in languages:
                dirs.update(cls.EXCLUDED_DIRS_JS)
            if 'go' in languages:
                dirs.update(cls.EXCLUDED_DIRS_GO)
        
        return dirs
```

### Model Configuration

```python
class AgentConfig:
    DEFAULTS = {
        "assessment": "sonnet",
        "threat_modeling": "sonnet",
        "code_review": "sonnet",
        "report_generator": "sonnet"
    }
    
    DEFAULT_MAX_TURNS = 50
    
    @classmethod
    def get_agent_model(cls, agent_name: str, cli_override: str = None) -> str:
        """Get model with priority: env > CLI > default."""
        env_var = f"SECUREVIBES_{agent_name.upper()}_MODEL"
        env_value = os.getenv(env_var)
        
        if env_value:
            return env_value
        if cli_override:
            return cli_override
        return cls.DEFAULTS.get(agent_name, "sonnet")
    
    @classmethod
    def get_max_turns(cls) -> int:
        try:
            return int(os.getenv("SECUREVIBES_MAX_TURNS", cls.DEFAULT_MAX_TURNS))
        except ValueError:
            return cls.DEFAULT_MAX_TURNS

# Global instance
config = AgentConfig()
```

---

## 10. Testing Approach

### Test Structure

```
packages/core/tests/
├── __init__.py
├── fixtures/
│   └── vulnerable_code.py      # Test data
├── test_agents.py              # Agent definition tests
├── test_cli.py                 # CLI tests
├── test_config.py              # Configuration tests
├── test_hooks.py               # Hook tests
├── test_models.py              # Data model tests
├── test_reporters.py           # Reporter tests
├── test_scanner.py             # Scanner tests
└── test_scanner_integration.py # Integration tests
```

### Example Test: Models

```python
import pytest
from securevibes.models.issue import SecurityIssue, Severity, ValidationStatus

def test_security_issue_creation():
    """Test creating a security issue."""
    issue = SecurityIssue(
        id="VULN-001",
        severity=Severity.HIGH,
        title="SQL Injection",
        description="User input used in SQL query",
        file_path="app/views.py",
        line_number=42,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        cwe_id="CWE-89",
        recommendation="Use parameterized queries"
    )
    
    assert issue.id == "VULN-001"
    assert issue.severity == Severity.HIGH
    assert issue.cwe_id == "CWE-89"

def test_issue_to_dict():
    """Test converting issue to dictionary."""
    issue = SecurityIssue(...)
    data = issue.to_dict()
    
    assert data["severity"] == "high"  # String value
    assert "file_path" in data
```

### Example Test: Configuration

```python
import os
import pytest
from securevibes.config import AgentConfig

def test_model_priority_env_var(monkeypatch):
    """Environment variable has highest priority."""
    monkeypatch.setenv("SECUREVIBES_ASSESSMENT_MODEL", "opus")
    
    model = AgentConfig.get_agent_model("assessment", cli_override="haiku")
    
    assert model == "opus"  # Env var wins

def test_model_priority_cli():
    """CLI override beats default."""
    model = AgentConfig.get_agent_model("assessment", cli_override="haiku")
    
    assert model == "haiku"

def test_model_priority_default():
    """Default used when no override."""
    model = AgentConfig.get_agent_model("assessment")
    
    assert model == "sonnet"  # Default
```

---

## Summary

| Component | File | Purpose |
|-----------|------|---------|
| CLI | `cli/main.py` | Entry point, arg parsing |
| Scanner | `scanner/scanner.py` | SDK orchestration |
| Agents | `agents/definitions.py` | Agent configurations |
| Prompts | `prompts/agents/*.txt` | Agent instructions |
| Orchestration | `prompts/orchestration/main.txt` | Phase coordination |
| Models | `models/*.py` | Data structures |
| Config | `config.py` | Settings, exclusions |
| Hooks | `scanner/hooks.py` | Security, monitoring |
| Reporters | `reporters/*.py` | Output formatting |

---

## Next Steps

Now that you understand SecureVibes in depth, proceed to:
- **[Phase 6: Build PenTest Multi-Agent System](PHASE6_PENTEST_SYSTEM.md)** - Apply these patterns

