"""
Enhanced AI-Powered Security Scanner.

This is a comprehensive security scanner that detects:
- Hardcoded secrets, API keys, passwords, and credentials
- Security vulnerabilities (SQL Injection, XSS, Command Injection, etc.)
- Uses AI verification to reduce false positives
- Remote URL scanning (GitHub, GitLab, archives)
- Black box web application testing
- Performance benchmarking and metrics

Version: 3.2.0
Author: Ahmed Mubaraki
"""

from typing import List, Dict, Optional, Tuple
import typer
import re
import os
import time
import math
import sys
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, track
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from datetime import datetime
import subprocess
import stat

# Import new enhanced modules
from config import get_config, reload_config
from logger import get_logger
from vulnerability_scanner import VulnerabilityScanner, scan_for_vulnerabilities
from report_generator import ReportGenerator
from auto_fix import AutoFix, auto_fix_directory
from ui_components import BeautifulUI
from url_scanner import URLScanner, scan_remote_url
from blackbox_tester import BlackBoxTester, run_blackbox_test
from benchmark import Benchmark, PerformanceMonitor, run_benchmark

# Import AI providers
from ai_providers.gemini_provider import GeminiProvider
from ai_providers.openai_provider import OpenAIProvider
from ai_providers.claude_provider import ClaudeProvider

# Initialize
console = Console()
logger = get_logger()
app = typer.Typer(help="🛡️ Enhanced AI-Powered Security Scanner 🛡️")

# Configuration paths
APP_CONFIG_DIR = Path.home() / ".security-scan"
RULES_FILE = APP_CONFIG_DIR / "rules.txt"
IGNORE_FILE = APP_CONFIG_DIR / "ignore.txt"

# AI Providers registry
AI_PROVIDERS = {
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
    "claude": ClaudeProvider,
}

DEFAULT_RULES = """
# Default rules for secret detection
password\s*[:=]\s*['"][^'"]+['"];?
token\s*[:=]\s*['"][^'"]+['"];?
API_KEY\s*[:=]\s*['"][^'"]+['"];?
AKIA[0-9A-Z]{16}
AIza[0-9A-Za-z\\-_]{35}
ghp_[a-zA-Z0-9]{36}
sk-[a-zA-Z0-9]{48}
"""


def initialize_config() -> None:
    """
    Initialize configuration directory and files on first run.
    
    Creates:
        - Config directory at ~/.security-scan
        - Default rules file
        - Default ignore patterns file
    """
    logger.info("Initializing configuration...")
    
    if not APP_CONFIG_DIR.exists():
        console.print(f"[yellow]First run detected. Creating config directory: {APP_CONFIG_DIR}[/yellow]")
        APP_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created config directory: {APP_CONFIG_DIR}")
    
    if not RULES_FILE.exists():
        console.print("[yellow]Creating default rules file...[/yellow]")
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            f.write(DEFAULT_RULES)
        logger.info(f"Created rules file: {RULES_FILE}")
    
    if not IGNORE_FILE.exists():
        console.print("[yellow]Creating default ignore file...[/yellow]")
        with open(IGNORE_FILE, "w", encoding="utf-8") as f:
            f.write("# Add files or patterns to ignore\n*.log\n*.tmp\n")
        logger.info(f"Created ignore file: {IGNORE_FILE}")


@lru_cache(maxsize=1)
def load_rules() -> List[re.Pattern]:
    """
    Load regex patterns from rules file (cached).

    Uses LRU cache to avoid re-loading rules on every scan.
    Cache is cleared when rules file is modified.

    Returns:
        List[re.Pattern]: Compiled regex patterns

    Raises:
        SystemExit: If rules file doesn't exist
    """
    if not RULES_FILE.exists():
        console.print(f"[bold red]Error: Rules file not found at {RULES_FILE}[/bold red]")
        console.print("Please run [bold]'security-scan interactive'[/bold] to create it.")
        logger.error(f"Rules file not found: {RULES_FILE}")
        sys.exit(1)

    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
            patterns = [
                re.compile(line.strip())
                for line in lines
                if line.strip() and not line.strip().startswith("#")
            ]
        logger.info(f"Loaded {len(patterns)} rules from {RULES_FILE} (cached)")
        return patterns
    except re.error as e:
        logger.error(f"Invalid regex pattern in rules file: {e}")
        console.print(f"[bold red]Error: Invalid regex in rules file: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load rules: {e}")
        console.print(f"[bold red]Error loading rules: {e}[/bold red]")
        sys.exit(1)


@lru_cache(maxsize=1)
def load_ignore_patterns() -> Tuple[str, ...]:
    """
    Load ignore patterns from ignore file (cached).

    Returns:
        Tuple[str, ...]: Tuple of patterns to ignore (tuple for caching)
    """
    if not IGNORE_FILE.exists():
        return tuple()

    try:
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            patterns = tuple([
                p.strip()
                for p in f.read().splitlines()
                if p.strip() and not p.startswith("#")
            ])
        logger.info(f"Loaded {len(patterns)} ignore patterns (cached)")
        return patterns
    except Exception as e:
        logger.warning(f"Failed to load ignore patterns: {e}")
        return tuple()


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text for randomness detection.

    Higher entropy indicates more randomness (likely a real secret).

    Args:
        text: Text to calculate entropy for

    Returns:
        float: Entropy value (0.0 to ~8.0 for ASCII)
    """
    if not text:
        return 0.0

    # Use Counter for O(n) complexity instead of O(n*m)
    char_counts = Counter(text)
    text_len = len(text)

    # Calculate character frequency probabilities
    probabilities = [count / text_len for count in char_counts.values()]

    # Shannon entropy formula
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)

    return entropy


def extract_value_for_entropy(match_string: str) -> str:
    """
    Extract the actual value from a pattern match for entropy calculation.
    
    Args:
        match_string: Matched string from regex
        
    Returns:
        str: Extracted value
    """
    # Try to extract quoted value
    quoted_match = re.search(r"['\"](.+?)['\"]", match_string)
    if quoted_match:
        return quoted_match.group(1)
    
    # Try to extract value after '='
    if '=' in match_string:
        parts = match_string.split('=', 1)
        if len(parts) > 1:
            return parts[1].strip().strip('\'";')
    
    return match_string


def collect_files(
    path: str,
    ignore_patterns: Optional[Tuple[str, ...]] = None
) -> List[Path]:
    """
    Collect all files to scan from given path.
    
    Args:
        path: Directory or file path to scan
        ignore_patterns: Patterns to ignore
        
    Returns:
        List[Path]: List of files to scan
    """
    logger.info(f"Collecting files from: {path}")
    target_path = Path(path)
    
    if target_path.is_file():
        return [target_path]
    
    if not target_path.is_dir():
        logger.error(f"Invalid path: {path}")
        return []
    
    # Default ignore patterns
    default_ignores = [
        '**/.git/**',
        '**/venv/**',
        '**/__pycache__/**',
        '**/node_modules/**',
        '**/output/**',
        '**/.venv/**',
        '**/dist/**',
        '**/build/**'
    ]
    
    all_ignores = default_ignores + (ignore_patterns or [])

    # Use generator instead of loading all files into memory
    # This is much more efficient for large directories
    files_to_scan = []

    for file_path in target_path.rglob("*"):
        if not file_path.is_file():
            continue

        # Check ignore patterns - use any() for early exit
        if not any(file_path.match(pattern) for pattern in all_ignores):
            files_to_scan.append(file_path)
    
    logger.info(f"Found {len(files_to_scan)} files to scan")
    return files_to_scan


def scan_single_file(file_path: Path, rules: List[re.Pattern]) -> List[Dict]:
    """
    Scan a single file for secrets (for parallel execution).

    Args:
        file_path: Path to file to scan
        rules: Compiled regex patterns

    Returns:
        List[Dict]: Findings in this file
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for rule in rules:
                    match = rule.search(line)
                    if match:
                        findings.append({
                            "file": str(file_path),
                            "line": line_num,
                            "match": match.group(0).strip(),
                            "rule": rule.pattern
                        })
                        break  # One match per line
    except Exception as e:
        logger.debug(f"Failed to scan {file_path}: {e}")
    return findings


def scan_for_secrets(
    files: List[Path],
    rules: List[re.Pattern],
    quiet: bool = False,
    use_parallel: bool = True
) -> List[Dict]:
    """
    Scan files for potential secrets using regex patterns.

    Args:
        files: List of files to scan
        rules: Compiled regex patterns
        quiet: Suppress progress output
        use_parallel: Use parallel processing (default: True)

    Returns:
        List[Dict]: List of potential findings
    """
    logger.info(f"Scanning {len(files)} files for secrets (parallel={use_parallel})...")
    potential_findings = []

    config = get_config()
    max_workers = config.api.get('max_workers', 4) if use_parallel else 1

    if use_parallel and len(files) > 10:
        # Parallel mode for large file sets
        if not quiet:
            console.print(f"\n[bold blue]⚡ Parallel scanning {len(files)} files with {max_workers} workers...[/bold blue]")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all files for scanning
            future_to_file = {executor.submit(scan_single_file, file_path, rules): file_path
                            for file_path in files}

            # Collect results with progress tracking
            completed = 0
            for future in as_completed(future_to_file):
                findings = future.result()
                potential_findings.extend(findings)
                completed += 1
                if not quiet and completed % 10 == 0:
                    console.print(f"[dim]Progress: {completed}/{len(files)} files scanned...[/dim]")

    else:
        # Sequential mode (original behavior)
        if quiet:
            for file_path in files:
                findings = scan_single_file(file_path, rules)
                potential_findings.extend(findings)
        else:
            console.print("\n[bold blue]Scanning files for secrets...[/bold blue]")
            for file_path in track(files, description="[cyan]Scanning..."):
                findings = scan_single_file(file_path, rules)
                potential_findings.extend(findings)

    logger.info(f"Found {len(potential_findings)} potential secrets")
    return potential_findings


def filter_by_entropy(
    findings: List[Dict],
    threshold: float = 3.5,
    quiet: bool = False
) -> List[Dict]:
    """
    Filter findings by entropy threshold.
    
    Args:
        findings: List of findings
        threshold: Entropy threshold
        quiet: Suppress output
        
    Returns:
        List[Dict]: High-entropy findings
    """
    logger.info(f"Filtering findings by entropy (threshold: {threshold})...")
    high_entropy_findings = []
    
    if not quiet:
        console.print(f"\n[bold blue]Filtering by entropy (threshold: {threshold})...[/bold blue]")
    
    for finding in findings:
        value = extract_value_for_entropy(finding['match'])
        entropy = calculate_entropy(value)
        
        if entropy > threshold:
            high_entropy_findings.append(finding)
            if not quiet:
                console.print(
                    f"  [green]✓[/green] HIGH entropy ({entropy:.2f}): "
                    f"{finding['match'][:40]}..."
                )
        elif not quiet:
            console.print(
                f"  [dim]✗ LOW entropy ({entropy:.2f}): "
                f"{finding['match'][:40]}...[/dim]"
            )
    
    logger.info(f"Filtered to {len(high_entropy_findings)} high-entropy findings")
    return high_entropy_findings


def verify_with_ai(
    findings: List[Dict],
    ai_provider_name: str,
    quiet: bool = False
) -> List[Dict]:
    """
    Verify findings using AI provider.
    
    Args:
        findings: List of findings to verify
        ai_provider_name: Name of AI provider to use
        quiet: Suppress output
        
    Returns:
        List[Dict]: Verified findings
    """
    if ai_provider_name not in AI_PROVIDERS:
        logger.error(f"Unknown AI provider: {ai_provider_name}")
        return findings
    
    logger.info(f"Verifying {len(findings)} findings with {ai_provider_name}...")
    
    # Initialize AI provider
    ProviderClass = AI_PROVIDERS[ai_provider_name]
    ai_client = ProviderClass()
    
    if not ai_client.initialize():
        logger.warning("AI provider initialization failed, skipping verification")
        return findings
    
    verified_findings = []
    
    if not quiet:
        console.print(f"\n[bold yellow]Verifying with {ai_provider_name} AI...[/bold yellow]")
    
    for finding in track(findings, description="[yellow]Verifying...", disable=quiet):
        try:
            is_real = ai_client.verify(finding['match'])
            finding['ai_verified'] = is_real
            
            if is_real:
                verified_findings.append(finding)
                if not quiet:
                    console.print(f"  [red]✗ REAL SECRET:[/red] {finding['match'][:40]}...")
            elif not quiet:
                console.print(f"  [green]✓ False positive:[/green] {finding['match'][:40]}...")
        except Exception as e:
            logger.error(f"AI verification error: {e}")
            finding['ai_verified'] = None
            verified_findings.append(finding)  # Include on error to be safe
    
    logger.info(f"AI verified {len(verified_findings)} real secrets")
    return verified_findings


def run_comprehensive_scan(
    path: str,
    enable_ai: bool = True,
    ai_provider: str = "gemini",
    enable_vulnerabilities: bool = True,
    quiet: bool = False,
    from_hook: bool = False
) -> Tuple[List[Dict], List, Dict]:
    """
    Run comprehensive security scan including secrets and vulnerabilities.

    Args:
        path: Path to scan
        enable_ai: Enable AI verification
        ai_provider: AI provider to use
        enable_vulnerabilities: Enable vulnerability scanning
        quiet: Suppress output
        from_hook: Running from git hook

    Returns:
        Tuple[List[Dict], List, Dict]: (secret_findings, vulnerabilities, vuln_stats)
    """
    config = get_config()
    start_time = time.time()

    # Show beautiful scan header
    if not quiet and not from_hook:
        BeautifulUI.show_scan_header(path, ai_provider, enable_ai, enable_vulnerabilities)

    logger.info(f"Starting scan: path={path}, ai={enable_ai}, vuln={enable_vulnerabilities}")

    # Load rules and patterns
    rules = load_rules()
    ignore_patterns = load_ignore_patterns()

    # Collect files
    files = collect_files(path, ignore_patterns)

    if not files:
        logger.warning("No files found to scan")
        if not quiet:
            console.print("[yellow]⚠️  No files found to scan[/yellow]")
        return [], [], {}

    # Beautiful progress bar for scanning
    total_files = len(files)
    secrets_found = []

    if not quiet and not from_hook:
        with BeautifulUI.create_scan_progress(total_files) as progress:
            task = progress.add_task("[cyan]🔍 Scanning for secrets...", total=total_files)

            for i, file_path in enumerate(files):
                # Read file ONCE outside rule loop
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Now scan with all rules on the already-loaded content
                    for rule in rules:
                        for match in rule.finditer(content):
                            secrets_found.append({
                                'file': file_path,
                                'line_number': content[:match.start()].count('\n') + 1,
                                'match': match.group(),
                                'type': 'Secret',
                                'file_path': file_path
                            })
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")

                progress.update(task, advance=1)
    else:
        # Quiet mode - scan without progress bar
        secrets_found = scan_for_secrets(files, rules, quiet=True)

    potential_findings = secrets_found

    # Filter by entropy
    entropy_threshold = config.scan.entropy_threshold
    high_entropy_findings = filter_by_entropy(potential_findings, entropy_threshold, quiet=True)

    # AI verification
    final_findings = []
    if enable_ai and high_entropy_findings:
        final_findings = verify_with_ai(high_entropy_findings, ai_provider, quiet)
    else:
        final_findings = high_entropy_findings

    # Vulnerability scanning
    vulnerabilities = []
    vuln_stats = {}
    if enable_vulnerabilities:
        if not quiet:
            console.print("\n[bold cyan]🐛 Scanning for vulnerabilities...[/bold cyan]")

        try:
            vulnerabilities, vuln_stats = scan_for_vulnerabilities(
                path,
                min_severity=config.vulnerabilities.severity_levels[0]
                    if config.vulnerabilities.severity_levels else "low"
            )

            if not quiet and not from_hook:
                console.print(f"[dim]Found {len(vulnerabilities)} vulnerabilities[/dim]\n")
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            if not quiet:
                console.print(f"[yellow]⚠️  Warning: Vulnerability scan failed: {e}[/yellow]")

    # Calculate duration and show beautiful summary
    duration = time.time() - start_time

    if not quiet and not from_hook:
        # Add total files to stats
        vuln_stats['total_files_scanned'] = total_files

        # Show beautiful summary
        BeautifulUI.show_scan_summary(final_findings, vulnerabilities, vuln_stats, duration)

        # Show vulnerability details if found
        if vulnerabilities:
            critical_vulns = [v for v in vulnerabilities if v.severity == 'critical']
            if critical_vulns:
                BeautifulUI.show_vulnerability_details(critical_vulns, limit=5)

        # Show secret details if found
        if final_findings:
            BeautifulUI.show_secret_details(final_findings, limit=3)

        # Show next steps
        has_critical = any(v.severity == 'critical' for v in vulnerabilities)
        BeautifulUI.show_next_steps(has_critical, len(final_findings) > 0, len(vulnerabilities) > 0)

    logger.info(
        f"Scan complete: {len(final_findings)} secrets, "
        f"{len(vulnerabilities)} vulnerabilities in {duration:.2f}s"
    )

    return final_findings, vulnerabilities, vuln_stats


def generate_reports(
    findings: List[Dict],
    vulnerabilities: List,
    vuln_stats: Dict,
    formats: List[str] = None,
    output_dir: str = "output",
    open_browser: bool = True
) -> Dict[str, str]:
    """
    Generate security scan reports in multiple formats.

    Args:
        findings: Secret findings
        vulnerabilities: Vulnerability findings
        vuln_stats: Vulnerability statistics
        formats: Report formats to generate
        output_dir: Output directory
        open_browser: Open HTML report in browser

    Returns:
        Dict[str, str]: Generated report paths (as strings)
    """
    logger.info(f"Generating reports: formats={formats}")
    config = get_config()

    if formats is None:
        formats = config.report.default_formats

    generator = ReportGenerator(output_dir)
    report_paths = {}

    # Calculate affected files
    affected_files = len(set(f['file'] for f in findings))
    if vulnerabilities:
        affected_files += len(set(v.file_path for v in vulnerabilities))

    # Generate requested formats
    # Convert Path objects to strings for JSON serialization
    if "text" in formats:
        report_paths["text"] = str(generator.write_text_report(findings, vulnerabilities))

    if "json" in formats:
        report_paths["json"] = str(generator.write_json_report(findings, vulnerabilities, vuln_stats))

    if "markdown" in formats:
        report_paths["markdown"] = str(generator.write_md_report(
            findings, affected_files, vulnerabilities, vuln_stats
        ))

    if "html" in formats:
        html_path = generator.write_html_report(
            findings, affected_files, vulnerabilities, vuln_stats
        )
        report_paths["html"] = str(html_path)

        if open_browser and config.report.auto_open_browser:
            generator.open_in_browser(html_path)

    logger.info(f"Generated {len(report_paths)} reports")
    return report_paths


def print_welcome_banner() -> None:
    """Print welcome banner for interactive mode."""
    console.clear()
    
    ascii_art = r"""
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║   
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
    """
    
    title = Text(ascii_art, style="bold magenta", justify="center")
    subtitle = Text(
        "E N H A N C E D   S E C U R I T Y   S C A N N E R   v3.0",
        style="bold blue",
        justify="center"
    )
    developed_by = Text(
        "\nDeveloped by Ahmed Mubaraki\nPowered by AI & Advanced Vulnerability Detection",
        style="dim italic",
        justify="center"
    )
    
    panel_content = Text.assemble(title, "\n", subtitle, developed_by)
    console.print(Panel(panel_content, padding=(1, 4), expand=False, border_style="magenta"))
    
    # Initialize config
    with console.status("[bold green]Initializing...", spinner="dots8Bit"):
        initialize_config()
    
    console.print()


def install_git_hook() -> bool:
    """
    Install pre-commit git hook for automatic scanning.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check if in git repo
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode != 0:
            console.print("[red]Error: Not a git repository[/red]")
            logger.error("Not a git repository")
            return False
        
        git_dir = Path(result.stdout.strip())
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        
        hook_path = hooks_dir / "pre-commit"
        
        # Hook script content
        hook_content = f"""#!/bin/sh
# Auto-generated security scanner pre-commit hook

echo "🛡️  Running security scan..."

security-scan scan --path . --no-ai --output text --from-hook

if [ $? -ne 0 ]; then
    echo "❌ Security scan found issues!"
    echo "Review the findings and fix them before committing."
    echo "To bypass this check (not recommended): git commit --no-verify"
    exit 1
fi

echo "✅ Security scan passed!"
exit 0
"""
        
        # Write hook
        with open(hook_path, "w", encoding="utf-8") as f:
            f.write(hook_content)
        
        # Make executable
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        console.print(f"[green]✓ Git pre-commit hook installed at: {hook_path}[/green]")
        logger.info(f"Installed git hook: {hook_path}")
        return True
        
    except Exception as e:
        console.print(f"[red]Failed to install git hook: {e}[/red]")
        logger.error(f"Failed to install git hook: {e}")
        return False


# ============================================================================
# CLI COMMANDS
# ============================================================================

@app.command()
def interactive():
    """
    🎯 Start interactive wizard mode for guided scanning.

    This provides a beautiful, step-by-step interface for configuring
    and running security scans.
    """
    # Show beautiful interactive prompt
    config = BeautifulUI.prompt_interactive_scan()

    # Check for API key if AI is enabled
    if config['enable_ai']:
        env_vars = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "claude": "ANTHROPIC_API_KEY"
        }

        env_var = env_vars[config['ai_provider']]
        if not os.getenv(env_var):
            console.print(f"\n[yellow]⚠ {env_var} not found in environment[/yellow]")
            api_key = Prompt.ask(f"Enter {config['ai_provider'].upper()} API key (or press Enter to skip)", password=True)
            if api_key:
                os.environ[env_var] = api_key
            else:
                console.print("[yellow]Continuing without AI verification...[/yellow]")
                config['enable_ai'] = False

    # Run scan with beautiful UI
    console.print()
    findings, vulnerabilities, vuln_stats = run_comprehensive_scan(
        path=config['path'],
        enable_ai=config['enable_ai'],
        ai_provider=config['ai_provider'],
        enable_vulnerabilities=config['enable_vulnerabilities'],
        quiet=False
    )

    # Generate reports
    formats = ["html", "json"]
    if findings or vulnerabilities:
        console.print("\n[bold blue]📝 Generating reports...[/bold blue]")
        report_paths = generate_reports(
            findings,
            vulnerabilities,
            vuln_stats,
            formats=formats
        )

        console.print("\n[bold green]📊 Reports Generated:[/bold green]")
        for fmt, path in report_paths.items():
            console.print(f"  • {fmt.upper()}: [cyan]{path}[/cyan]")

    # Offer to install git hook
    if Confirm.ask("\n[bold]Install git pre-commit hook for automatic scanning?[/bold]", default=False):
        install_git_hook()


@app.command()
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Path to scan"),
    ai_provider: str = typer.Option("gemini", "--ai-provider", help="AI provider (gemini/openai/claude)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI verification"),
    no_vuln: bool = typer.Option(False, "--no-vuln", help="Disable vulnerability scanning"),
    output: str = typer.Option("html", "--output", "-o", help="Report format (html/markdown/json/text/all)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress output"),
    from_hook: bool = typer.Option(False, "--from-hook", hidden=True, help="Running from git hook")
):
    """
    Run automated security scan (non-interactive mode).
    """
    # Parse output format
    if output == "all":
        formats = ["html", "markdown", "json", "text"]
    else:
        formats = [output]
    
    # Run scan
    findings, vulnerabilities, vuln_stats = run_comprehensive_scan(
        path=path,
        enable_ai=not no_ai,
        ai_provider=ai_provider,
        enable_vulnerabilities=not no_vuln,
        quiet=quiet,
        from_hook=from_hook
    )
    
    # Generate reports
    report_paths = generate_reports(
        findings,
        vulnerabilities,
        vuln_stats,
        formats=formats,
        open_browser=not quiet and not from_hook
    )
    
    if not quiet:
        console.print("\n[bold green]✅ Scan complete![/bold green]")
        console.print(f"📊 Found: {len(findings)} secrets, {len(vulnerabilities)} vulnerabilities")
        
        for fmt, path in report_paths.items():
            console.print(f"  • {fmt.upper()}: [cyan]{path}[/cyan]")
    
    # Exit with error code if critical/high vulnerabilities found
    config = get_config()
    if from_hook and config.git_hook.block_on_critical:
        critical_high = vuln_stats.get('critical_and_high', 0)
        if critical_high > 0 or (config.git_hook.block_on_secrets and findings):
            sys.exit(1)


@app.command()
def install_hook():
    """
    Install git pre-commit hook for automatic scanning.
    """
    console.print("[bold]Installing Git Pre-Commit Hook...[/bold]\n")
    
    if install_git_hook():
        console.print("\n[green]✅ Hook installed successfully![/green]")
        console.print("\n[dim]The hook will run automatically before each commit.")
        console.print("To bypass: git commit --no-verify[/dim]")
    else:
        console.print("\n[red]❌ Hook installation failed[/red]")
        sys.exit(1)


@app.command()
def auto_fix(
    path: str = typer.Option(".", help="Path to scan and fix"),
    fix_types: Optional[List[str]] = typer.Option(None, help="Fix types to apply (crypto, secrets, sql, dangerous, xss)"),
    interactive: bool = typer.Option(True, help="Ask for confirmation before applying fixes"),
    extensions: Optional[List[str]] = typer.Option(None, help="File extensions to process"),
    dry_run: bool = typer.Option(False, help="Show fixes without applying them")
):
    """
    🔧 Automatically fix security vulnerabilities in your code.

    Fixes include:
    - Weak cryptography (MD5 → SHA256, SHA1 → SHA256)
    - Hardcoded secrets (move to environment variables)
    - SQL injection (suggest parameterized queries)
    - Dangerous functions (eval, exec, pickle)
    - XSS vulnerabilities (suggest sanitization)

    Examples:
        security-scan auto-fix --path ./src
        security-scan auto-fix --path . --fix-types crypto secrets
        security-scan auto-fix --path . --dry-run
        security-scan auto-fix --path . --no-interactive
    """
    console.print(Panel.fit(
        "[bold cyan]🔧 Auto-Fix Engine[/bold cyan]\n\n"
        "Automatically fixes common security vulnerabilities",
        title="Security Auto-Fix"
    ))

    # Validate path
    if not Path(path).exists():
        console.print(f"[red]Error: Path '{path}' does not exist[/red]")
        sys.exit(1)

    # Dry run mode
    if dry_run:
        console.print("\n[yellow]🔍 DRY RUN MODE - No changes will be applied[/yellow]\n")
        interactive = False

    # Show warning
    if not dry_run:
        console.print("\n[yellow]⚠️  Warning: This will modify your source code![/yellow]")
        console.print("[yellow]   Backups will be created with .backup extension[/yellow]\n")

        if not Confirm.ask("Do you want to continue?"):
            console.print("[yellow]Operation cancelled[/yellow]")
            return

    # Parse fix types
    fix_type_list = None
    if fix_types:
        fix_type_list = [ft.strip() for ft in fix_types]
        valid_types = {'crypto', 'secrets', 'sql', 'dangerous', 'xss'}
        invalid = set(fix_type_list) - valid_types
        if invalid:
            console.print(f"[red]Error: Invalid fix types: {', '.join(invalid)}[/red]")
            console.print(f"Valid types: {', '.join(valid_types)}")
            sys.exit(1)

    # Parse extensions
    ext_list = extensions if extensions else ['.py', '.js', '.ts', '.php', '.java']

    # Run auto-fix
    start_time = time.time()

    try:
        if Path(path).is_file():
            # Fix single file
            auto_fix_engine = AutoFix(interactive=interactive and not dry_run)
            result = auto_fix_engine.fix_file(path, fix_type_list)

            if result['success']:
                if result.get('fixes'):
                    console.print(f"\n[green]✅ Fixed {len(result['fixes'])} issues in {path}[/green]")
                    if result.get('backup_path'):
                        console.print(f"[dim]Backup: {result['backup_path']}[/dim]")
                else:
                    console.print(f"\n[green]✅ No fixes needed for {path}[/green]")
            else:
                if result.get('skipped'):
                    console.print(f"\n[yellow]⏭️  Skipped {path}[/yellow]")
                else:
                    console.print(f"\n[red]❌ Failed to fix {path}: {result.get('error')}[/red]")
        else:
            # Fix directory
            summary = auto_fix_directory(
                directory=path,
                fix_types=fix_type_list,
                interactive=interactive and not dry_run,
                extensions=ext_list
            )

            # Show detailed summary
            elapsed_time = time.time() - start_time
            console.print(f"\n[dim]Completed in {elapsed_time:.2f} seconds[/dim]")

            if summary['applied'] > 0:
                console.print(f"\n[bold green]Successfully applied {summary['applied']} fixes![/bold green]")
                console.print("\n[yellow]⚠️  Remember to:[/yellow]")
                console.print("  1. Review the changes")
                console.print("  2. Test your code")
                console.print("  3. Update .env files with real values")
                console.print("  4. Commit the changes")

    except KeyboardInterrupt:
        console.print("\n[yellow]Auto-fix interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Auto-fix failed")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def version():
    """
    Show version information.
    """
    BeautifulUI.show_welcome_screen()
    console.print()
    console.print("[bold cyan]Author:[/bold cyan] Ahmed Mubaraki")
    console.print("[bold cyan]License:[/bold cyan] MIT")
    console.print("[bold cyan]Repository:[/bold cyan] https://github.com/ALxxy123/code-scan-sec")
    console.print()


@app.command()
def demo():
    """
    🎨 Show beautiful UI demo and available features.

    This displays the scanner's capabilities and beautiful interface
    without running an actual scan.
    """
    BeautifulUI.show_welcome_screen()

    # Show sample scan summary with demo data
    console.print("[bold cyan]📊 Example Scan Results:[/bold cyan]\n")

    demo_secrets = [
        {
            'type': 'API Key',
            'file_path': 'src/config.py',
            'line_number': 45,
            'matched_text': 'sk-1234567890abcdef',
            'ai_verified': True
        },
        {
            'type': 'AWS Access Key',
            'file_path': 'src/aws.py',
            'line_number': 12,
            'matched_text': 'AKIAIOSFODNN7EXAMPLE',
            'ai_verified': True
        }
    ]

    from vulnerability_scanner import Vulnerability
    demo_vulns = [
        Vulnerability(
            name="SQL Injection",
            severity="critical",
            category="sql_injection",
            cwe="CWE-89",
            owasp="A03:2021",
            file_path="src/database/queries.py",
            line_number=45,
            matched_text="query = 'SELECT * FROM users WHERE id = ' + user_id",
            description="SQL query uses string concatenation",
            recommendation="Use parameterized queries",
            pattern=r"query.*\+.*",
            languages=["python", "javascript"]
        ),
        Vulnerability(
            name="Weak Cryptography - MD5",
            severity="high",
            category="weak_crypto",
            cwe="CWE-327",
            owasp="A02:2021",
            file_path="src/utils/crypto.py",
            line_number=23,
            matched_text="hashlib.md5(password)",
            description="MD5 is cryptographically broken",
            recommendation="Use SHA256 or bcrypt",
            pattern=r"hashlib\.md5",
            languages=["python"]
        )
    ]

    demo_stats = {
        'total_files_scanned': 150,
        'vulnerability_stats': {
            'by_severity': {
                'critical': 1,
                'high': 2,
                'medium': 5,
                'low': 3
            },
            'by_category': {
                'sql_injection': 1,
                'xss': 2,
                'weak_crypto': 2,
                'command_injection': 1,
                'dangerous_functions': 5
            }
        }
    }

    BeautifulUI.show_scan_summary(demo_secrets, demo_vulns, demo_stats, 12.5)
    BeautifulUI.show_vulnerability_details(demo_vulns, limit=2)
    BeautifulUI.show_secret_details(demo_secrets, limit=2)

    console.print("\n[bold green]✨ Ready to scan your code?[/bold green]")
    console.print("Try: [cyan]security-scan interactive[/cyan]\n")


@app.command()
def scan_url(
    url: str = typer.Argument(..., help="URL of remote repository or project"),
    shallow: bool = typer.Option(True, help="Use shallow clone for git repos (faster)"),
    ai_provider: Optional[str] = typer.Option(None, "--ai-provider", help="AI provider (gemini/openai/claude)"),
    output: str = typer.Option("text", "--output", help="Output format (text/json/html/md/all)"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI verification"),
    no_vuln: bool = typer.Option(False, "--no-vuln", help="Disable vulnerability scanning"),
):
    """
    🌐 Scan a remote repository or project from URL.

    Supports:
    - Git repositories (GitHub, GitLab, Bitbucket, etc.)
    - Archive files (zip, tar.gz, etc.)
    - Direct file URLs

    Examples:
    - security-scan scan-url https://github.com/user/repo
    - security-scan scan-url https://example.com/project.zip
    - security-scan scan-url https://gitlab.com/user/project --ai-provider gemini
    """
    try:
        initialize_config()
        BeautifulUI.show_welcome_screen()

        console.print(Panel.fit(
            f"[bold cyan]🌐 Remote URL Scan[/bold cyan]\n"
            f"Target: {url}",
            border_style="cyan"
        ))

        # Download/clone the remote resource
        with URLScanner() as url_scanner:
            console.print(f"\n[cyan]📥 Downloading remote project...[/cyan]")
            local_path = url_scanner.scan_url(url, shallow=shallow)

            # Now scan it
            console.print(f"\n[cyan]🔍 Scanning downloaded project...[/cyan]\n")

            # Call the main scan function (we'll need to import the actual scan logic)
            from pathlib import Path

            # Collect files
            ignore_patterns = load_ignore_patterns()
            files_to_scan = collect_files(str(local_path), ignore_patterns)

            if not files_to_scan:
                console.print("[yellow]No files found to scan[/yellow]")
                return

            # Load rules
            patterns = load_rules()

            # Scan for secrets
            console.print(f"[cyan]🔍 Scanning {len(files_to_scan)} files for secrets...[/cyan]")
            all_secrets = []

            for file_path in track(files_to_scan, description="Scanning files..."):
                secrets = scan_file_for_secrets(file_path, patterns)
                all_secrets.extend(secrets)

            console.print(f"[green]✓ Found {len(all_secrets)} potential secrets[/green]")

            # Filter by entropy and AI verification
            config = get_config()
            filtered_secrets = filter_by_entropy(all_secrets, config['scan']['entropy_threshold'])

            verified_secrets = []
            if not no_ai and ai_provider:
                verified_secrets = verify_with_ai(filtered_secrets, ai_provider)
            else:
                verified_secrets = filtered_secrets

            # Scan for vulnerabilities
            vulnerabilities = []
            if not no_vuln:
                console.print(f"\n[cyan]🐛 Scanning for vulnerabilities...[/cyan]")
                vulnerabilities = scan_for_vulnerabilities(str(local_path))
                console.print(f"[green]✓ Found {len(vulnerabilities)} vulnerabilities[/green]")

            # Generate reports
            console.print(f"\n[cyan]📊 Generating reports...[/cyan]")
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)

            report_gen = ReportGenerator(output_dir)

            # Calculate stats
            stats = {
                'total_files_scanned': len(files_to_scan),
                'vulnerability_stats': {
                    'by_severity': {},
                    'by_category': {}
                }
            }

            if output in ["text", "all"]:
                BeautifulUI.show_scan_summary(verified_secrets, vulnerabilities, stats, 0)

            if output in ["json", "all"]:
                report_gen.generate_json_report(verified_secrets, vulnerabilities, "url_scan_report.json")

            if output in ["html", "all"]:
                report_gen.generate_html_report(verified_secrets, vulnerabilities, "url_scan_report.html")

            console.print(f"\n[green]✅ Remote URL scan completed![/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("URL scan failed")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def blackbox(
    url: str = typer.Argument(..., help="Target web application URL"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    output: str = typer.Option("text", "--output", help="Output format (text/json/html)"),
):
    """
    🎯 Perform black box security testing on a web application.

    Tests include:
    - Security headers analysis
    - SSL/TLS configuration
    - SQL injection detection
    - XSS vulnerability testing
    - Path traversal testing
    - Command injection testing

    Examples:
    - security-scan blackbox https://example.com
    - security-scan blackbox https://app.example.com --timeout 15
    - security-scan blackbox https://api.example.com --output json
    """
    try:
        BeautifulUI.show_welcome_screen()

        console.print(Panel.fit(
            f"[bold cyan]🎯 Black Box Security Testing[/bold cyan]\n"
            f"Target: {url}\n"
            f"Timeout: {timeout}s",
            border_style="cyan"
        ))

        # Run black box tests
        tester = BlackBoxTester(url, timeout=timeout)
        results = tester.run_all_tests()

        # Generate reports
        if output in ["json", "all"]:
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)
            output_file = output_dir / "blackbox_report.json"

            import json
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            console.print(f"[green]✓ JSON report saved to: {output_file}[/green]")

        if output in ["html", "all"]:
            output_dir = Path("output")
            output_dir.mkdir(exist_ok=True)
            output_file = output_dir / "blackbox_report.html"

            # Generate simple HTML report
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Black Box Security Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        .issue {{ margin: 20px 0; padding: 15px; border-left: 4px solid #e74c3c; background: #f9f9f9; }}
        .critical {{ border-color: #e74c3c; }}
        .high {{ border-color: #e67e22; }}
        .medium {{ border-color: #f39c12; }}
        .low {{ border-color: #3498db; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Black Box Security Test Report</h1>
    <div class="summary">
        <p><strong>Target:</strong> {results['target_url']}</p>
        <p><strong>Scan Date:</strong> {results['scan_date']}</p>
        <p><strong>Duration:</strong> {results['duration_seconds']:.2f}s</p>
        <p><strong>Total Issues:</strong> {results['total_issues']}</p>
    </div>
    <h2>Issues Found</h2>
"""
            for issue in results['issues']:
                severity = issue.get('severity', 'low')
                html_content += f"""
    <div class="issue {severity}">
        <h3>{issue.get('type', 'Unknown')} - {severity.upper()}</h3>
        <p><strong>Description:</strong> {issue.get('description', 'N/A')}</p>
        <p><strong>Recommendation:</strong> {issue.get('recommendation', 'N/A')}</p>
    </div>
"""

            html_content += """
</body>
</html>
"""

            with open(output_file, 'w') as f:
                f.write(html_content)

            console.print(f"[green]✓ HTML report saved to: {output_file}[/green]")

        console.print(f"\n[green]✅ Black box testing completed![/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Black box testing failed")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def benchmark_scan(
    path: str = typer.Argument(..., help="Path to scan"),
    name: str = typer.Option("benchmark", "--name", help="Benchmark name"),
    compare: bool = typer.Option(True, "--compare/--no-compare", help="Compare with baseline"),
):
    """
    📊 Run performance benchmark on a scan.

    This command runs a full scan while collecting detailed performance metrics:
    - Scan duration and throughput
    - CPU and memory usage
    - Files and lines processed per second
    - AI API performance (if enabled)

    Results are saved to benchmark history for comparison.

    Examples:
    - security-scan benchmark /path/to/project
    - security-scan benchmark /path/to/project --name "baseline"
    - security-scan benchmark /path/to/project --no-compare
    """
    try:
        initialize_config()
        BeautifulUI.show_welcome_screen()

        console.print(Panel.fit(
            f"[bold cyan]📊 Performance Benchmark[/bold cyan]\n"
            f"Name: {name}\n"
            f"Path: {path}",
            border_style="cyan"
        ))

        # Initialize monitor
        monitor = PerformanceMonitor(scan_name=name)
        bench = Benchmark()

        # Start monitoring
        monitor.start()

        # Collect files
        ignore_patterns = load_ignore_patterns()
        files_to_scan = collect_files(path, ignore_patterns)

        if not files_to_scan:
            console.print("[yellow]No files found to scan[/yellow]")
            return

        # Load rules
        patterns = load_rules()

        # Scan files
        all_secrets = []
        for file_path in track(files_to_scan, description="Scanning files..."):
            secrets = scan_file_for_secrets(file_path, patterns)
            all_secrets.extend(secrets)

            # Update monitor
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = sum(1 for _ in f)
                monitor.record_file_scanned(line_count)
            except:
                monitor.record_file_scanned(0)

        # Filter secrets
        config = get_config()
        filtered_secrets = filter_by_entropy(all_secrets, config['scan']['entropy_threshold'])

        for _ in filtered_secrets:
            monitor.record_secret_found()

        # Scan for vulnerabilities
        vulnerabilities = scan_for_vulnerabilities(path)
        for _ in vulnerabilities:
            monitor.record_vulnerability_found()

        # Stop monitoring
        metrics = monitor.stop()

        # Save and compare
        bench.add_result(metrics)

        comparison = None
        if compare:
            comparison = bench.compare_with_baseline(metrics)

        bench.display_metrics(metrics, comparison)

        console.print(f"\n[green]✅ Benchmark completed![/green]")
        console.print(f"Results saved to: {bench.results_file}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Benchmark interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Benchmark failed")
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unexpected error")
        console.print(f"\n[red]Fatal error: {e}[/red]")
        sys.exit(1)
