"""
Enhanced AI-Powered Security Scanner.

This is a comprehensive security scanner that detects:
- Hardcoded secrets, API keys, passwords, and credentials
- Security vulnerabilities (SQL Injection, XSS, Command Injection, etc.)
- Uses AI verification to reduce false positives

Version: 3.0.0
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


def load_rules() -> List[re.Pattern]:
    """
    Load regex patterns from rules file.
    
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
        logger.info(f"Loaded {len(patterns)} rules from {RULES_FILE}")
        return patterns
    except re.error as e:
        logger.error(f"Invalid regex pattern in rules file: {e}")
        console.print(f"[bold red]Error: Invalid regex in rules file: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load rules: {e}")
        console.print(f"[bold red]Error loading rules: {e}[/bold red]")
        sys.exit(1)


def load_ignore_patterns() -> List[str]:
    """
    Load ignore patterns from ignore file.
    
    Returns:
        List[str]: List of patterns to ignore
    """
    if not IGNORE_FILE.exists():
        return []
    
    try:
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            patterns = [
                p.strip()
                for p in f.read().splitlines()
                if p.strip() and not p.startswith("#")
            ]
        logger.info(f"Loaded {len(patterns)} ignore patterns")
        return patterns
    except Exception as e:
        logger.warning(f"Failed to load ignore patterns: {e}")
        return []


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
    
    # Calculate character frequency probabilities
    probabilities = [text.count(c) / len(text) for c in set(text)]
    
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
    ignore_patterns: Optional[List[str]] = None
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
    
    # Collect all files
    all_files = list(target_path.rglob("*"))
    files_to_scan = []
    
    for file_path in all_files:
        if not file_path.is_file():
            continue
            
        # Check ignore patterns
        should_ignore = False
        for pattern in all_ignores:
            if file_path.match(pattern):
                should_ignore = True
                break
        
        if not should_ignore:
            files_to_scan.append(file_path)
    
    logger.info(f"Found {len(files_to_scan)} files to scan")
    return files_to_scan


def scan_for_secrets(
    files: List[Path],
    rules: List[re.Pattern],
    quiet: bool = False
) -> List[Dict]:
    """
    Scan files for potential secrets using regex patterns.
    
    Args:
        files: List of files to scan
        rules: Compiled regex patterns
        quiet: Suppress progress output
        
    Returns:
        List[Dict]: List of potential findings
    """
    logger.info(f"Scanning {len(files)} files for secrets...")
    potential_findings = []
    
    if quiet:
        # Silent mode
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for rule in rules:
                            match = rule.search(line)
                            if match:
                                potential_findings.append({
                                    "file": str(file_path),
                                    "line": line_num,
                                    "match": match.group(0).strip(),
                                    "rule": rule.pattern
                                })
                                break  # One match per line
            except Exception as e:
                logger.debug(f"Failed to scan {file_path}: {e}")
    else:
        # With progress bar
        console.print("\n[bold blue]Scanning files for secrets...[/bold blue]")
        for file_path in track(files, description="[cyan]Scanning..."):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for rule in rules:
                            match = rule.search(line)
                            if match:
                                potential_findings.append({
                                    "file": str(file_path),
                                    "line": line_num,
                                    "match": match.group(0).strip(),
                                    "rule": rule.pattern
                                })
                                break
            except Exception as e:
                logger.debug(f"Failed to scan {file_path}: {e}")
    
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
    
    if not quiet and not from_hook:
        console.rule("[bold blue]🛡️  Security Scan Started[/bold blue]")
        console.print(f"📂 Target: [cyan]{path}[/cyan]")
        console.print(f"🤖 AI Verification: [cyan]{'Enabled' if enable_ai else 'Disabled'}[/cyan]")
        console.print(f"🐛 Vulnerability Scan: [cyan]{'Enabled' if enable_vulnerabilities else 'Disabled'}[/cyan]\n")
    
    logger.info(f"Starting scan: path={path}, ai={enable_ai}, vuln={enable_vulnerabilities}")
    
    # Load rules and patterns
    rules = load_rules()
    ignore_patterns = load_ignore_patterns()
    
    # Collect files
    files = collect_files(path, ignore_patterns)
    
    if not files:
        logger.warning("No files found to scan")
        if not quiet:
            console.print("[yellow]No files found to scan[/yellow]")
        return [], [], {}
    
    # Scan for secrets
    potential_findings = scan_for_secrets(files, rules, quiet)
    
    # Filter by entropy
    entropy_threshold = config.scan.entropy_threshold
    high_entropy_findings = filter_by_entropy(potential_findings, entropy_threshold, quiet)
    
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
            console.print("\n[bold blue]🐛 Scanning for vulnerabilities...[/bold blue]")
        
        try:
            vulnerabilities, vuln_stats = scan_for_vulnerabilities(
                path,
                min_severity=config.vulnerabilities.severity_levels[0]
                    if config.vulnerabilities.severity_levels else "low"
            )
            
            if not quiet:
                console.print(
                    f"[green]Found {len(vulnerabilities)} vulnerabilities[/green] "
                    f"([red]{vuln_stats.get('critical_and_high', 0)} critical/high[/red])"
                )
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            if not quiet:
                console.print(f"[yellow]Warning: Vulnerability scan failed: {e}[/yellow]")
    
    if not quiet and not from_hook:
        console.rule("[bold green]✅ Scan Complete[/bold green]")
    
    logger.info(
        f"Scan complete: {len(final_findings)} secrets, "
        f"{len(vulnerabilities)} vulnerabilities"
    )
    
    return final_findings, vulnerabilities, vuln_stats


def generate_reports(
    findings: List[Dict],
    vulnerabilities: List,
    vuln_stats: Dict,
    formats: List[str] = None,
    output_dir: str = "output",
    open_browser: bool = True
) -> Dict[str, Path]:
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
        Dict[str, Path]: Generated report paths
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
    if "text" in formats:
        report_paths["text"] = generator.write_text_report(findings, vulnerabilities)
    
    if "json" in formats:
        report_paths["json"] = generator.write_json_report(findings, vulnerabilities, vuln_stats)
    
    if "markdown" in formats:
        report_paths["markdown"] = generator.write_md_report(
            findings, affected_files, vulnerabilities, vuln_stats
        )
    
    if "html" in formats:
        html_path = generator.write_html_report(
            findings, affected_files, vulnerabilities, vuln_stats
        )
        report_paths["html"] = html_path
        
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
        time.sleep(0.5)
    
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
    Start interactive wizard mode for guided scanning.
    """
    print_welcome_banner()
    
    console.print("[bold]Welcome to Interactive Mode![/bold]\n")
    console.print("This wizard will guide you through the security scan process.\n")
    
    # Ask about AI verification
    enable_ai = Confirm.ask("Enable AI verification (reduces false positives)?", default=True)
    
    ai_provider = "gemini"
    if enable_ai:
        console.print("\n[bold]Available AI Providers:[/bold]")
        console.print("  1. Gemini (Google) - Fast and accurate")
        console.print("  2. OpenAI (ChatGPT) - Reliable")
        console.print("  3. Claude (Anthropic) - Advanced reasoning\n")
        
        provider_choice = Prompt.ask(
            "Select AI provider",
            choices=["1", "2", "3"],
            default="1"
        )
        
        provider_map = {"1": "gemini", "2": "openai", "3": "claude"}
        ai_provider = provider_map[provider_choice]
        
        # Check for API key
        env_vars = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "claude": "ANTHROPIC_API_KEY"
        }
        
        env_var = env_vars[ai_provider]
        if not os.getenv(env_var):
            console.print(f"\n[yellow]⚠ {env_var} not found in environment[/yellow]")
            api_key = Prompt.ask(f"Enter {ai_provider.upper()} API key (or press Enter to skip)")
            if api_key:
                os.environ[env_var] = api_key
            else:
                console.print("[yellow]Continuing without AI verification...[/yellow]")
                enable_ai = False
    
    # Ask about vulnerability scanning
    enable_vulns = Confirm.ask("\nEnable vulnerability scanning?", default=True)
    
    # Ask for path
    default_path = "."
    path = Prompt.ask("\nPath to scan", default=default_path)
    
    # Ask for report format
    console.print("\n[bold]Report Formats:[/bold]")
    console.print("  1. HTML (recommended)")
    console.print("  2. Markdown")
    console.print("  3. JSON")
    console.print("  4. Text")
    console.print("  5. All formats\n")
    
    format_choice = Prompt.ask(
        "Select report format",
        choices=["1", "2", "3", "4", "5"],
        default="1"
    )
    
    format_map = {
        "1": ["html"],
        "2": ["markdown"],
        "3": ["json"],
        "4": ["text"],
        "5": ["html", "markdown", "json", "text"]
    }
    
    formats = format_map[format_choice]
    
    # Run scan
    console.print()
    findings, vulnerabilities, vuln_stats = run_comprehensive_scan(
        path=path,
        enable_ai=enable_ai,
        ai_provider=ai_provider,
        enable_vulnerabilities=enable_vulns,
        quiet=False
    )
    
    # Generate reports
    if findings or vulnerabilities:
        console.print("\n[bold blue]Generating reports...[/bold blue]")
        report_paths = generate_reports(
            findings,
            vulnerabilities,
            vuln_stats,
            formats=formats
        )
        
        console.print("\n[bold green]📊 Reports Generated:[/bold green]")
        for fmt, path in report_paths.items():
            console.print(f"  • {fmt.upper()}: [cyan]{path}[/cyan]")
    else:
        console.print("\n[bold green]✨ No security issues found! Your code looks clean.[/bold green]")
    
    # Offer to install git hook
    if Confirm.ask("\nInstall git pre-commit hook for automatic scanning?", default=False):
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
def version():
    """
    Show version information.
    """
    console.print("[bold]Security Scanner v3.0.0[/bold]")
    console.print("Enhanced with AI verification and vulnerability detection")
    console.print("\nAuthor: Ahmed Mubaraki")
    console.print("License: MIT")


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
