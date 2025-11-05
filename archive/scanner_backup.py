import typer
import re
import os
import time
import json
import math
import webbrowser
import subprocess
import google.generativeai as genai
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.spinner import Spinner
from datetime import datetime
import sys
import stat
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.text import Text

# --- (استيراد المزودين) ---
from ai_providers.gemini_provider import GeminiProvider
from ai_providers.openai_provider import OpenAIProvider

# --- الإعدادات والتهيئة ---
console = Console()
app = typer.Typer(help="🛡️ AI-Powered Security Scanner by Ahmed Mubaraki 🛡️")

OUTPUT_DIR = Path("output")
APP_CONFIG_DIR = Path.home() / ".security-scan"
RULES_FILE = APP_CONFIG_DIR / "rules.txt"
IGNORE_FILE = APP_CONFIG_DIR / "ignore.txt"
ENTROPY_THRESHOLD = 3.5 

AI_PROVIDERS = {
    "gemini": GeminiProvider,
    "openai": OpenAIProvider,
}

DEFAULT_RULES = """
# Default rules file for Security Scan
# Add your custom Regex patterns below
password\s*[:=]\s*['"][^'"]+['"];?
token\s*[:=]\s*['"][^'"]+['"];?
API_KEY\s*[:=]\s*['"][^'"]+['"];?
AKIA[0-9A-Z]{16}
AIza[0-9A-Za-z\\-_]{35}
ghp_[a-zA-Z0-9]{36}
"""

# --- (جميع الدوال المساعدة ودوال التقارير كما هي) ---
def initialize_config():
    if not APP_CONFIG_DIR.exists():
        console.print(f"[yellow]First run detected. Creating config directory at: {APP_CONFIG_DIR}[/yellow]")
        APP_CONFIG_DIR.mkdir(parents=True)
    if not RULES_FILE.exists():
        console.print(f"[yellow]No 'rules.txt' found. Creating default rules file...[/yellow]")
        with open(RULES_FILE, "w") as f: f.write(DEFAULT_RULES)
    if not IGNORE_FILE.exists():
        console.print(f"[yellow]No 'ignore.txt' found. Creating empty ignore file...[/yellow]")
        with open(IGNORE_FILE, "w") as f: f.write("# Add files or patterns to ignore, e.g.: *.log\n")

def load_rules() -> list[re.Pattern]:
    if not RULES_FILE.exists():
        console.print(f"[bold red]Error: Config files not found at {RULES_FILE}[/bold red]")
        console.print("Please run [bold]'security-scan interactive'[/bold] once to create them.")
        sys.exit(1)
    with open(RULES_FILE, "r") as f:
        return [
            re.compile(line) for line in f.read().splitlines() 
            if line and not line.strip().startswith("#")
        ]

def load_ignore_patterns() -> list[str]:
    if not IGNORE_FILE.exists():
        return []
    with open(IGNORE_FILE, "r") as f:
        return [
            p.strip() for p in f.read().splitlines() 
            if p.strip() and not p.startswith("#")
        ]

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    entropy = -sum(p * math.log2(p) for p in probabilities if p > 0)
    return entropy

def extract_value_for_entropy(match_string: str) -> str:
    quoted_match = re.search(r"['\"](.+?)['\"]", match_string)
    if quoted_match: return quoted_match.group(1)
    if '=' in match_string:
        parts = match_string.split('=', 1)
        if len(parts) > 1: return parts[1].strip()
    return match_string

def write_text_report(findings: list):
    report_path = OUTPUT_DIR / "results.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("--- AI-Verified Security Scan Results ---\n\n")
        for i, finding in enumerate(findings, 1):
            f.write(f"Finding #{i}:\n")
            f.write(f"  File:  {finding['file']}:{finding['line']}\n")
            f.write(f"  Rule:  {finding['rule']}\n")
            f.write(f"  Match: {finding['match']}\n")
            f.write("---\n")
    return report_path

def write_json_report(findings: list):
    report_path = OUTPUT_DIR / "results.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
    return report_path

def write_md_report(findings: list, affected_files: int):
    report_path = OUTPUT_DIR / "report.md"
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# 🛡️ Security Scan Report\n\n")
        f.write("## 📊 Summary\n")
        f.write(f"- **Total Findings:** {len(findings)}\n")
        f.write(f"- **Affected Files:** {affected_files}\n")
        f.write(f"- **Scan Date:** {scan_date}\n\n---\n\n")
        f.write("## 📄 Details\n\n")
        f.write("| File | Line | Rule | Match |\n")
        f.write("|------|------|------|-------|\n")
        for finding in findings:
            f.write(f"| `{finding['file']}` | {finding['line']} | `{finding['rule']}` | `{finding['match']}` |\n")
    return report_path

def write_html_report(findings: list, affected_files: int):
    report_path = OUTPUT_DIR / "report.html"
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows_html = ""
    for finding in findings:
        rows_html += f"<tr><td><code>{finding['file']}</code></td><td>{finding['line']}</td><td><code>{finding['rule']}</code></td><td><code>{finding['match']}</code></td></tr>\n"
    html_template = f"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Security Scan Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }}
    .container {{ max-width: 1200px; margin: auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
    .summary {{ background-color: #ecf0f1; padding: 1em; border-radius: 5px; display: flex; justify-content: space-around; }}
    .summary-item {{ text-align: center; }} .summary-item .value {{ font-size: 2em; font-weight: bold; color: #e74c3c; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 2em; }}
    th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; word-break: break-all; }}
    thead {{ background-color: #3498db; color: white; }}
    tbody tr:nth-child(even) {{ background-color: #f2f2f2; }}
    code {{ background-color: #e4e4e4; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
</style></head><body><div class="container">
<h1>🛡️ Security Scan Report</h1><h2>📊 Summary</h2>
<div class="summary">
    <div class="summary-item"><span>Total Findings</span><div class="value">{len(findings)}</div></div>
    <div class="summary-item"><span>Affected Files</span><div class="value">{affected_files}</div></div>
</div>
<p style="text-align:center; margin-top:1em; color:#777;">Scan Date: {scan_date}</p>
<h2>📄 Details</h2>
<table><thead><tr><th>File</th><th>Line</th><th>Rule</th><th>Match</th></tr></thead>
<tbody>{rows_html}</tbody></table></div></body></html>
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    return report_path

def is_wsl() -> bool:
    return "WSL_DISTRO_NAME" in os.environ

def open_browser(file_path: Path):
    try:
        url = f"file://{file_path.resolve()}"
        if is_wsl():
            windows_path = subprocess.check_output(["wslpath", "-w", str(file_path.resolve())]).decode("utf-8").strip()
            subprocess.run(["explorer.exe", windows_path], check=True)
        else:
            webbrowser.open(url)
        console.print(f"\n[bold green]Opening report in your browser...[/bold green]")
    except Exception as e:
        console.print(f"\n[bold red]Error opening browser:[/bold red] {e}")
        console.print(f"You can open the file manually at: {url}")

# --- (هنا الإصلاح) ---
# تم تعديل هذه الدالة لتقبل "quiet" و "from_hook"
def run_scan(path: str, no_ai: bool, ai_provider: str, quiet: bool, from_hook: bool) -> list:
    if not quiet:
        console.rule("[bold blue]Starting AI-Powered Security Scan[/bold blue]")
        console.print(f"Target Path: [cyan]{path}[/cyan]")
    OUTPUT_DIR.mkdir(exist_ok=True)
    ai_client = None
    if not no_ai:
        if ai_provider in AI_PROVIDERS:
            ProviderClass = AI_PROVIDERS[ai_provider]
            ai_client = ProviderClass()
            if not ai_client.initialize(quiet=quiet):
                ai_client = None
                no_ai = True
        else:
            if not quiet: console.print(f"[bold red]Error: AI provider '{ai_provider}' not found. Disabling AI.[/bold red]")
            no_ai = True

    if not quiet:
        with console.status("[bold green]Loading rules and ignore patterns...[/bold green]", spinner="dots"):
            rules = load_rules()
            ignore_patterns = load_ignore_patterns()
        console.print(f"Loaded [bold green]{len(rules)}[/bold green] rules.")
    else:
        rules = load_rules()
        ignore_patterns = load_ignore_patterns()

    if not quiet:
        with console.status("[bold green]Finding files...[/bold green]", spinner="dots8Bit") as status:
            target_path = Path(path)
            all_files = list(target_path.rglob("*"))
            files_to_scan = [f for f in all_files if f.is_file() and '.git' not in str(f) and 'venv' not in str(f) and str(OUTPUT_DIR) not in str(f)]
            status.update(f"[bold green]Found {len(files_to_scan)} files to scan.[/bold green]")
    else:
        target_path = Path(path)
        all_files = list(target_path.rglob("*"))
        files_to_scan = [f for f in all_files if f.is_file() and '.git' not in str(f) and 'venv' not in str(f) and str(OUTPUT_DIR) not in str(f)]

    potential_findings = []
    if not quiet:
        console.print("\nScanning files:")
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(files_to_scan))
            for file_path in files_to_scan:
                progress.update(task, advance=1, description=f"[cyan]Scanning {file_path.name}[/cyan]")
                try:
                    with open(file_path, "r", encoding="utf-8") as file:
                        for line_num, line in enumerate(file, 1):
                            for rule in rules:
                                match = rule.search(line)
                                if match:
                                    potential_findings.append({"file": str(file_path), "line": line_num, "match": match.group(0).strip(), "rule": rule.pattern})
                                    break
                except Exception: pass
    else:
        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    for line_num, line in enumerate(file, 1):
                        for rule in rules:
                            match = rule.search(line)
                            if match:
                                potential_findings.append({"file": str(file_path), "line": line_num, "match": match.group(0).strip(), "rule": rule.pattern})
                                break
            except Exception: pass

    findings_for_ai = []
    final_findings = [] 
    if not no_ai:
        if not quiet: console.print("\n[bold blue]Pre-filtering findings with Entropy Check...[/bold blue]")
        for f in potential_findings:
            value_to_check = extract_value_for_entropy(f['match'])
            entropy = calculate_entropy(value_to_check)
            if entropy > ENTROPY_THRESHOLD:
                findings_for_ai.append(f)
                if not quiet: console.print(f"[Entropy] HIGH ({entropy:.2f}) -> Queued for AI: {f['match'][:20]}...")
            else:
                if not quiet: console.print(f"[Entropy] LOW ({entropy:.2f})  -> Ignored (Simple): {f['match'][:20]}...")
    else:
        final_findings = potential_findings 

    if not no_ai and findings_for_ai:
        if not quiet: console.print(f"\n[bold yellow]Verifying high-entropy findings with {ai_provider}...[/bold yellow]")
        with console.status("[bold yellow]Communicating with AI...[/bold yellow]", spinner="moon"):
            for finding in findings_for_ai:
                if ai_client.verify(finding["match"], quiet=quiet):
                    final_findings.append(finding) 

    if not quiet: console.print("\n[bold green]✅ Scan Complete![/bold green]")
    return final_findings

def print_welcome_banner():
    console.clear() 
    ascii_art = r"""
 ██████╗ ██████╗  █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝ ██╔══██╗██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
╚█████╗  ██████╔╝███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ╚═══██╗ ██╔══██╗██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██████╔╝ ██║  ██║██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    title = Text(ascii_art, style="bold magenta", justify="center")
    subtitle = Text("AI - P O W E R E D   S E C U R I T Y   S C A N N E R", style="bold blue", justify="center")
    developed_by = Text("\nDeveloped by Ahmed Mubaraki", style="dim italic", justify="center")
    panel_content = Text.assemble(title, "\n", subtitle, developed_by)
    console.print(Panel(panel_content, padding=(1, 4), expand=False, border_style="dim"))
    with console.status("[bold green]Initializing engine...", spinner="dots8Bit"):
        initialize_config() 
        time.sleep(1)
    console.print("\nWelcome to the interactive scanner.\n")

@app.command()
def interactive():
    """
    Starts the interactive (TUI) mode to guide you through a scan.
    """
    while True:
        print_welcome_banner()
        use_ai = Confirm.ask("Do you want to use AI to verify results (reduces false positives)?", default=True)
        ai_provider = "gemini" 
        if use_ai:
            ai_provider = Prompt.ask(
                "Which AI provider do you want to use?",
                choices=["gemini", "openai"],
                default="gemini"
            )
            key_name = f"{ai_provider.upper()}_API_KEY"
            api_key = Prompt.ask(
                f"Please enter your [bold yellow]{key_name}[/bold yellow]",
                password=True
            )
            os.environ[key_name] = api_key
        scan_path = Prompt.ask(
            "Enter the path to the project you want to scan",
            default="."
        )

        final_findings = run_scan(
            path=scan_path,
            no_ai=not use_ai,
            ai_provider=ai_provider,
            quiet=False, # (جديد) تمرير المتغيرات الناقصة
            from_hook=False # (جديد) تمرير المتغيرات الناقصة
        )

        if not final_findings:
            console.print("No secrets found. Your code is clean! ✨")
        else:
            console.print(f"\n[bold red]Found {len(final_findings)} VERIFIED secrets![/bold red]")
            affected_files_count = len(set(f['file'] for f in final_findings))

            table = Table(title="AI-Verified Scan Results", show_header=True, header_style="bold magenta")
            table.add_column("File", style="cyan")
            table.add_column("Line", style="green")
            table.add_column("Rule", style="yellow")
            table.add_column("Match", style="red")
            for finding in final_findings:
                table.add_row(finding["file"], str(finding["line"]), finding["rule"], finding["match"])
            console.print(table)

            console.print("\n" + "-"*30 + "\n")
            output_format = Prompt.ask(
                "Which report format do you want to generate?",
                choices=["html", "md", "json", "text", "all", "none"],
                default="html"
            )

            if output_format != "none":
                report_paths = []
                with console.status("[bold green]Generating reports...[/bold green]", spinner="dots"):
                    if output_format == "json" or output_format == "all":
                        report_paths.append(write_json_report(final_findings))
                    if output_format == "text" or output_format == "all":
                        report_paths.append(write_text_report(final_findings))
                    if output_format == "md" or output_format == "all":
                        report_paths.append(write_md_report(final_findings, affected_files_count))
                    if output_format == "html" or output_format == "all":
                        report_paths.append(write_html_report(final_findings, affected_files_count))

                console.print(f"\n[bold green]✅ Reports successfully generated![/bold green]")
                for path in report_paths:
                    if path:
                        full_path = path.resolve()
                        console.print(f"- [link=file://{full_path}]{full_path}[/link]")

                if "html" in output_format or "all" in output_format:
                    if Confirm.ask("\nDo you want to open the HTML report now?", default=True):
                        open_browser(OUTPUT_DIR / "report.html")

        console.print("\n" + "="*80 + "\n")
        if not Confirm.ask("Do you want to run another scan?", default=True):
            console.print("\n[bold magenta]Goodbye![/bold magenta] 👋")
            break

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    AI-Powered Security Scanner.
    If no command is specified, runs the interactive mode.
    """
    if ctx.invoked_subcommand is None:
        interactive()

@app.command()
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Path to the directory to scan."),
    output: str = typer.Option("none", "--output", "-o", help="Report format (json, text, md, html, all, none)."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI verification."),
    ai_provider: str = typer.Option("gemini", "--ai-provider", help="AI provider to use (gemini, openai)."),
    from_hook: bool = typer.Option(False, hidden=True),
    quiet: bool = typer.Option(False, "--quiet", hidden=True)
):
    """
    Runs a non-interactive scan. (Used by automation & Git hooks)
    """
    initialize_config() 

    # --- (هنا الإصلاح) ---
    # تمرير جميع المتغيرات الخمسة
    final_findings = run_scan(path, no_ai, ai_provider, quiet, from_hook)

    if not final_findings:
        if not quiet: console.print("No secrets found. Your code is clean! ✨")
        if from_hook: sys.exit(0)
        return

    affected_files_count = len(set(f['file'] for f in final_findings))

    if not quiet:
        console.print(f"\n[bold red]Found {len(final_findings)} VERIFIED secrets![/bold red]")
        table = Table(title="AI-Verified Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("File", style="cyan")
        table.add_column("Line", style="green")
        table.add_column("Rule", style="yellow")
        table.add_column("Match", style="red")
        for finding in final_findings:
            table.add_row(finding["file"], str(finding["line"]), finding["rule"], finding["match"])
        console.print(table)

    if output and output != "none":
        if not quiet: console.print("\n[bold blue]Generating Reports...[/bold blue]")
        report_paths = []
        if output == "json" or output == "all":
            report_paths.append(write_json_report(final_findings))
        if output == "text" or output == "all":
            report_paths.append(write_text_report(final_findings))
        if output == "md" or output == "all":
            report_paths.append(write_md_report(final_findings, affected_files_count))
        if output == "html" or output == "all":
            report_paths.append(write_html_report(final_findings, affected_files_count))
        if not quiet and report_paths:
            console.print("\n[bold green]Reports successfully generated at:[/bold green]")
            for path in report_paths:
                console.print(f"- [link=file://{Path(path).resolve()}]{Path(path).resolve()}[/link]")

    if from_hook:
        console.print("\n[bold red]COMMIT REJECTED:[/bold red] Secrets detected. Please review findings and try again.")
        sys.exit(1)

@app.command()
def install_hook(
    project_path: str = typer.Option(".", "--path", "-p", help="Path to the Git project to install the hook in.")
):
    """
    Installs the pre-commit hook into a Git repository.
    """
    console.rule("[bold blue]Installing Git Pre-Commit Hook[/bold blue]")
    git_dir = Path(project_path) / ".git"
    if not git_dir.is_dir():
        console.print(f"[bold red]Error: '{git_dir}' is not a Git repository. Run 'git init' first.[/bold red]")
        raise typer.Exit(1)
    hook_dir = git_dir / "hooks"
    hook_file = hook_dir / "pre-commit"
    console.print(f"Target repository: [cyan]{git_dir.resolve()}[/cyan]")

    hook_script_content = f"""
#!/bin/sh
# Security Scan Pre-Commit Hook (Managed by security-scan)
echo "--- Running Security Scan (Pre-Commit) ---"
export PATH="$HOME/.local/bin:$PATH"
security-scan scan --no-ai --from-hook --output none
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "----------------------------------------------"
    echo "COMMIT FAILED: Secrets found in your code."
    echo "----------------------------------------------"
    exit 1
else
    echo "--- Security Scan PASSED ---"
    exit 0
fi
"""

    try:
        if hook_file.exists():
            console.print(f"[yellow]Warning: A 'pre-commit' hook already exists. Backing it up to 'pre-commit.bak'...[/yellow]")
            os.rename(hook_file, hook_file.with_suffix(".bak"))
        with open(hook_file, "w") as f:
            f.write(hook_script_content)
        st = os.stat(hook_file)
        os.chmod(hook_file, st.st_mode | stat.S_IEXEC)
        console.print(f"[bold green]✅ Git hook installed successfully to: {hook_file}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error installing hook: {e}[/bold red]")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
