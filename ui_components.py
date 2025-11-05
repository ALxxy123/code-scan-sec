"""
Enhanced CLI UI components for beautiful terminal interface.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from rich.columns import Columns
from rich.tree import Tree
from rich.syntax import Syntax
from rich.prompt import Prompt, Confirm
from rich import box
from rich.text import Text
from typing import List, Dict, Optional
import time
from datetime import datetime

console = Console()


class BeautifulUI:
    """Beautiful terminal UI components."""

    @staticmethod
    def show_banner():
        """Display beautiful banner."""
        banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗  ║
║     ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝  ║
║     ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝   ║
║     ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝    ║
║     ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║     ║
║     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝     ║
║                                                                       ║
║              🛡️  AI-Powered Security Scanner v3.1.0  🛡️               ║
║                                                                       ║
║              Advanced Vulnerability & Secret Detection                ║
║                    with Auto-Fix Capabilities                         ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
        """

        console.print(banner, style="bold cyan")
        console.print(Align.center(
            "🔒 Protecting your code, one scan at a time\n",
            style="dim italic"
        ))

    @staticmethod
    def show_welcome_screen():
        """Show welcome screen with options."""
        BeautifulUI.show_banner()

        # Quick stats panel
        stats_panel = Panel(
            "[bold green]✅ Scanner Ready[/bold green]\n\n"
            "• 🤖 3 AI Providers Available (Gemini, OpenAI, Claude)\n"
            "• 🐛 50+ Vulnerability Detection Rules\n"
            "• 🔑 Advanced Secret Detection\n"
            "• 🔧 Auto-Fix Engine Enabled\n"
            "• 🌐 Web Dashboard Available",
            title="[bold cyan]📊 Status[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        )

        console.print(stats_panel)
        console.print()

    @staticmethod
    def create_scan_progress(total_files: int):
        """Create beautiful progress bar for scanning."""
        return Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            TaskProgressColumn(),
            TextColumn("•"),
            TextColumn("[bold green]{task.completed}/{task.total} files"),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            expand=False
        )

    @staticmethod
    def show_scan_header(path: str, ai_provider: str, enable_ai: bool, enable_vuln: bool):
        """Show beautiful scan header."""
        # Configuration table
        config_table = Table(show_header=False, box=box.ROUNDED, border_style="cyan", padding=(0, 2))
        config_table.add_column("Setting", style="bold cyan", width=20)
        config_table.add_column("Value", style="green")

        config_table.add_row("📁 Scan Path", path)
        config_table.add_row("🤖 AI Provider", ai_provider.upper() if enable_ai else "Disabled")
        config_table.add_row("🔑 Secret Detection", "✅ Enabled")
        config_table.add_row("🐛 Vulnerability Scan", "✅ Enabled" if enable_vuln else "❌ Disabled")
        config_table.add_row("🔧 Auto-Fix", "Available")

        panel = Panel(
            config_table,
            title="[bold cyan]🔍 Scan Configuration[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        )

        console.print(panel)
        console.print()

    @staticmethod
    def show_live_stats(current_file: str, secrets_found: int, vulns_found: int,
                       files_scanned: int, total_files: int):
        """Show live scanning statistics."""
        # Create stats display
        stats = f"""
[bold cyan]📂 Current:[/bold cyan] {current_file[:60]}...

[bold green]Progress:[/bold green]
  └─ Files: {files_scanned}/{total_files} ({int(files_scanned/total_files*100)}%)

[bold yellow]Findings:[/bold yellow]
  ├─ 🔑 Secrets: {secrets_found}
  └─ 🐛 Vulnerabilities: {vulns_found}
        """
        return stats

    @staticmethod
    def show_scan_summary(secrets: List[Dict], vulnerabilities: List,
                         stats: Dict, duration: float):
        """Show beautiful scan summary."""
        console.print("\n")

        # Status determination
        critical_count = stats.get('vulnerability_stats', {}).get('by_severity', {}).get('critical', 0)
        secret_count = len(secrets)

        if critical_count > 0 or secret_count > 0:
            status_emoji = "🚨"
            status_text = "CRITICAL ISSUES FOUND"
            status_style = "bold red"
        elif len(vulnerabilities) > 0:
            status_emoji = "⚠️"
            status_text = "ISSUES FOUND"
            status_style = "bold yellow"
        else:
            status_emoji = "✅"
            status_text = "ALL CLEAR"
            status_style = "bold green"

        # Header
        console.print("═" * 80, style="cyan")
        console.print(
            Align.center(
                f"{status_emoji}  [bold]{status_text}[/bold]  {status_emoji}",
                style=status_style
            )
        )
        console.print("═" * 80, style="cyan")
        console.print()

        # Summary table
        summary_table = Table(show_header=False, box=box.ROUNDED, border_style="cyan",
                            padding=(0, 3), expand=True)
        summary_table.add_column("Metric", style="bold cyan", width=30)
        summary_table.add_column("Count", style="bold white", justify="right", width=15)
        summary_table.add_column("Status", style="bold", width=20)

        # Duration
        summary_table.add_row(
            "⏱️  Scan Duration",
            f"{duration:.2f}s",
            "[dim]Completed[/dim]"
        )

        # Files
        summary_table.add_row(
            "📂 Files Scanned",
            str(stats.get('total_files_scanned', 0)),
            "[dim green]✓[/dim green]"
        )

        summary_table.add_section()

        # Secrets
        secret_status = "🔴 ACTION REQUIRED" if secret_count > 0 else "🟢 Clean"
        summary_table.add_row(
            "🔑 Hardcoded Secrets",
            str(secret_count),
            secret_status
        )

        # AI Verified
        ai_verified = sum(1 for s in secrets if s.get('ai_verified', False))
        if secret_count > 0:
            summary_table.add_row(
                "   └─ AI Verified",
                str(ai_verified),
                f"[dim]({int(ai_verified/secret_count*100)}%)[/dim]"
            )

        summary_table.add_section()

        # Vulnerabilities
        total_vulns = len(vulnerabilities)
        vuln_status = "🔴 CRITICAL" if critical_count > 0 else "🟡 Warning" if total_vulns > 0 else "🟢 Clean"
        summary_table.add_row(
            "🐛 Vulnerabilities",
            str(total_vulns),
            vuln_status
        )

        # By severity
        by_severity = stats.get('vulnerability_stats', {}).get('by_severity', {})
        if total_vulns > 0:
            summary_table.add_row(
                "   ├─ 🔴 Critical",
                str(by_severity.get('critical', 0)),
                "[bold red]High Priority[/bold red]" if by_severity.get('critical', 0) > 0 else ""
            )
            summary_table.add_row(
                "   ├─ 🟠 High",
                str(by_severity.get('high', 0)),
                ""
            )
            summary_table.add_row(
                "   ├─ 🟡 Medium",
                str(by_severity.get('medium', 0)),
                ""
            )
            summary_table.add_row(
                "   └─ 🔵 Low",
                str(by_severity.get('low', 0)),
                ""
            )

        console.print(Panel(summary_table, title="[bold cyan]📊 Scan Summary[/bold cyan]",
                          border_style="cyan", padding=(1, 2)))
        console.print()

        # Top categories
        if total_vulns > 0:
            BeautifulUI._show_top_categories(stats)

        # Security score
        BeautifulUI._show_security_score(secret_count, critical_count, total_vulns)

    @staticmethod
    def _show_top_categories(stats: Dict):
        """Show top vulnerability categories."""
        by_category = stats.get('vulnerability_stats', {}).get('by_category', {})

        if by_category:
            console.print("[bold cyan]🏆 Top Vulnerability Categories:[/bold cyan]")
            console.print()

            # Sort by count
            sorted_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:5]

            max_count = max(count for _, count in sorted_categories) if sorted_categories else 1

            for category, count in sorted_categories:
                bar_length = int((count / max_count) * 40)
                bar = "█" * bar_length + "░" * (40 - bar_length)
                console.print(f"  {bar} {category}: [bold]{count}[/bold]")

            console.print()

    @staticmethod
    def _show_security_score(secrets: int, critical: int, total_vulns: int):
        """Calculate and show security score."""
        # Simple scoring algorithm
        score = 100
        score -= secrets * 10  # Each secret -10 points
        score -= critical * 15  # Each critical -15 points
        score -= (total_vulns - critical) * 2  # Other vulns -2 points each
        score = max(0, min(100, score))  # Clamp between 0-100

        # Determine grade
        if score >= 90:
            grade = "A+"
            grade_style = "bold green"
            emoji = "🏆"
        elif score >= 80:
            grade = "A"
            grade_style = "bold green"
            emoji = "✅"
        elif score >= 70:
            grade = "B"
            grade_style = "bold yellow"
            emoji = "👍"
        elif score >= 60:
            grade = "C"
            grade_style = "bold yellow"
            emoji = "⚠️"
        else:
            grade = "F"
            grade_style = "bold red"
            emoji = "🚨"

        # Score bar
        bar_length = int(score / 100 * 50)
        bar = "█" * bar_length + "░" * (50 - bar_length)

        score_display = f"""
[bold cyan]🎯 Security Score:[/bold cyan]

{bar}

[{grade_style}]{emoji} Grade: {grade} ({score}/100)[/{grade_style}]
        """

        console.print(Panel(score_display.strip(), border_style="cyan", padding=(1, 2)))
        console.print()

    @staticmethod
    def show_vulnerability_details(vulnerabilities: List, limit: int = 10):
        """Show detailed vulnerability information."""
        if not vulnerabilities:
            return

        console.print("[bold cyan]🐛 Critical Vulnerabilities:[/bold cyan]")
        console.print()

        # Filter critical and high
        critical_vulns = [v for v in vulnerabilities if v.severity == 'critical'][:limit]

        for i, vuln in enumerate(critical_vulns, 1):
            # Severity styling
            severity_styles = {
                'critical': ('🔴', 'bold red'),
                'high': ('🟠', 'bold yellow'),
                'medium': ('🟡', 'bold yellow'),
                'low': ('🔵', 'bold blue'),
                'info': ('⚪', 'dim')
            }

            emoji, style = severity_styles.get(vuln.severity, ('●', 'white'))

            # Create vulnerability card
            vuln_content = f"""[{style}]{emoji} {vuln.name}[/{style}]

[bold]Location:[/bold] {vuln.file_path}:{vuln.line_number}
[bold]Category:[/bold] {vuln.category}
[bold]CWE:[/bold] {vuln.cwe} | [bold]OWASP:[/bold] {vuln.owasp}

[bold yellow]⚠️  Issue:[/bold yellow]
{vuln.description}

[bold green]✅ Recommendation:[/bold green]
{vuln.recommendation}
            """

            console.print(Panel(
                vuln_content.strip(),
                title=f"[bold]Vulnerability #{i}[/bold]",
                border_style=style.split()[1] if 'bold' in style else 'white',
                padding=(1, 2)
            ))
            console.print()

    @staticmethod
    def show_secret_details(secrets: List[Dict], limit: int = 5):
        """Show detailed secret information."""
        if not secrets:
            return

        console.print("[bold cyan]🔑 Detected Secrets:[/bold cyan]")
        console.print()

        for i, secret in enumerate(secrets[:limit], 1):
            verified = "✅ AI Verified" if secret.get('ai_verified', False) else "⚠️  Needs Review"
            verified_style = "bold green" if secret.get('ai_verified', False) else "bold yellow"

            secret_content = f"""[bold]Type:[/bold] {secret.get('type', 'Unknown')}
[bold]Location:[/bold] {secret.get('file_path', '')}:{secret.get('line_number', 0)}
[{verified_style}]{verified}[/{verified_style}]

[bold red]Matched Text:[/bold red]
[dim]{secret.get('matched_text', '')[:100]}...[/dim]
            """

            console.print(Panel(
                secret_content.strip(),
                title=f"[bold red]Secret #{i}[/bold red]",
                border_style="red",
                padding=(1, 2)
            ))
            console.print()

    @staticmethod
    def show_next_steps(has_critical: bool, has_secrets: bool, has_vulns: bool):
        """Show recommended next steps."""
        steps = []

        if has_critical or has_secrets:
            steps.append("🚨 [bold red]URGENT:[/bold red] Review and fix critical issues immediately")

        if has_secrets:
            steps.append("🔑 Run auto-fix to move secrets to environment variables:")
            steps.append("   [dim]$ security-scan auto-fix --path . --fix-types secrets[/dim]")

        if has_vulns:
            steps.append("🔧 Run auto-fix to automatically fix vulnerabilities:")
            steps.append("   [dim]$ security-scan auto-fix --path .[/dim]")

        steps.append("📊 Generate detailed report:")
        steps.append("   [dim]$ security-scan scan --path . --output all[/dim]")

        steps.append("📈 View in web dashboard:")
        steps.append("   [dim]$ python api_server.py[/dim]")

        if not steps:
            steps.append("✅ No action needed - your code is secure!")

        steps_text = "\n".join(f"  {step}" for step in steps)

        console.print(Panel(
            steps_text,
            title="[bold cyan]📋 Recommended Next Steps[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        ))
        console.print()

    @staticmethod
    def show_comparison(previous_scan: Dict, current_results: Dict):
        """Show comparison with previous scan."""
        console.print("[bold cyan]📊 Comparison with Previous Scan:[/bold cyan]")
        console.print()

        # Create comparison table
        comp_table = Table(show_header=True, box=box.ROUNDED, border_style="cyan")
        comp_table.add_column("Metric", style="bold cyan", width=25)
        comp_table.add_column("Previous", style="dim", justify="center", width=15)
        comp_table.add_column("Current", style="bold", justify="center", width=15)
        comp_table.add_column("Change", justify="center", width=15)

        def format_change(prev, curr):
            diff = curr - prev
            if diff < 0:
                return f"[bold green]✅ {diff:+d}[/bold green]"
            elif diff > 0:
                return f"[bold red]⚠️ {diff:+d}[/bold red]"
            else:
                return "[dim]─[/dim]"

        prev_secrets = previous_scan.get('secrets', 0)
        curr_secrets = current_results.get('total_secrets', 0)
        comp_table.add_row(
            "🔑 Secrets",
            str(prev_secrets),
            str(curr_secrets),
            format_change(prev_secrets, curr_secrets)
        )

        prev_critical = previous_scan.get('critical', 0)
        curr_critical = current_results.get('critical_vulnerabilities', 0)
        comp_table.add_row(
            "🔴 Critical",
            str(prev_critical),
            str(curr_critical),
            format_change(prev_critical, curr_critical)
        )

        prev_high = previous_scan.get('high', 0)
        curr_high = current_results.get('high_vulnerabilities', 0)
        comp_table.add_row(
            "🟠 High",
            str(prev_high),
            str(curr_high),
            format_change(prev_high, curr_high)
        )

        console.print(comp_table)
        console.print()

    @staticmethod
    def prompt_interactive_scan():
        """Interactive prompt for scan configuration."""
        BeautifulUI.show_banner()

        console.print("[bold cyan]🔍 Interactive Scan Configuration[/bold cyan]\n")

        # Scan mode
        scan_modes = {
            "1": ("Quick Scan", "Secrets only (fast)"),
            "2": ("Full Scan", "Secrets + Vulnerabilities (recommended)"),
            "3": ("Custom Scan", "Configure manually")
        }

        console.print("[bold]Select scan mode:[/bold]")
        for key, (name, desc) in scan_modes.items():
            console.print(f"  {key}. {name} - [dim]{desc}[/dim]")

        mode = Prompt.ask("\n[bold cyan]Choice[/bold cyan]", choices=["1", "2", "3"], default="2")

        if mode == "1":
            enable_vuln = False
            enable_ai = True
        elif mode == "2":
            enable_vuln = True
            enable_ai = True
        else:
            enable_vuln = Confirm.ask("\n[bold]Enable vulnerability scanning?[/bold]", default=True)
            enable_ai = Confirm.ask("[bold]Enable AI verification?[/bold]", default=True)

        # Path
        path = Prompt.ask("\n[bold cyan]Scan path[/bold cyan]", default=".")

        # AI Provider
        if enable_ai:
            console.print("\n[bold]Select AI provider:[/bold]")
            console.print("  1. Google Gemini - [dim]Fast & accurate[/dim]")
            console.print("  2. OpenAI - [dim]Reliable[/dim]")
            console.print("  3. Anthropic Claude - [dim]Advanced reasoning[/dim]")

            ai_choice = Prompt.ask("\n[bold cyan]Choice[/bold cyan]", choices=["1", "2", "3"], default="1")
            ai_providers = {"1": "gemini", "2": "openai", "3": "claude"}
            ai_provider = ai_providers[ai_choice]
        else:
            ai_provider = "gemini"

        console.print()
        return {
            'path': path,
            'enable_ai': enable_ai,
            'enable_vulnerabilities': enable_vuln,
            'ai_provider': ai_provider
        }

    @staticmethod
    def show_auto_fix_preview(fixes: List):
        """Show auto-fix preview."""
        console.print("[bold cyan]🔧 Auto-Fix Preview:[/bold cyan]\n")

        for i, fix in enumerate(fixes[:5], 1):
            fix_panel = f"""[bold]Type:[/bold] {fix.vulnerability_type}
[bold]Location:[/bold] {fix.file_path}:{fix.line_number}
[bold]Confidence:[/bold] {fix.confidence.upper()}

[bold red]Original:[/bold red]
[dim]{fix.original_code}[/dim]

[bold green]Fixed:[/bold green]
[dim]{fix.fixed_code}[/dim]
            """

            console.print(Panel(
                fix_panel.strip(),
                title=f"[bold]Fix #{i}[/bold]",
                border_style="yellow",
                padding=(1, 2)
            ))

        if len(fixes) > 5:
            console.print(f"\n[dim]... and {len(fixes) - 5} more fixes[/dim]\n")
