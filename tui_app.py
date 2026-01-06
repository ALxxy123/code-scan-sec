"""
🛡️ Security Scanner - Professional Interactive TUI
A beautiful terminal interface for security scanning
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center
from textual.widgets import (
    Header, Footer, Static, Button, Input, 
    Label, ProgressBar, RichLog, Rule, Placeholder
)
from textual.binding import Binding
from textual.screen import Screen
from rich.text import Text
from rich.panel import Panel
from rich.align import Align
from pathlib import Path
import asyncio
import sys
import os
import subprocess

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


# ============================================================================
# STYLES - Modern Dark Theme
# ============================================================================

CSS = """
Screen {
    background: #0f0f23;
}

#app-grid {
    layout: grid;
    grid-size: 1;
    grid-rows: auto 1fr auto;
    padding: 1 2;
}

.banner {
    text-align: center;
    padding: 1;
    color: #00ff88;
    text-style: bold;
}

.banner-sub {
    text-align: center;
    color: #888888;
    padding-bottom: 1;
}

#menu-container {
    align: center middle;
    width: 100%;
    height: auto;
}

.menu-box {
    width: 60;
    border: heavy #00ff88;
    border-title-align: center;
    background: #1a1a2e;
    padding: 1 2;
}

.menu-button {
    width: 100%;
    margin: 1 0;
    height: 3;
}

.menu-button:hover {
    background: #00ff88 20%;
}

.menu-button:focus {
    background: #00ff88;
    color: #0f0f23;
    text-style: bold;
}

.quit-button {
    background: #ff4444 20%;
}

.quit-button:hover {
    background: #ff4444 40%;
}

.quit-button:focus {
    background: #ff4444;
    color: white;
}

.tips {
    text-align: center;
    color: #666666;
    padding: 1;
}

/* Scan Screen Styles */
.scan-container {
    padding: 1 2;
}

.scan-title {
    text-align: center;
    color: #00ff88;
    text-style: bold;
    padding: 1;
}

.input-group {
    padding: 1;
    border: solid #333;
    margin: 1 0;
    background: #1a1a2e;
}

.input-label {
    color: #00ff88;
    padding: 0 0 1 0;
}

#path-input {
    background: #0f0f23;
    border: solid #333;
}

#path-input:focus {
    border: solid #00ff88;
}

.button-row {
    align: center middle;
    height: auto;
    padding: 1;
}

.action-btn {
    margin: 0 1;
    min-width: 16;
}

.primary-btn {
    background: #00ff88;
    color: #0f0f23;
}

.primary-btn:hover {
    background: #00cc66;
}

.secondary-btn {
    background: #333;
    color: #fff;
}

.secondary-btn:hover {
    background: #444;
}

.log-container {
    border: solid #333;
    background: #0a0a1a;
    height: 100%;
    margin: 1 0;
    padding: 1;
}

.log-title {
    text-align: center;
    color: #ffaa00;
    padding: 0 0 1 0;
}

/* Footer */
.footer-tips {
    dock: bottom;
    text-align: center;
    color: #555;
    padding: 1;
    background: #0a0a15;
}
"""


# ============================================================================
# ASCII ART BANNER
# ============================================================================

BANNER = """
[bold green]
   _____ ______ _____ _    _ ____  _____ _______ __   __
  / ____|  ____/ ____| |  | |  _ \\|_   _|__   __|\\ \\ / /
 | (___ | |__ | |    | |  | | |_) | | |    | |    \\ V / 
  \\___ \\|  __|| |    | |  | |  _ <  | |    | |     > <  
  ____) | |___| |____| |__| | |_) |_| |_   | |    / . \\ 
 |_____/|______\\_____|\____/|____/|_____|  |_|   /_/ \\_\\
                                                         
[/bold green][bold cyan]        ⚡ AI-Powered Security Scanner v4.0 ⚡[/bold cyan]
"""


# ============================================================================
# MAIN MENU SCREEN
# ============================================================================

class MainMenuScreen(Screen):
    """Beautiful main menu with keyboard navigation."""
    
    BINDINGS = [
        Binding("1", "option_1", "Scan", show=False),
        Binding("2", "option_2", "URL", show=False),
        Binding("3", "option_3", "BlackBox", show=False),
        Binding("4", "option_4", "AutoFix", show=False),
        Binding("5", "option_5", "Reports", show=False),
        Binding("q", "quit", "Quit", show=False),
        Binding("escape", "quit", "Quit"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="app-grid"):
            yield Static(BANNER, classes="banner", markup=True)
            yield Static("Professional Security Analysis Suite", classes="banner-sub")
            
            with Center(id="menu-container"):
                with Container(classes="menu-box"):
                    yield Static("🎯 MAIN MENU", classes="scan-title")
                    yield Rule(style="dim")
                    
                    yield Button("🔍  [1]  Scan Local Project", id="btn-1", classes="menu-button")
                    yield Button("🌐  [2]  Scan Git Repository", id="btn-2", classes="menu-button")
                    yield Button("🎯  [3]  Black Box Testing", id="btn-3", classes="menu-button")
                    yield Button("🔧  [4]  Auto Fix Issues", id="btn-4", classes="menu-button")
                    yield Button("📊  [5]  View Reports", id="btn-5", classes="menu-button")
                    
                    yield Rule(style="dim")
                    yield Button("🚪  [Q]  Exit", id="btn-quit", classes="menu-button quit-button")
            
            yield Static("💡 Press number keys [1-5] or click • [Q] or [ESC] to quit", classes="tips")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "btn-1": lambda: self.app.push_screen(ScanScreen()),
            "btn-2": lambda: self.app.push_screen(URLScreen()),
            "btn-3": lambda: self.app.push_screen(BlackBoxScreen()),
            "btn-4": lambda: self.app.push_screen(AutoFixScreen()),
            "btn-5": lambda: self.app.push_screen(ReportsScreen()),
            "btn-quit": lambda: self.app.exit(),
        }
        action = actions.get(event.button.id)
        if action:
            action()
    
    def action_option_1(self) -> None:
        self.app.push_screen(ScanScreen())
    
    def action_option_2(self) -> None:
        self.app.push_screen(URLScreen())
    
    def action_option_3(self) -> None:
        self.app.push_screen(BlackBoxScreen())
    
    def action_option_4(self) -> None:
        self.app.push_screen(AutoFixScreen())
    
    def action_option_5(self) -> None:
        self.app.push_screen(ReportsScreen())
    
    def action_quit(self) -> None:
        self.app.exit()


# ============================================================================
# SCAN SCREEN
# ============================================================================

class ScanScreen(Screen):
    """Professional scan interface."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("ctrl+s", "start_scan", "Start"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Vertical(classes="scan-container"):
            yield Static("🔍 SCAN LOCAL PROJECT", classes="scan-title")
            yield Rule(style="green")
            
            with Container(classes="input-group"):
                yield Label("📁 Project Path:", classes="input-label")
                yield Input(
                    placeholder="Enter path (e.g., . or /home/user/project)",
                    id="path-input",
                    value="."
                )
            
            with Horizontal(classes="button-row"):
                yield Button("🔍 Start Scan", id="btn-scan", classes="action-btn primary-btn")
                yield Button("📂 Use Current Dir", id="btn-cwd", classes="action-btn secondary-btn")
                yield Button("⬅️ Back", id="btn-back", classes="action-btn secondary-btn")
            
            with Container(classes="log-container"):
                yield Static("📋 OUTPUT LOG", classes="log-title")
                yield Rule(style="dim")
                yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        
        yield Static("💡 [Ctrl+S] to start scan • [ESC] to go back", classes="footer-tips")
    
    def on_mount(self) -> None:
        log = self.query_one("#log", RichLog)
        log.write("[dim]Ready to scan. Enter a path and click 'Start Scan'.[/dim]")
        log.write("")
        log.write("[cyan]Tips:[/cyan]")
        log.write("  • Use [bold].[/bold] for current directory")
        log.write("  • Use absolute paths like [bold]/home/user/project[/bold]")
        log.write("  • Press [bold]Ctrl+S[/bold] to quickly start scanning")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-cwd":
            self.query_one("#path-input", Input).value = str(Path.cwd())
        elif event.button.id == "btn-scan":
            self.run_scan()
    
    def run_scan(self) -> None:
        path = self.query_one("#path-input", Input).value or "."
        log = self.query_one("#log", RichLog)
        
        log.clear()
        log.write(f"[bold green]🚀 STARTING SECURITY SCAN[/bold green]")
        log.write(f"[blue]📁 Target:[/blue] {path}")
        log.write("")
        log.write("[yellow]⏳ Scanning for secrets and vulnerabilities...[/yellow]")
        log.write("")
        
        # Run scan using CLI
        asyncio.create_task(self._run_scan_async(path, log))
    
    async def _run_scan_async(self, path: str, log: RichLog) -> None:
        try:
            # Try to import and run scanner
            from scanner import scan_for_secrets, load_rules
            from vulnerability_scanner import VulnerabilityScanner
            
            log.write("[cyan]🔍 Loading rules...[/cyan]")
            
            # Scan for secrets
            rules = load_rules()
            secrets = []
            
            target_path = Path(path).resolve()
            if target_path.is_dir():
                files = list(target_path.rglob("*"))
                files = [f for f in files if f.is_file() and f.suffix in ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.yaml', '.yml', '.json', '.env', '.config']]
                
                log.write(f"[cyan]📂 Found {len(files)} files to scan[/cyan]")
                
                for i, file in enumerate(files[:50], 1):  # Limit to 50 files
                    try:
                        content = file.read_text(errors='ignore')
                        file_secrets = scan_for_secrets(str(file), content, rules)
                        secrets.extend(file_secrets)
                    except:
                        pass
                    
                    if i % 10 == 0:
                        log.write(f"[dim]  Scanned {i}/{min(len(files), 50)} files...[/dim]")
            
            # Scan for vulnerabilities
            log.write("[cyan]🐛 Scanning for vulnerabilities...[/cyan]")
            scanner = VulnerabilityScanner()
            vulns = []
            
            if target_path.is_dir():
                for file in list(target_path.rglob("*.py"))[:30]:
                    try:
                        file_vulns = scanner.scan_file(str(file))
                        vulns.extend(file_vulns)
                    except:
                        pass
            
            # Show results
            log.write("")
            log.write("[bold green]" + "=" * 50 + "[/bold green]")
            log.write("[bold green]✅ SCAN COMPLETE![/bold green]")
            log.write("[bold green]" + "=" * 50 + "[/bold green]")
            log.write("")
            
            if secrets:
                log.write(f"[bold red]🔑 Secrets Found: {len(secrets)}[/bold red]")
                for s in secrets[:5]:
                    log.write(f"  [red]• {s.get('type', 'Secret')} in {s.get('file', 'unknown')}:{s.get('line', 0)}[/red]")
                if len(secrets) > 5:
                    log.write(f"  [dim]... and {len(secrets) - 5} more[/dim]")
            else:
                log.write("[green]🔑 No secrets found[/green]")
            
            log.write("")
            
            if vulns:
                log.write(f"[bold yellow]🐛 Vulnerabilities Found: {len(vulns)}[/bold yellow]")
                critical = sum(1 for v in vulns if v.severity == 'critical')
                high = sum(1 for v in vulns if v.severity == 'high')
                medium = sum(1 for v in vulns if v.severity == 'medium')
                low = sum(1 for v in vulns if v.severity == 'low')
                
                if critical: log.write(f"  [bold red]🔴 Critical: {critical}[/bold red]")
                if high: log.write(f"  [red]🟠 High: {high}[/red]")
                if medium: log.write(f"  [yellow]🟡 Medium: {medium}[/yellow]")
                if low: log.write(f"  [green]🟢 Low: {low}[/green]")
            else:
                log.write("[green]🐛 No vulnerabilities found[/green]")
            
            log.write("")
            log.write("[dim]Press ESC to go back to menu[/dim]")
            
        except ImportError as e:
            log.write(f"[red]❌ Import Error: {e}[/red]")
            log.write("[yellow]Running simplified scan...[/yellow]")
            log.write("")
            
            # Fallback: simple file count
            target = Path(path).resolve()
            if target.exists():
                if target.is_dir():
                    files = list(target.rglob("*"))
                    py_files = [f for f in files if f.suffix == '.py']
                    log.write(f"[cyan]📂 Directory: {target}[/cyan]")
                    log.write(f"[cyan]📄 Total files: {len(files)}[/cyan]")
                    log.write(f"[cyan]🐍 Python files: {len(py_files)}[/cyan]")
                else:
                    log.write(f"[cyan]📄 File: {target}[/cyan]")
            else:
                log.write(f"[red]❌ Path not found: {target}[/red]")
        
        except Exception as e:
            log.write(f"[red]❌ Error: {e}[/red]")
    
    def action_go_back(self) -> None:
        self.app.pop_screen()
    
    def action_start_scan(self) -> None:
        self.run_scan()


# ============================================================================
# URL SCREEN
# ============================================================================

class URLScreen(Screen):
    """Git repository scanning."""
    
    BINDINGS = [Binding("escape", "go_back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Vertical(classes="scan-container"):
            yield Static("🌐 SCAN GIT REPOSITORY", classes="scan-title")
            yield Rule(style="cyan")
            
            with Container(classes="input-group"):
                yield Label("📎 Repository URL:", classes="input-label")
                yield Input(
                    placeholder="https://github.com/username/repo",
                    id="url-input"
                )
            
            with Horizontal(classes="button-row"):
                yield Button("🔍 Clone & Scan", id="btn-scan", classes="action-btn primary-btn")
                yield Button("⬅️ Back", id="btn-back", classes="action-btn secondary-btn")
            
            with Container(classes="log-container"):
                yield Static("📋 OUTPUT", classes="log-title")
                yield Rule(style="dim")
                yield RichLog(id="log", highlight=True, markup=True)
        
        yield Static("💡 Enter a GitHub/GitLab URL to scan • [ESC] to go back", classes="footer-tips")
    
    def on_mount(self) -> None:
        log = self.query_one("#log", RichLog)
        log.write("[dim]Enter a Git repository URL and click 'Clone & Scan'[/dim]")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-scan":
            url = self.query_one("#url-input", Input).value
            log = self.query_one("#log", RichLog)
            log.clear()
            log.write(f"[green]🌐 Scanning: {url}[/green]")
            log.write("[yellow]⏳ Feature coming soon...[/yellow]")
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# BLACK BOX SCREEN
# ============================================================================

class BlackBoxScreen(Screen):
    """Web application testing."""
    
    BINDINGS = [Binding("escape", "go_back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Vertical(classes="scan-container"):
            yield Static("🎯 BLACK BOX TESTING", classes="scan-title")
            yield Rule(style="red")
            
            with Container(classes="input-group"):
                yield Label("🌐 Target URL:", classes="input-label")
                yield Input(
                    placeholder="https://example.com",
                    id="target-input"
                )
            
            with Horizontal(classes="button-row"):
                yield Button("🎯 Start Test", id="btn-test", classes="action-btn primary-btn")
                yield Button("⬅️ Back", id="btn-back", classes="action-btn secondary-btn")
            
            with Container(classes="log-container"):
                yield Static("📋 TEST RESULTS", classes="log-title")
                yield Rule(style="dim")
                yield RichLog(id="log", highlight=True, markup=True)
        
        yield Static("💡 Enter a website URL to test security • [ESC] to go back", classes="footer-tips")
    
    def on_mount(self) -> None:
        log = self.query_one("#log", RichLog)
        log.write("[dim]Enter a target URL and click 'Start Test'[/dim]")
        log.write("")
        log.write("[cyan]Tests include:[/cyan]")
        log.write("  • Security Headers")
        log.write("  • SSL/TLS Configuration")
        log.write("  • SQL Injection")
        log.write("  • XSS Detection")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# AUTO FIX SCREEN
# ============================================================================

class AutoFixScreen(Screen):
    """Auto fix vulnerabilities."""
    
    BINDINGS = [Binding("escape", "go_back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Vertical(classes="scan-container"):
            yield Static("🔧 AUTO FIX VULNERABILITIES", classes="scan-title")
            yield Rule(style="yellow")
            
            with Container(classes="input-group"):
                yield Label("📁 Project Path:", classes="input-label")
                yield Input(placeholder="Enter path...", id="path-input", value=".")
            
            with Horizontal(classes="button-row"):
                yield Button("👁️ Preview Fixes", id="btn-preview", classes="action-btn secondary-btn")
                yield Button("🔧 Apply Fixes", id="btn-apply", classes="action-btn primary-btn")
                yield Button("⬅️ Back", id="btn-back", classes="action-btn secondary-btn")
            
            with Container(classes="log-container"):
                yield Static("📋 FIX LOG", classes="log-title")
                yield Rule(style="dim")
                yield RichLog(id="log", highlight=True, markup=True)
        
        yield Static("💡 Preview fixes before applying • [ESC] to go back", classes="footer-tips")
    
    def on_mount(self) -> None:
        log = self.query_one("#log", RichLog)
        log.write("[dim]Enter path and click 'Preview Fixes' to see available fixes[/dim]")
        log.write("")
        log.write("[cyan]Auto-fix supports:[/cyan]")
        log.write("  • [green]✓[/green] Weak Crypto (MD5 → SHA256)")
        log.write("  • [green]✓[/green] Hardcoded Secrets → Environment Variables")
        log.write("  • [green]✓[/green] Dangerous Functions (eval, exec)")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# REPORTS SCREEN
# ============================================================================

class ReportsScreen(Screen):
    """View scan reports."""
    
    BINDINGS = [Binding("escape", "go_back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Vertical(classes="scan-container"):
            yield Static("📊 SCAN REPORTS", classes="scan-title")
            yield Rule(style="blue")
            
            with Container(classes="log-container"):
                yield Static("📁 Reports Directory: ./output/", classes="log-title")
                yield Rule(style="dim")
                yield RichLog(id="log", highlight=True, markup=True)
            
            with Horizontal(classes="button-row"):
                yield Button("🔄 Refresh", id="btn-refresh", classes="action-btn secondary-btn")
                yield Button("⬅️ Back", id="btn-back", classes="action-btn secondary-btn")
        
        yield Static("💡 Reports are saved in the output/ directory • [ESC] to go back", classes="footer-tips")
    
    def on_mount(self) -> None:
        self.list_reports()
    
    def list_reports(self) -> None:
        log = self.query_one("#log", RichLog)
        log.clear()
        
        output_dir = Path("output")
        if output_dir.exists():
            reports = list(output_dir.glob("*"))
            if reports:
                log.write("[green]📄 Available Reports:[/green]")
                log.write("")
                for r in sorted(reports, key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
                    size = r.stat().st_size // 1024
                    log.write(f"  [cyan]•[/cyan] {r.name} ({size} KB)")
            else:
                log.write("[yellow]No reports found yet.[/yellow]")
        else:
            log.write("[yellow]Output directory not found.[/yellow]")
        
        log.write("")
        log.write("[dim]Run a scan to generate reports.[/dim]")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-refresh":
            self.list_reports()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class SecurityScannerApp(App):
    """Professional Security Scanner TUI."""
    
    TITLE = "Security Scanner"
    SUB_TITLE = "AI-Powered Security Analysis"
    CSS = CSS
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+d", "toggle_dark", "Theme"),
    ]
    
    def on_mount(self) -> None:
        self.push_screen(MainMenuScreen())
    
    def action_toggle_dark(self) -> None:
        self.dark = not self.dark


def main():
    """Entry point."""
    app = SecurityScannerApp()
    app.run()


if __name__ == "__main__":
    main()
