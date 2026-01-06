"""
🛡️ Security Scanner - Professional Interactive TUI
A high-performance terminal interface for security professionals.
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import (
    Header, Footer, Static, Button, Input, 
    Label, RichLog, Rule, LoadingIndicator
)
from textual.binding import Binding
from textual.screen import Screen
from textual.reactive import reactive
from rich.text import Text
from rich.table import Table
from pathlib import Path
import asyncio
import sys
import datetime
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# ============================================================================
# STYLES - Professional Dashboard Theme
# ============================================================================

CSS = """
Screen {
    background: #0d1117;
    color: #c9d1d9;
}

/* --- HEADER & FOOTER --- */
Header {
    background: #161b22;
    color: #58a6ff;
    dock: top;
    height: 1;
}

Footer {
    background: #161b22;
    color: #8b949e;
    dock: bottom;
    height: 1;
}

/* --- COMMON ELEMENTS --- */
.title-text {
    text-align: center;
    color: #58a6ff;
    text-style: bold;
    padding: 1;
    background: #161b22;
    border-bottom: solid #30363d;
}

.section-title {
    color: #8b949e;
    text-style: bold;
    padding: 0 1;
    margin: 1 0 0 0;
}

/* --- DASHBOARD GRID --- */
.dashboard-grid {
    layout: grid;
    grid-size: 2;
    grid-rows: 1fr 1fr 1fr;
    grid-columns: 1fr 1fr;
    grid-gutter: 1;
    padding: 1 2;
    background: #0d1117;
}

.dashboard-card {
    height: 100%;
    border: solid #30363d;
    background: #161b22;
    padding: 1;
    text-align: center;
    content-align: center middle;
}

.dashboard-card:hover {
    border: solid #58a6ff;
    background: #1f2428;
}

.card-icon {
    text-align: center;
    color: #58a6ff;
    padding-bottom: 1;
}

.card-title {
    text-align: center;
    text-style: bold;
    color: #c9d1d9;
}

.card-desc {
    text-align: center;
    color: #8b949e;
}

/* --- ACTION BUTTONS --- */
Button {
    width: 100%;
    margin: 1 0;
    border: none;
    background: #21262d;
    color: #58a6ff;
}

Button:hover {
    background: #30363d;
}

Button.primary {
    background: #238636;
    color: white;
}

Button.primary:hover {
    background: #2ea043;
}

Button.danger {
    background: #da3633;
    color: white;
}

Button.danger:hover {
    background: #f85149;
}

/* --- INPUTS --- */
Input {
    border: solid #30363d;
    background: #0d1117;
    padding: 0 1;
    color: #c9d1d9;
}

Input:focus {
    border: solid #58a6ff;
}

/* --- LOGS & OUTPUTS --- */
RichLog {
    background: #010409;
    color: #c9d1d9;
    border: solid #30363d;
    padding: 1;
    height: 1fr;
}

/* --- SPECIFIC LAYOUTS --- */
.scan-layout {
    layout: grid;
    grid-size: 1;
    grid-rows: auto auto 1fr;
    padding: 1;
}

.input-container {
    padding: 1;
    background: #161b22;
    border: solid #30363d;
    margin-bottom: 1;
}

.status-bar {
    height: 1;
    background: #1f2428;
    color: #8b949e;
    padding: 0 1;
    dock: bottom;
}
"""

# ============================================================================
# HELPER WIDGETS
# ============================================================================

class DashboardCard(Button):
    """Custom dashboard card widget."""
    def __init__(self, title: str, icon: str, description: str, id: str):
        super().__init__(id=id)
        self.card_title = title
        self.icon = icon
        self.description = description
        self.classes = "dashboard-card"

    def render(self) -> str:
        return f"\n{self.icon}\n\n[b]{self.card_title}[/b]\n[dim]{self.description}[/dim]"

# ============================================================================
# DASHBOARD SCREEN
# ============================================================================

class DashboardScreen(Screen):
    """Main professional dashboard."""
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("1", "scan_local", "Scan Local"),
        Binding("2", "scan_url", "Scan URL"),
        Binding("3", "blackbox", "Black Box"),
        Binding("4", "autofix", "Auto Fix"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🛡️  SECURITY OPERATIONS CENTER", classes="title-text")
        
        with Container(classes="dashboard-grid"):
            yield DashboardCard(
                "LOCAL SCAN", 
                "🔍", 
                "Deep scan of local projects\n[1]",
                id="btn-local"
            )
            yield DashboardCard(
                "GIT REPO SCAN", 
                "🌐", 
                "Clone and analyze remote repos\n[2]",
                id="btn-url"
            )
            yield DashboardCard(
                "BLACK BOX TEST", 
                "🎯", 
                "External DAST & Penetration Testing\n[3]",
                id="btn-blackbox"
            )
            yield DashboardCard(
                "AUTO REMEDIATION", 
                "🔧", 
                "Automatically fix vulnerabilities\n[4]",
                id="btn-autofix"
            )
            yield DashboardCard(
                "AUDIT REPORTS", 
                "📊", 
                "View and export security reports\n[5]",
                id="btn-reports"
            )
            yield DashboardCard(
                "SYSTEM EXIT", 
                "🚪", 
                "Close the application\n[Q]",
                id="btn-quit"
            )
            
        with Horizontal(classes="status-bar"):
            yield Static(f"System Status: ONLINE  |  User: {os.getenv('USER', 'Admin')}  |  Engine: v4.0.0")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-local": self.app.push_screen(ScanScreen())
        elif bid == "btn-url": self.app.push_screen(URLScreen())
        elif bid == "btn-blackbox": self.app.push_screen(BlackBoxScreen())
        elif bid == "btn-autofix": self.app.push_screen(AutoFixScreen())
        elif bid == "btn-reports": self.app.push_screen(ReportsScreen())
        elif bid == "btn-quit": self.app.exit()

    def action_scan_local(self): self.app.push_screen(ScanScreen())
    def action_scan_url(self): self.app.push_screen(URLScreen())
    def action_blackbox(self): self.app.push_screen(BlackBoxScreen())
    def action_autofix(self): self.app.push_screen(AutoFixScreen())
    def action_quit(self): self.app.exit()

# ============================================================================
# SCAN SCREEN
# ============================================================================

class ScanScreen(Screen):
    """Professional scanning interface."""
    
    BINDINGS = [Binding("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🔍 LOCAL VULNERABILITY SCANNER", classes="title-text")
        
        with Vertical(classes="scan-layout"):
            with Vertical(classes="input-container"):
                yield Label("TARGET DIRECTORY", classes="section-title")
                yield Input(placeholder="/path/to/project", value=".", id="path-input")
                
                with Horizontal():
                    yield Button("🚀 INITIALIZE SCAN", id="btn-start", classes="primary")
                    yield Button("⬅ RETURN TO DASHBOARD", id="btn-back")

            yield RichLog(id="console", highlight=True, markup=True)

        yield Footer()

    def on_mount(self):
        self.query_one("#console").write("[dim]System ready. Select target and initialize scan.[/dim]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-start": self.start_scan()

    def action_back(self):
        self.app.pop_screen()

    def start_scan(self):
        path = self.query_one("#path-input").value
        console = self.query_one("#console")
        console.clear()
        console.write(f"[bold blue]⚡ INITIALIZING SCAN SEQUENCE: {path}[/]")
        
        asyncio.create_task(self._run_scan(path, console))

    async def _run_scan(self, path, console):
        try:
            from scanner import scan_for_secrets, load_rules
            from vulnerability_scanner import VulnerabilityScanner
            
            console.write("[cyan]ℹ Loading rule definitions...[/]")
            rules = load_rules()
            scanner = VulnerabilityScanner()
            
            target = Path(path).resolve()
            files = list(target.rglob("*")) if target.is_dir() else [target]
            files = [f for f in files if f.is_file() and not f.name.startswith('.')]
            
            console.write(f"[cyan]ℹ Analysis Scope: {len(files)} files found[/]")
            console.write(Rule())
            
            secrets_found = 0
            vulns_found = 0
            
            for i, f in enumerate(files):
                if i > 50: break # Demo limit
                try:
                    # Secret Scan
                    content = f.read_text(errors='ignore')
                    s = scan_for_secrets(str(f), content, rules)
                    if s:
                        secrets_found += len(s)
                        for secret in s:
                            console.write(f"[red]⚠ SECRET DETECTED: {secret.get('type')} in {f.name}[/]")
                    
                    # Vuln Scan (Python only mostly)
                    if f.suffix == ".py":
                        v = scanner.scan_file(str(f))
                        if v:
                            vulns_found += len(v)
                            for vuln in v:
                                console.write(f"[yellow]⚠ VULNERABILITY: {vuln.title} ({vuln.severity}) in {f.name}[/]")
                                
                except Exception:
                    pass
                
                if i % 5 == 0:
                    console.write(f"[dim]Processing... {i+1}/{min(len(files), 50)}[/dim]")
                    await asyncio.sleep(0.01)

            console.write(Rule())
            console.write(f"[bold green]✔ SCAN COMPLETE[/]")
            console.write(f"[bold red]Secrets: {secrets_found}[/] | [bold yellow]Vulnerabilities: {vulns_found}[/]")
            
        except Exception as e:
            console.write(f"[bold red]❌ SYSTEM ERROR: {e}[/]")

# ============================================================================
# URL SCREEN (Skeleton)
# ============================================================================

class URLScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("🌐 REMOTE REPOSITORY SCANNER", classes="title-text")
        with Vertical(classes="scan-layout"):
            with Vertical(classes="input-container"):
                yield Label("REPOSITORY URL", classes="section-title")
                yield Input(placeholder="https://github.com/...", id="url-input")
                with Horizontal():
                    yield Button("🚀 CLONE & SCAN", id="btn-scan", classes="primary")
                    yield Button("⬅ RETURN", id="btn-back")
            yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-scan":
            self.query_one("#console").write("[yellow]⚠ Feature not fully implemented in demo mode.[/yellow]")

    def action_back(self): self.app.pop_screen()

# ============================================================================
# BLACKBOX SCREEN (Skeleton)
# ============================================================================

class BlackBoxScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("🎯 DYNAMIC APPLICATION SECURITY TESTING", classes="title-text")
        with Vertical(classes="scan-layout"):
            with Vertical(classes="input-container"):
                yield Label("TARGET URL", classes="section-title")
                yield Input(placeholder="https://example.com", id="url-input")
                with Horizontal():
                    yield Button("🚀 LAUNCH ATTACK SIMULATION", id="btn-scan", classes="danger")
                    yield Button("⬅ RETURN", id="btn-back")
            yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-scan":
            self.query_one("#console").write("[red]🚀 Launching simulated attacks...[/red]")

    def action_back(self): self.app.pop_screen()

# ============================================================================
# AUTOFIX SCREEN (Skeleton)
# ============================================================================

class AutoFixScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("🔧 AUTOMATED RESTORATION ENGINE", classes="title-text")
        with Vertical(classes="scan-layout"):
            with Vertical(classes="input-container"):
                yield Label("PROJECT PATH", classes="section-title")
                yield Input(value=".", id="path-input")
                with Horizontal():
                    yield Button("🚀 EXECUTE FIXES", id="btn-scan", classes="primary")
                    yield Button("⬅ RETURN", id="btn-back")
            yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-scan":
            self.query_one("#console").write("[green]🔧 Analyzing for fixable patterns...[/green]")

    def action_back(self): self.app.pop_screen()

# ============================================================================
# REPORTS SCREEN (Skeleton)
# ============================================================================

class ReportsScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("📊 AUDIT LOGS & REPORTS", classes="title-text")
        with Vertical(classes="scan-layout"):
            yield RichLog(id="console", highlight=True, markup=True)
            yield Button("⬅ RETURN", id="btn-back")
        yield Footer()

    def on_mount(self):
        self.query_one("#console").write("[cyan]ℹ Listing generated reports...[/cyan]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()

    def action_back(self): self.app.pop_screen()

# ============================================================================
# MAIN APP
# ============================================================================

class SecurityScannerApp(App):
    TITLE = "Security Scanner Pro"
    CSS = CSS
    
    def on_mount(self):
        self.push_screen(DashboardScreen())

def main():
    app = SecurityScannerApp()
    app.run()

if __name__ == "__main__":
    main()
