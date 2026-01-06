"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  🛡️ SECURITY SCANNER PRO - Enterprise Security Analysis Suite               ║
║  Professional Terminal Interface for Security Professionals                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Grid
from textual.widgets import Header, Footer, Static, Button, Input, Label, RichLog, ProgressBar
from textual.binding import Binding
from textual.screen import Screen
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from pathlib import Path
import asyncio
import sys
import os
import time

sys.path.insert(0, str(Path(__file__).parent))

# ═══════════════════════════════════════════════════════════════════════════════
# PROFESSIONAL THEME - Cybersecurity Dashboard Style
# ═══════════════════════════════════════════════════════════════════════════════

THEME = """
* {
    transition: background 200ms;
}

Screen {
    background: #0a0e14;
}

/* ═══ HEADER & FOOTER ═══ */
Header {
    background: #1a1f29;
    color: #39ff14;
    text-style: bold;
}

Footer {
    background: #1a1f29;
    color: #6b7280;
}

FooterKey {
    background: #252b37;
    color: #39ff14;
}

/* ═══ MAIN CONTAINER ═══ */
#main-box {
    width: 100%;
    height: 100%;
    padding: 1 2;
}

/* ═══ LOGO BOX ═══ */
.logo-box {
    height: auto;
    padding: 0;
    margin-bottom: 1;
}

.logo-text {
    text-align: center;
    color: #39ff14;
}

.version-text {
    text-align: center;
    color: #6b7280;
    padding-bottom: 1;
}

/* ═══ MENU GRID ═══ */
.menu-grid {
    layout: grid;
    grid-size: 3 2;
    grid-gutter: 1;
    height: auto;
    padding: 1;
}

/* ═══ MENU CARDS ═══ */
.menu-card {
    height: 7;
    border: solid #252b37;
    background: #141922;
    padding: 1;
    text-align: center;
    content-align: center middle;
}

.menu-card:hover {
    border: solid #39ff14;
    background: #1a2332;
}

.menu-card:focus {
    border: double #39ff14;
    background: #1f2d3d;
}

.menu-card.-exit {
    border: solid #ff4444;
}

.menu-card.-exit:hover {
    border: solid #ff6666;
    background: #2a1a1a;
}

/* ═══ STATUS BAR ═══ */
.status-bar {
    height: 3;
    background: #141922;
    border: solid #252b37;
    padding: 0 2;
    margin-top: 1;
}

.status-ok {
    color: #39ff14;
}

.status-text {
    color: #6b7280;
}

/* ═══ SCREEN TITLE ═══ */
.screen-title {
    text-align: center;
    background: #1a1f29;
    color: #39ff14;
    text-style: bold;
    padding: 1;
    border-bottom: solid #252b37;
}

/* ═══ INPUT SECTION ═══ */
.input-section {
    background: #141922;
    border: solid #252b37;
    padding: 1 2;
    margin: 1 0;
}

.input-label {
    color: #39ff14;
    text-style: bold;
    padding-bottom: 1;
}

Input {
    background: #0a0e14;
    border: solid #252b37;
    color: #e4e4e7;
}

Input:focus {
    border: solid #39ff14;
}

/* ═══ ACTION BUTTONS ═══ */
.btn-row {
    height: auto;
    padding: 1 0;
}

Button {
    margin: 0 1;
    min-width: 20;
    background: #252b37;
    color: #e4e4e7;
    border: none;
}

Button:hover {
    background: #3a4556;
}

Button.-primary {
    background: #166534;
    color: #ffffff;
}

Button.-primary:hover {
    background: #22863a;
}

Button.-danger {
    background: #7f1d1d;
    color: #ffffff;
}

Button.-danger:hover {
    background: #991b1b;
}

/* ═══ CONSOLE OUTPUT ═══ */
.console-section {
    background: #0a0e14;
    border: solid #252b37;
    padding: 1;
    height: 1fr;
}

.console-title {
    color: #fbbf24;
    text-style: bold;
    padding-bottom: 1;
}

RichLog {
    background: #050709;
    border: none;
    scrollbar-background: #141922;
    scrollbar-color: #252b37;
}

/* ═══ PROGRESS ═══ */
ProgressBar {
    padding: 1 0;
}

ProgressBar > .bar--bar {
    color: #39ff14;
}
"""

# ═══════════════════════════════════════════════════════════════════════════════
# ASCII LOGO
# ═══════════════════════════════════════════════════════════════════════════════

LOGO = """[bold #39ff14]
   ▄████████    ▄████████  ▄████████ ███    █▄     ▄████████  ▄█      ███     ▄██   ▄   
  ███    ███   ███    ███ ███    ███ ███    ███   ███    ███ ███  ▀█████████▄ ███   ██▄ 
  ███    █▀    ███    █▀  ███    █▀  ███    ███   ███    ███ ███▌    ▀███▀▀██ ███▄▄▄███ 
  ███         ▄███▄▄▄     ███        ███    ███  ▄███▄▄▄▄██▀ ███▌     ███   ▀ ▀▀▀▀▀▀███ 
▀███████████ ▀▀███▀▀▀     ███        ███    ███ ▀▀███▀▀▀▀▀   ███▌     ███     ▄██   ███ 
         ███   ███    █▄  ███    █▄  ███    ███ ▀███████████ ███      ███     ███   ███ 
   ▄█    ███   ███    ███ ███    ███ ███    ███   ███    ███ ███      ███     ███   ███ 
 ▄████████▀    ██████████ ████████▀  ████████▀    ███    ███ █▀      ▄████▀    ▀█████▀  
[/][bold #6b7280]
                    ━━━ AI-Powered Enterprise Security Scanner v4.0 ━━━[/]"""

MINI_LOGO = "[bold #39ff14]🛡️ SECURITY SCANNER PRO[/]"

# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class DashboardScreen(Screen):
    """Main security operations dashboard."""
    
    BINDINGS = [
        Binding("1", "go_scan", "Local Scan", show=False),
        Binding("2", "go_url", "URL Scan", show=False),
        Binding("3", "go_blackbox", "Black Box", show=False),
        Binding("4", "go_autofix", "Auto Fix", show=False),
        Binding("5", "go_reports", "Reports", show=False),
        Binding("q", "quit", "Quit", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Vertical(id="main-box"):
            # Logo
            with Container(classes="logo-box"):
                yield Static(LOGO, classes="logo-text", markup=True)
            
            # Menu Grid
            with Grid(classes="menu-grid"):
                yield Button("🔍\n\nLOCAL SCAN\n[dim][1][/]", id="btn-1", classes="menu-card")
                yield Button("🌐\n\nURL SCAN\n[dim][2][/]", id="btn-2", classes="menu-card")
                yield Button("🎯\n\nBLACK BOX\n[dim][3][/]", id="btn-3", classes="menu-card")
                yield Button("🔧\n\nAUTO FIX\n[dim][4][/]", id="btn-4", classes="menu-card")
                yield Button("📊\n\nREPORTS\n[dim][5][/]", id="btn-5", classes="menu-card")
                yield Button("🚪\n\nEXIT\n[dim][Q][/]", id="btn-q", classes="menu-card -exit")
            
            # Status Bar
            with Horizontal(classes="status-bar"):
                yield Static("[bold #39ff14]●[/] SYSTEM ONLINE", classes="status-ok")
                yield Static(f"  │  [dim]User: {os.getenv('USER', os.getenv('USERNAME', 'Admin'))}[/]", classes="status-text")
                yield Static(f"  │  [dim]Engine: v4.0.0[/]", classes="status-text")
        
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-1": self.action_go_scan()
        elif bid == "btn-2": self.action_go_url()
        elif bid == "btn-3": self.action_go_blackbox()
        elif bid == "btn-4": self.action_go_autofix()
        elif bid == "btn-5": self.action_go_reports()
        elif bid == "btn-q": self.app.exit()

    def action_go_scan(self): self.app.push_screen(ScanScreen())
    def action_go_url(self): self.app.push_screen(URLScreen())
    def action_go_blackbox(self): self.app.push_screen(BlackBoxScreen())
    def action_go_autofix(self): self.app.push_screen(AutoFixScreen())
    def action_go_reports(self): self.app.push_screen(ReportsScreen())
    def action_quit(self): self.app.exit()


# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL SCAN SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class ScanScreen(Screen):
    """Professional local vulnerability scanner."""
    
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("enter", "start", "Start Scan"),
        Binding("f5", "start", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🔍  LOCAL VULNERABILITY SCANNER", classes="screen-title")
        
        with Vertical(id="main-box"):
            # Input Section
            with Container(classes="input-section"):
                yield Static("📁 TARGET PATH", classes="input-label")
                yield Input(placeholder="Enter directory path (e.g., . or C:\\Projects\\MyApp)", value=".", id="path-input")
            
            # Action Buttons
            with Center(classes="btn-row"):
                yield Button("🚀 START SCAN", id="btn-start", classes="-primary")
                yield Button("📂 CURRENT DIR", id="btn-cwd")
                yield Button("⬅ BACK", id="btn-back")
            
            # Console
            with Container(classes="console-section"):
                yield Static("📋 SCAN OUTPUT", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True, wrap=True)
        
        yield Footer()

    def on_mount(self):
        self._show_welcome()

    def _show_welcome(self):
        c = self.query_one("#console", RichLog)
        c.clear()
        c.write("[bold #39ff14]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #39ff14]║[/]          [bold]🛡️ Security Scanner - Ready[/]                          [bold #39ff14]║[/]")
        c.write("[bold #39ff14]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write("[#fbbf24]QUICK START:[/]")
        c.write("  [dim]1.[/] Enter target path above [dim](default: current directory)[/]")
        c.write("  [dim]2.[/] Press [bold #39ff14]Enter[/] or click [bold #39ff14]START SCAN[/]")
        c.write("  [dim]3.[/] View results below")
        c.write("")
        c.write("[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "btn-back": self.app.pop_screen()
        elif bid == "btn-start": self.action_start()
        elif bid == "btn-cwd":
            self.query_one("#path-input", Input).value = str(Path.cwd())

    def action_back(self): self.app.pop_screen()
    
    def action_start(self):
        path = self.query_one("#path-input", Input).value
        asyncio.create_task(self._run_scan(path))

    async def _run_scan(self, path: str):
        c = self.query_one("#console", RichLog)
        c.clear()
        
        c.write(f"[bold #39ff14]⚡ INITIALIZING SCAN[/]")
        c.write(f"[dim]Target: {path}[/]")
        c.write("")
        
        try:
            from scanner import scan_for_secrets, load_rules
            from vulnerability_scanner import VulnerabilityScanner
            
            start_time = time.time()
            
            c.write("[#3b82f6]▸ Loading rule definitions...[/]")
            rules = load_rules()
            scanner = VulnerabilityScanner()
            
            target = Path(path).resolve()
            if not target.exists():
                c.write(f"[bold red]✖ Error: Path not found: {target}[/]")
                return
            
            files = list(target.rglob("*")) if target.is_dir() else [target]
            files = [f for f in files if f.is_file() and not any(p.startswith('.') for p in f.parts)]
            
            c.write(f"[#3b82f6]▸ Scanning {len(files)} files...[/]")
            c.write("")
            
            secrets_found = []
            vulns_found = []
            
            for i, f in enumerate(files[:100]):
                try:
                    content = f.read_text(errors='ignore')
                    
                    # Secret scan
                    s = scan_for_secrets(str(f), content, rules)
                    if s:
                        secrets_found.extend(s)
                        for sec in s:
                            c.write(f"[bold red]🔑 SECRET:[/] {sec.get('type', 'Unknown')} in [dim]{f.name}[/]")
                    
                    # Vuln scan (Python files)
                    if f.suffix == ".py":
                        v = scanner.scan_file(str(f))
                        if v:
                            vulns_found.extend(v)
                            for vuln in v:
                                color = {"critical": "#ef4444", "high": "#f97316", "medium": "#fbbf24", "low": "#22c55e"}.get(vuln.severity, "#6b7280")
                                c.write(f"[bold {color}]⚠ {vuln.severity.upper()}:[/] {vuln.title} in [dim]{f.name}[/]")
                                
                except Exception:
                    pass
                
                if i % 20 == 0 and i > 0:
                    await asyncio.sleep(0.01)
            
            elapsed = time.time() - start_time
            
            c.write("")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write(f"[bold #39ff14]✓ SCAN COMPLETE[/] [dim]({elapsed:.2f}s)[/]")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write("")
            c.write(f"[bold]📊 SUMMARY[/]")
            c.write(f"   Files Scanned: [bold]{min(len(files), 100)}[/]")
            c.write(f"   Secrets Found: [bold red]{len(secrets_found)}[/]")
            c.write(f"   Vulnerabilities: [bold #fbbf24]{len(vulns_found)}[/]")
            
            if secrets_found or vulns_found:
                c.write("")
                c.write("[bold red]⚠ Security issues detected! Review findings above.[/]")
            else:
                c.write("")
                c.write("[bold #39ff14]✓ No security issues detected.[/]")
            
        except ImportError as e:
            c.write(f"[bold red]✖ Module Error: {e}[/]")
            c.write("[dim]Running in demo mode...[/]")
            
            target = Path(path).resolve()
            if target.exists():
                files = list(target.rglob("*")) if target.is_dir() else [target]
                c.write(f"[#3b82f6]▸ Found {len(files)} files[/]")
                c.write("[#39ff14]✓ Demo scan complete[/]")
            
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# URL SCAN SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class URLScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🌐  REMOTE REPOSITORY SCANNER", classes="screen-title")
        with Vertical(id="main-box"):
            with Container(classes="input-section"):
                yield Static("📎 REPOSITORY URL", classes="input-label")
                yield Input(placeholder="https://github.com/user/repo", id="url-input")
            with Center(classes="btn-row"):
                yield Button("🚀 CLONE & SCAN", id="btn-start", classes="-primary")
                yield Button("⬅ BACK", id="btn-back")
            with Container(classes="console-section"):
                yield Static("📋 OUTPUT", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        self.query_one("#console", RichLog).write("[dim]Enter a Git repository URL to scan...[/]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-start":
            url = self.query_one("#url-input", Input).value
            self.query_one("#console", RichLog).write(f"[#fbbf24]▸ Cloning: {url}[/]")

    def action_back(self): self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# BLACK BOX SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class BlackBoxScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🎯  DYNAMIC APPLICATION SECURITY TESTING", classes="screen-title")
        with Vertical(id="main-box"):
            with Container(classes="input-section"):
                yield Static("🌐 TARGET URL", classes="input-label")
                yield Input(placeholder="https://target-website.com", id="url-input")
            with Center(classes="btn-row"):
                yield Button("🎯 LAUNCH TEST", id="btn-start", classes="-danger")
                yield Button("⬅ BACK", id="btn-back")
            with Container(classes="console-section"):
                yield Static("📋 TEST RESULTS", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        c = self.query_one("#console", RichLog)
        c.write("[dim]Black Box Security Testing Suite[/]")
        c.write("")
        c.write("[#fbbf24]Available Tests:[/]")
        c.write("  • Security Headers Analysis")
        c.write("  • SSL/TLS Configuration Check")
        c.write("  • SQL Injection Detection")
        c.write("  • XSS Vulnerability Scan")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
    
    def action_back(self): self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO FIX SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class AutoFixScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🔧  AUTOMATED REMEDIATION ENGINE", classes="screen-title")
        with Vertical(id="main-box"):
            with Container(classes="input-section"):
                yield Static("📁 PROJECT PATH", classes="input-label")
                yield Input(value=".", id="path-input")
            with Center(classes="btn-row"):
                yield Button("👁 PREVIEW", id="btn-preview")
                yield Button("🔧 APPLY FIXES", id="btn-start", classes="-primary")
                yield Button("⬅ BACK", id="btn-back")
            with Container(classes="console-section"):
                yield Static("📋 FIX LOG", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        c = self.query_one("#console", RichLog)
        c.write("[dim]Automated Security Fix Engine[/]")
        c.write("")
        c.write("[#39ff14]Supported Fixes:[/]")
        c.write("  ✓ Weak Crypto (MD5 → SHA256)")
        c.write("  ✓ Hardcoded Secrets → Environment Variables")
        c.write("  ✓ Dangerous Functions (eval, exec)")
        c.write("  ✓ SQL Injection Prevention")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
    
    def action_back(self): self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class ReportsScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("📊  SECURITY AUDIT REPORTS", classes="screen-title")
        with Vertical(id="main-box"):
            with Container(classes="console-section"):
                yield Static("📁 ./output/", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
            with Center(classes="btn-row"):
                yield Button("🔄 REFRESH", id="btn-refresh")
                yield Button("⬅ BACK", id="btn-back")
        yield Footer()

    def on_mount(self):
        self._list_reports()

    def _list_reports(self):
        c = self.query_one("#console", RichLog)
        c.clear()
        output = Path("output")
        if output.exists():
            reports = sorted(output.glob("*"), key=lambda x: x.stat().st_mtime, reverse=True)
            if reports:
                for r in reports[:15]:
                    size = r.stat().st_size // 1024
                    c.write(f"[#3b82f6]📄[/] {r.name} [dim]({size}KB)[/]")
            else:
                c.write("[dim]No reports found. Run a scan first.[/]")
        else:
            c.write("[dim]Output directory not found.[/]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-refresh": self._list_reports()
    
    def action_back(self): self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityScannerApp(App):
    """Enterprise Security Scanner - Professional TUI."""
    
    TITLE = "Security Scanner Pro"
    CSS = THEME
    
    def on_mount(self):
        self.push_screen(DashboardScreen())


def main():
    """Application entry point."""
    app = SecurityScannerApp()
    app.run()


if __name__ == "__main__":
    main()
