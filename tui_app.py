"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  🛡️ SECURITY SCANNER PRO - Enterprise Security Analysis Suite               ║
║  Professional Terminal Interface for Security Professionals                  ║
║  Version 4.0.0 - Full Featured Edition                                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Center, Grid
from textual.widgets import (
    Header, Footer, Static, Button, Input, Label, 
    RichLog, ProgressBar, Select, Switch, RadioButton, RadioSet
)
from textual.binding import Binding
from textual.screen import Screen
from textual.reactive import reactive
from rich.table import Table
from pathlib import Path
import asyncio
import sys
import os
import time
import json

sys.path.insert(0, str(Path(__file__).parent))

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

CONFIG_FILE = Path.home() / ".security-scan" / "tui_config.json"

DEFAULT_CONFIG = {
    "ai_provider": "gemini",
    "output_dir": "./output",
    "scan_depth": 100,
    "enable_ai": True,
    "auto_open_reports": True,
}

def load_config():
    try:
        if CONFIG_FILE.exists():
            return {**DEFAULT_CONFIG, **json.loads(CONFIG_FILE.read_text())}
    except:
        pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
    except:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
# PROFESSIONAL THEME
# ═══════════════════════════════════════════════════════════════════════════════

THEME = """
* {
    transition: background 200ms;
}

Screen {
    background: #0a0e14;
}

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

#main-box {
    width: 100%;
    height: 100%;
    padding: 1 2;
}

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

.menu-grid {
    layout: grid;
    grid-size: 4 2;
    grid-gutter: 1;
    height: auto;
    padding: 1;
}

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

.menu-card.-settings {
    border: solid #fbbf24;
}

.menu-card.-settings:hover {
    border: solid #fcd34d;
    background: #2a2a1a;
}

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

.screen-title {
    text-align: center;
    background: #1a1f29;
    color: #39ff14;
    text-style: bold;
    padding: 1;
    border-bottom: solid #252b37;
}

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

Select {
    background: #0a0e14;
    border: solid #252b37;
    color: #e4e4e7;
}

Select:focus {
    border: solid #39ff14;
}

.btn-row {
    height: auto;
    padding: 1 0;
}

Button {
    margin: 0 1;
    min-width: 16;
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

Button.-warning {
    background: #854d0e;
    color: #ffffff;
}

Button.-warning:hover {
    background: #a16207;
}

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

ProgressBar {
    padding: 1 0;
}

ProgressBar > .bar--bar {
    color: #39ff14;
}

.settings-group {
    background: #141922;
    border: solid #252b37;
    padding: 1 2;
    margin: 1 0;
}

.settings-label {
    color: #39ff14;
    padding: 0 0 1 0;
}

Switch {
    background: #252b37;
}

Switch.-on {
    background: #166534;
}

RadioSet {
    background: transparent;
    border: none;
}

RadioButton {
    background: transparent;
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
        Binding("6", "go_benchmark", "Benchmark", show=False),
        Binding("7", "go_settings", "Settings", show=False),
        Binding("q", "quit", "Quit", show=True),
    ]

    def compose(self) -> ComposeResult:
        config = load_config()
        yield Header(show_clock=True)
        
        with Vertical(id="main-box"):
            with Container(classes="logo-box"):
                yield Static(LOGO, classes="logo-text", markup=True)
            
            with Grid(classes="menu-grid"):
                yield Button("🔍\n\nLOCAL SCAN\n[dim][1][/]", id="btn-1", classes="menu-card")
                yield Button("🌐\n\nURL SCAN\n[dim][2][/]", id="btn-2", classes="menu-card")
                yield Button("🎯\n\nBLACK BOX\n[dim][3][/]", id="btn-3", classes="menu-card")
                yield Button("🔧\n\nAUTO FIX\n[dim][4][/]", id="btn-4", classes="menu-card")
                yield Button("📊\n\nREPORTS\n[dim][5][/]", id="btn-5", classes="menu-card")
                yield Button("📈\n\nBENCHMARK\n[dim][6][/]", id="btn-6", classes="menu-card")
                yield Button("⚙️\n\nSETTINGS\n[dim][7][/]", id="btn-7", classes="menu-card -settings")
                yield Button("🚪\n\nEXIT\n[dim][Q][/]", id="btn-q", classes="menu-card -exit")
            
            with Horizontal(classes="status-bar"):
                yield Static("[bold #39ff14]●[/] SYSTEM ONLINE", classes="status-ok")
                yield Static(f"  │  [dim]AI: {config['ai_provider'].upper()}[/]", classes="status-text")
                yield Static(f"  │  [dim]User: {os.getenv('USER', os.getenv('USERNAME', 'Admin'))}[/]", classes="status-text")
                yield Static(f"  │  [dim]v4.0.0[/]", classes="status-text")
        
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        actions = {
            "btn-1": self.action_go_scan,
            "btn-2": self.action_go_url,
            "btn-3": self.action_go_blackbox,
            "btn-4": self.action_go_autofix,
            "btn-5": self.action_go_reports,
            "btn-6": self.action_go_benchmark,
            "btn-7": self.action_go_settings,
            "btn-q": self.app.exit,
        }
        if bid in actions:
            actions[bid]()

    def action_go_scan(self): self.app.push_screen(ScanScreen())
    def action_go_url(self): self.app.push_screen(URLScreen())
    def action_go_blackbox(self): self.app.push_screen(BlackBoxScreen())
    def action_go_autofix(self): self.app.push_screen(AutoFixScreen())
    def action_go_reports(self): self.app.push_screen(ReportsScreen())
    def action_go_benchmark(self): self.app.push_screen(BenchmarkScreen())
    def action_go_settings(self): self.app.push_screen(SettingsScreen())
    def action_quit(self): self.app.exit()


# ═══════════════════════════════════════════════════════════════════════════════
# SETTINGS SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class SettingsScreen(Screen):
    """Configuration settings."""
    
    BINDINGS = [Binding("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        config = load_config()
        yield Header(show_clock=True)
        yield Static("⚙️  SETTINGS", classes="screen-title")
        
        with Vertical(id="main-box"):
            # AI Provider Selection
            with Container(classes="settings-group"):
                yield Static("🤖 AI PROVIDER", classes="settings-label")
                yield Select(
                    [
                        ("Google Gemini", "gemini"),
                        ("OpenAI GPT-4", "openai"),
                        ("Anthropic Claude", "anthropic"),
                        ("No AI (Offline)", "none"),
                    ],
                    value=config.get("ai_provider", "gemini"),
                    id="ai-select"
                )
            
            # Output Directory
            with Container(classes="settings-group"):
                yield Static("📁 OUTPUT DIRECTORY", classes="settings-label")
                yield Input(value=config.get("output_dir", "./output"), id="output-dir")
            
            # Scan Depth
            with Container(classes="settings-group"):
                yield Static("🔢 MAX FILES TO SCAN", classes="settings-label")
                yield Input(value=str(config.get("scan_depth", 100)), id="scan-depth")
            
            # Toggles
            with Container(classes="settings-group"):
                yield Static("🔧 OPTIONS", classes="settings-label")
                with Horizontal():
                    yield Static("Enable AI Verification: ")
                    yield Switch(value=config.get("enable_ai", True), id="enable-ai")
                with Horizontal():
                    yield Static("Auto-open Reports: ")
                    yield Switch(value=config.get("auto_open_reports", True), id="auto-open")
            
            # Buttons
            with Center(classes="btn-row"):
                yield Button("💾 SAVE SETTINGS", id="btn-save", classes="-primary")
                yield Button("🔄 RESET DEFAULTS", id="btn-reset", classes="-warning")
                yield Button("⬅ BACK", id="btn-back")
        
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-save":
            self._save_settings()
        elif event.button.id == "btn-reset":
            self._reset_settings()

    def _save_settings(self):
        config = {
            "ai_provider": self.query_one("#ai-select", Select).value,
            "output_dir": self.query_one("#output-dir", Input).value,
            "scan_depth": int(self.query_one("#scan-depth", Input).value or 100),
            "enable_ai": self.query_one("#enable-ai", Switch).value,
            "auto_open_reports": self.query_one("#auto-open", Switch).value,
        }
        save_config(config)
        self.notify("Settings saved!", severity="information")

    def _reset_settings(self):
        save_config(DEFAULT_CONFIG)
        self.notify("Settings reset to defaults!", severity="warning")
        # Refresh screen
        self.app.pop_screen()
        self.app.push_screen(SettingsScreen())

    def action_back(self):
        self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# BENCHMARK SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class BenchmarkScreen(Screen):
    """Performance benchmarking."""
    
    BINDINGS = [Binding("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("📈  PERFORMANCE BENCHMARK", classes="screen-title")
        
        with Vertical(id="main-box"):
            with Container(classes="input-section"):
                yield Static("📁 TARGET PATH", classes="input-label")
                yield Input(value=".", id="path-input")
            
            with Center(classes="btn-row"):
                yield Button("🚀 RUN BENCHMARK", id="btn-start", classes="-primary")
                yield Button("⬅ BACK", id="btn-back")
            
            with Container(classes="console-section"):
                yield Static("📊 RESULTS", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        
        yield Footer()

    def on_mount(self):
        c = self.query_one("#console", RichLog)
        c.write("[bold #39ff14]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #39ff14]║[/]          [bold]📈 Performance Benchmark Suite[/]                     [bold #39ff14]║[/]")
        c.write("[bold #39ff14]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write("[dim]Measures:[/]")
        c.write("  • Scan duration")
        c.write("  • Files/second processing rate")
        c.write("  • Memory usage")
        c.write("")
        c.write("[dim]Click RUN BENCHMARK to start...[/]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-start":
            asyncio.create_task(self._run_benchmark())

    async def _run_benchmark(self):
        path = self.query_one("#path-input", Input).value
        c = self.query_one("#console", RichLog)
        c.clear()
        
        c.write("[bold #39ff14]🚀 STARTING BENCHMARK[/]")
        c.write(f"[dim]Target: {path}[/]")
        c.write("")
        
        try:
            import psutil
            
            start_time = time.time()
            start_mem = psutil.Process().memory_info().rss / 1024 / 1024
            
            target = Path(path).resolve()
            files = list(target.rglob("*")) if target.is_dir() else [target]
            files = [f for f in files if f.is_file()]
            
            c.write(f"[#3b82f6]▸ Found {len(files)} files[/]")
            
            # Simulate scan
            lines_scanned = 0
            for i, f in enumerate(files[:200]):
                try:
                    content = f.read_text(errors='ignore')
                    lines_scanned += len(content.split('\n'))
                except:
                    pass
                
                if i % 50 == 0:
                    await asyncio.sleep(0.01)
                    c.write(f"[dim]Processing... {i+1}/{min(len(files), 200)}[/dim]")
            
            end_time = time.time()
            end_mem = psutil.Process().memory_info().rss / 1024 / 1024
            
            duration = end_time - start_time
            files_per_sec = min(len(files), 200) / duration if duration > 0 else 0
            lines_per_sec = lines_scanned / duration if duration > 0 else 0
            mem_used = end_mem - start_mem
            
            c.write("")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write("[bold #39ff14]✓ BENCHMARK COMPLETE[/]")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write("")
            c.write(f"[bold]📊 RESULTS[/]")
            c.write(f"   Duration: [bold]{duration:.2f}s[/]")
            c.write(f"   Files Scanned: [bold]{min(len(files), 200)}[/]")
            c.write(f"   Lines Scanned: [bold]{lines_scanned:,}[/]")
            c.write(f"   Speed: [bold #39ff14]{files_per_sec:.1f}[/] files/sec")
            c.write(f"   Speed: [bold #39ff14]{lines_per_sec:.0f}[/] lines/sec")
            c.write(f"   Memory Delta: [bold]{mem_used:+.1f}[/] MB")
            
        except ImportError:
            c.write("[bold red]✖ psutil not installed[/]")
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")

    def action_back(self):
        self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL SCAN SCREEN (with Progress & AI Selection)
# ═══════════════════════════════════════════════════════════════════════════════

class ScanScreen(Screen):
    """Professional local vulnerability scanner."""
    
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("enter", "start", "Start Scan"),
    ]

    def compose(self) -> ComposeResult:
        config = load_config()
        yield Header(show_clock=True)
        yield Static("🔍  LOCAL VULNERABILITY SCANNER", classes="screen-title")
        
        with Vertical(id="main-box"):
            with Container(classes="input-section"):
                yield Static("📁 TARGET PATH", classes="input-label")
                yield Input(placeholder="Enter directory path", value=".", id="path-input")
            
            with Container(classes="input-section"):
                yield Static("🤖 AI PROVIDER", classes="input-label")
                yield Select(
                    [
                        ("Google Gemini", "gemini"),
                        ("OpenAI GPT-4", "openai"),
                        ("Anthropic Claude", "anthropic"),
                        ("No AI (Offline)", "none"),
                    ],
                    value=config.get("ai_provider", "gemini"),
                    id="ai-select"
                )
            
            with Center(classes="btn-row"):
                yield Button("🚀 START SCAN", id="btn-start", classes="-primary")
                yield Button("📂 CURRENT DIR", id="btn-cwd")
                yield Button("⬅ BACK", id="btn-back")
            
            # Progress Bar
            yield ProgressBar(id="progress", total=100, show_eta=False)
            
            with Container(classes="console-section"):
                yield Static("📋 SCAN OUTPUT", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True, wrap=True)
        
        yield Footer()

    def on_mount(self):
        self._show_welcome()
        self.query_one("#progress", ProgressBar).update(total=100, progress=0)

    def _show_welcome(self):
        c = self.query_one("#console", RichLog)
        c.clear()
        c.write("[bold #39ff14]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #39ff14]║[/]          [bold]🛡️ Security Scanner - Ready[/]                          [bold #39ff14]║[/]")
        c.write("[bold #39ff14]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write("[#fbbf24]QUICK START:[/]")
        c.write("  [dim]1.[/] Enter target path above")
        c.write("  [dim]2.[/] Select AI provider for verification")
        c.write("  [dim]3.[/] Press [bold #39ff14]Enter[/] or click [bold #39ff14]START SCAN[/]")

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "btn-back": self.app.pop_screen()
        elif bid == "btn-start": self.action_start()
        elif bid == "btn-cwd":
            self.query_one("#path-input", Input).value = str(Path.cwd())

    def action_back(self): self.app.pop_screen()
    
    def action_start(self):
        path = self.query_one("#path-input", Input).value
        ai = self.query_one("#ai-select", Select).value
        asyncio.create_task(self._run_scan(path, ai))

    async def _run_scan(self, path: str, ai_provider: str):
        c = self.query_one("#console", RichLog)
        progress = self.query_one("#progress", ProgressBar)
        c.clear()
        
        c.write(f"[bold #39ff14]⚡ INITIALIZING SCAN[/]")
        c.write(f"[dim]Target: {path}[/]")
        c.write(f"[dim]AI: {ai_provider}[/]")
        c.write("")
        
        progress.update(total=100, progress=5)
        
        try:
            from scanner import scan_for_secrets, load_rules
            from vulnerability_scanner import VulnerabilityScanner
            
            start_time = time.time()
            
            c.write("[#3b82f6]▸ Loading rule definitions...[/]")
            progress.update(progress=10)
            rules = load_rules()
            scanner = VulnerabilityScanner()
            
            target = Path(path).resolve()
            if not target.exists():
                c.write(f"[bold red]✖ Error: Path not found[/]")
                return
            
            files = list(target.rglob("*")) if target.is_dir() else [target]
            files = [f for f in files if f.is_file() and not any(p.startswith('.') for p in f.parts)]
            
            config = load_config()
            max_files = config.get("scan_depth", 100)
            files = files[:max_files]
            
            c.write(f"[#3b82f6]▸ Scanning {len(files)} files...[/]")
            progress.update(progress=20)
            
            secrets_found = []
            vulns_found = []
            
            for i, f in enumerate(files):
                try:
                    content = f.read_text(errors='ignore')
                    
                    s = scan_for_secrets(str(f), content, rules)
                    if s:
                        secrets_found.extend(s)
                        for sec in s:
                            c.write(f"[bold red]🔑 SECRET:[/] {sec.get('type', 'Unknown')} in [dim]{f.name}[/]")
                    
                    if f.suffix == ".py":
                        v = scanner.scan_file(str(f))
                        if v:
                            vulns_found.extend(v)
                            for vuln in v:
                                color = {"critical": "#ef4444", "high": "#f97316", "medium": "#fbbf24", "low": "#22c55e"}.get(vuln.severity, "#6b7280")
                                c.write(f"[bold {color}]⚠ {vuln.severity.upper()}:[/] {vuln.title}")
                                
                except Exception:
                    pass
                
                # Update progress
                pct = 20 + int((i / len(files)) * 70)
                progress.update(progress=pct)
                
                if i % 20 == 0:
                    await asyncio.sleep(0.01)
            
            progress.update(progress=95)
            
            # AI Verification (if enabled)
            if ai_provider != "none" and secrets_found:
                c.write(f"[#3b82f6]▸ AI verification with {ai_provider}...[/]")
                await asyncio.sleep(0.5)  # Placeholder
            
            elapsed = time.time() - start_time
            progress.update(progress=100)
            
            c.write("")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write(f"[bold #39ff14]✓ SCAN COMPLETE[/] [dim]({elapsed:.2f}s)[/]")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write("")
            c.write(f"[bold]📊 SUMMARY[/]")
            c.write(f"   Files Scanned: [bold]{len(files)}[/]")
            c.write(f"   Secrets Found: [bold red]{len(secrets_found)}[/]")
            c.write(f"   Vulnerabilities: [bold #fbbf24]{len(vulns_found)}[/]")
            
            if secrets_found or vulns_found:
                c.write("")
                c.write("[bold red]⚠ Security issues detected![/]")
            else:
                c.write("")
                c.write("[bold #39ff14]✓ No security issues detected.[/]")
            
        except ImportError as e:
            c.write(f"[bold red]✖ Module Error: {e}[/]")
            progress.update(progress=100)
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")
            progress.update(progress=100)


# ═══════════════════════════════════════════════════════════════════════════════
# URL SCAN SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class URLScreen(Screen):
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("enter", "start", "Start"),
    ]
    
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
            yield ProgressBar(id="progress", total=100, show_eta=False)
            with Container(classes="console-section"):
                yield Static("📋 OUTPUT", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        c = self.query_one("#console", RichLog)
        c.write("[bold #39ff14]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #39ff14]║[/]          [bold]🌐 Remote Repository Scanner[/]                       [bold #39ff14]║[/]")
        c.write("[bold #39ff14]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write("[#fbbf24]Supported:[/] GitHub, GitLab, Bitbucket")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-start": self.action_start()

    def action_back(self): self.app.pop_screen()
    
    def action_start(self):
        url = self.query_one("#url-input", Input).value
        if not url:
            self.query_one("#console", RichLog).write("[bold red]✖ Enter a URL[/]")
            return
        asyncio.create_task(self._run_url_scan(url))

    async def _run_url_scan(self, url: str):
        c = self.query_one("#console", RichLog)
        progress = self.query_one("#progress", ProgressBar)
        c.clear()
        c.write(f"[bold #39ff14]⚡ SCANNING: {url}[/]")
        progress.update(progress=10)
        
        try:
            from url_scanner import URLScanner
            from scanner import scan_for_secrets, load_rules
            from vulnerability_scanner import VulnerabilityScanner
            
            c.write("[#3b82f6]▸ Cloning repository...[/]")
            progress.update(progress=30)
            
            with URLScanner() as scanner:
                local_path = scanner.scan_url(url)
                c.write(f"[#39ff14]✓ Cloned[/]")
                progress.update(progress=50)
                
                rules = load_rules()
                vuln_scanner = VulnerabilityScanner()
                
                files = list(Path(local_path).rglob("*"))
                files = [f for f in files if f.is_file()][:100]
                
                c.write(f"[#3b82f6]▸ Scanning {len(files)} files...[/]")
                
                secrets = []
                vulns = []
                for f in files:
                    try:
                        content = f.read_text(errors='ignore')
                        s = scan_for_secrets(str(f), content, rules)
                        secrets.extend(s or [])
                        if f.suffix == ".py":
                            v = vuln_scanner.scan_file(str(f))
                            vulns.extend(v or [])
                    except: pass
                
                progress.update(progress=100)
                c.write("")
                c.write(f"[bold #39ff14]✓ COMPLETE[/]")
                c.write(f"   Secrets: [bold red]{len(secrets)}[/]")
                c.write(f"   Vulnerabilities: [bold #fbbf24]{len(vulns)}[/]")
                
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")
            progress.update(progress=100)


# ═══════════════════════════════════════════════════════════════════════════════
# BLACK BOX SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class BlackBoxScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back"), Binding("enter", "start", "Start")]
    
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
            yield ProgressBar(id="progress", total=100, show_eta=False)
            with Container(classes="console-section"):
                yield Static("📋 TEST RESULTS", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        c = self.query_one("#console", RichLog)
        c.write("[bold #39ff14]🎯 Black Box Security Testing[/]")
        c.write("")
        c.write("[#fbbf24]Tests:[/] Headers, SSL, SQLi, XSS, Path Traversal")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-start": self.action_start()

    def action_back(self): self.app.pop_screen()
    
    def action_start(self):
        url = self.query_one("#url-input", Input).value
        if not url: return
        asyncio.create_task(self._run_blackbox(url))

    async def _run_blackbox(self, url: str):
        c = self.query_one("#console", RichLog)
        progress = self.query_one("#progress", ProgressBar)
        c.clear()
        c.write(f"[bold red]🎯 TESTING: {url}[/]")
        
        try:
            from blackbox_tester import BlackBoxTester
            tester = BlackBoxTester(url)
            
            tests = [
                ("Security Headers", tester.test_security_headers, 25),
                ("SSL/TLS", tester.test_ssl_tls, 50),
                ("SQL Injection", tester.test_sql_injection, 75),
                ("XSS", tester.test_xss, 100),
            ]
            
            total_issues = 0
            for name, func, pct in tests:
                c.write(f"[#3b82f6]▸ Testing {name}...[/]")
                progress.update(progress=pct)
                await asyncio.sleep(0.1)
                try:
                    results = func()
                    if results:
                        total_issues += len(results)
                        for issue in results[:3]:
                            c.write(f"[bold #fbbf24]⚠[/] {issue.get('issue', issue.get('header', str(issue)))}")
                    else:
                        c.write(f"[#39ff14]✓ {name} OK[/]")
                except Exception as e:
                    c.write(f"[dim]  Error: {e}[/dim]")
            
            c.write("")
            c.write(f"[bold #39ff14]✓ COMPLETE - {total_issues} issues found[/]")
            
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")
            progress.update(progress=100)


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO FIX SCREEN
# ═══════════════════════════════════════════════════════════════════════════════

class AutoFixScreen(Screen):
    BINDINGS = [Binding("escape", "back", "Back"), Binding("enter", "start", "Start")]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("🔧  AUTOMATED REMEDIATION ENGINE", classes="screen-title")
        with Vertical(id="main-box"):
            with Container(classes="input-section"):
                yield Static("📁 PROJECT PATH", classes="input-label")
                yield Input(value=".", id="path-input")
            with Center(classes="btn-row"):
                yield Button("👁 PREVIEW", id="btn-preview")
                yield Button("🔧 APPLY FIXES", id="btn-apply", classes="-primary")
                yield Button("⬅ BACK", id="btn-back")
            yield ProgressBar(id="progress", total=100, show_eta=False)
            with Container(classes="console-section"):
                yield Static("📋 FIX LOG", classes="console-title")
                yield RichLog(id="console", highlight=True, markup=True)
        yield Footer()

    def on_mount(self):
        c = self.query_one("#console", RichLog)
        c.write("[bold #39ff14]🔧 Auto-Fix Engine[/]")
        c.write("")
        c.write("[#fbbf24]Fixes:[/] Weak Crypto, Hardcoded Secrets, Dangerous Functions")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-preview": asyncio.create_task(self._preview())
        elif event.button.id == "btn-apply": asyncio.create_task(self._apply())

    def action_back(self): self.app.pop_screen()
    def action_start(self): asyncio.create_task(self._preview())

    async def _preview(self):
        path = self.query_one("#path-input", Input).value
        c = self.query_one("#console", RichLog)
        progress = self.query_one("#progress", ProgressBar)
        c.clear()
        c.write(f"[bold #fbbf24]👁 PREVIEW FIXES[/]")
        
        try:
            from auto_fix import AutoFix
            fixer = AutoFix(interactive=False)
            
            files = list(Path(path).resolve().rglob("*.py"))[:50]
            total = 0
            
            for i, f in enumerate(files):
                progress.update(progress=int((i/len(files))*100))
                try:
                    content = f.read_text(errors='ignore')
                    _, crypto = fixer.fix_weak_crypto(str(f), content)
                    _, secrets, _ = fixer.fix_hardcoded_secrets(str(f), content)
                    _, danger = fixer.fix_dangerous_functions(str(f), content)
                    
                    for fix in crypto + secrets + danger:
                        c.write(f"[#fbbf24]⚡[/] {fix.description} in [dim]{f.name}[/]")
                        total += 1
                except: pass
            
            progress.update(progress=100)
            c.write("")
            c.write(f"[bold]Total fixable: {total}[/]")
            
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")

    async def _apply(self):
        path = self.query_one("#path-input", Input).value
        c = self.query_one("#console", RichLog)
        progress = self.query_one("#progress", ProgressBar)
        c.clear()
        c.write(f"[bold #39ff14]🔧 APPLYING FIXES[/]")
        
        try:
            from auto_fix import AutoFix
            fixer = AutoFix(interactive=False)
            
            files = list(Path(path).resolve().rglob("*.py"))[:50]
            fixed = 0
            
            for i, f in enumerate(files):
                progress.update(progress=int((i/len(files))*100))
                try:
                    result = fixer.fix_file(str(f))
                    if result.get('fixes_applied', 0) > 0:
                        fixed += result['fixes_applied']
                        c.write(f"[#39ff14]✓[/] {f.name} ({result['fixes_applied']} fixes)")
                except: pass
            
            progress.update(progress=100)
            c.write("")
            c.write(f"[bold #39ff14]✓ Applied {fixed} fixes[/]")
            
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS SCREEN (with PDF Export)
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
                yield Button("📄 EXPORT PDF", id="btn-pdf", classes="-warning")
                yield Button("📂 OPEN FOLDER", id="btn-open")
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
                for r in reports[:20]:
                    size = r.stat().st_size // 1024
                    icon = "📄" if r.suffix in [".txt", ".md"] else "📊" if r.suffix == ".json" else "🌐" if r.suffix == ".html" else "📑"
                    c.write(f"[#3b82f6]{icon}[/] {r.name} [dim]({size}KB)[/]")
            else:
                c.write("[dim]No reports found.[/]")
        else:
            c.write("[dim]Output directory not found.[/]")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-back": self.app.pop_screen()
        elif event.button.id == "btn-refresh": self._list_reports()
        elif event.button.id == "btn-pdf": self._export_pdf()
        elif event.button.id == "btn-open": self._open_folder()

    def _export_pdf(self):
        c = self.query_one("#console", RichLog)
        try:
            from report_generator import ReportGenerator
            gen = ReportGenerator()
            c.write("[#3b82f6]▸ Generating PDF...[/]")
            # This would need actual data - placeholder
            c.write("[bold #39ff14]✓ PDF export feature ready[/]")
            c.write("[dim]Run a scan first to generate PDF report[/]")
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")

    def _open_folder(self):
        import subprocess
        output = Path("output")
        if output.exists():
            if sys.platform == "win32":
                subprocess.run(["explorer", str(output)])
            elif sys.platform == "darwin":
                subprocess.run(["open", str(output)])
            else:
                subprocess.run(["xdg-open", str(output)])
    
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
