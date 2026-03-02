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
    "ai_provider": "huggingface",
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
    background: #0f172a;  /* Slate 950 */
}

Header {
    background: #1e293b;  /* Slate 800 */
    color: #38bdf8;       /* Sky 400 */
    text-style: bold;
    border-bottom: solid #0f172a;
}

Footer {
    background: #1e293b;
    color: #94a3b8;       /* Slate 400 */
    border-top: solid #0f172a;
}

FooterKey {
    background: #334155;
    color: #38bdf8;
    padding: 0 1;
}

#main-box {
    width: 100%;
    height: 100%;
    padding: 1 2;
}

.logo-box {
    height: auto;
    padding: 1;
    background: #1e293b;
    border: solid #334155;
    margin-bottom: 1;
}

.title-text {
    color: #38bdf8;
    text-style: bold;
    text-align: center;
}

/* DASHBOARD GRID */
.dashboard-grid {
    layout: grid;
    grid-size: 4 2;
    grid-gutter: 1;
    margin: 1 1;
}

.dashboard-card {
    background: #1e293b;
    border: solid #334155;
    height: 100%;
    padding: 1;
    align: center middle;
}

.dashboard-card:hover {
    background: #334155;
    border: solid #38bdf8;
}

.card-icon {
    text-align: center;
    color: #38bdf8;
    padding-bottom: 1;
}

.card-title {
    text-align: center;
    text-style: bold;
    color: #f8fafc;
}

.card-desc {
    text-align: center;
    color: #94a3b8;
}

/* STATUS BAR */
.status-bar {
    height: 3;
    background: #1e293b;
    border-top: solid #334155;
    padding: 1 2;
    color: #94a3b8;
    align-vertical: middle;
}

/* INPUTS & SELECTS */
Input {
    background: #1e293b;
    border: solid #475569;
    color: #f8fafc;
    padding: 0 1;
}

Input:focus {
    border: solid #38bdf8;
}

Select {
    background: #1e293b;
    border: solid #475569;
    color: #f8fafc;
    width: 100%;
    height: 3;
}

Select:focus {
    border: double #38bdf8;
}

Select > SelectCurrent {
    background: #1e293b;
    color: #f8fafc;
}

Select > SelectOverlay {
    background: #0f172a;
    border: solid #334155;
}

SelectOverlay:focus > SelectCurrent {
    background: #334155;
}

/* BUTTONS */
Button {
    min-width: 16;
    background: #334155;
    color: #f8fafc;
    border: none;
}

Button:hover {
    background: #475569;
}

Button.-primary {
    background: #0369a1; /* Sky 700 */
    color: #ffffff;
}

Button.-primary:hover {
    background: #0284c7; /* Sky 600 */
}

Button.-warning {
    background: #b45309;
    color: #ffffff;
}

Button.-danger {
    background: #be123c;
    color: #ffffff;
}

/* CONSOLE */
RichLog {
    background: #0f172a;
    border: solid #334155;
    padding: 1;
    height: 1fr;
    color: #e2e8f0;
    overflow-y: scroll;
}

/* UTILS */
.screen-title {
    text-align: center;
    color: #38bdf8;
    text-style: bold;
    padding: 1;
    background: #1e293b;
    border-bottom: solid #334155;
    width: 100%;
}

.input-section {
    padding: 1 2;
    background: #1e293b;
    border: solid #334155;
    margin: 1 0;
}

.input-label {
    color: #38bdf8;
    margin-bottom: 1;
    text-style: bold;
}

.btn-row {
    height: auto;
    padding: 1 0;
    align: center middle;
    background: #0f172a;
}

.settings-group {
    background: #1e293b;
    border: solid #334155;
    padding: 1 2;
    margin: 1 0;
}

.settings-label {
    color: #38bdf8;
    text-style: bold;
    padding-bottom: 1;
}

ProgressBar {
    padding: 1 0;
}

ProgressBar > .bar--bar {
    color: #38bdf8;
    background: #0369a1;
}

Switch {
    background: #334155;
}

Switch.-on {
    background: #0369a1;
}

/* CONSOLE SECTION */
.console-section {
    background: #0f172a;
    border: solid #334155;
    padding: 0 1;
    height: 1fr;
    margin-top: 1;
}

.console-title {
    color: #38bdf8;
    text-style: bold;
    padding: 0 1;
    background: #1e293b;
    border-bottom: solid #334155;
    height: 3;
}

/* STATUS BAR LABELS */
.status-ok {
    color: #39ff14;
    text-style: bold;
}

.status-text {
    color: #94a3b8;
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

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        actions = {
            "btn-1": self.action_go_scan,
            "btn-2": self.action_go_url,
            "btn-3": self.action_go_blackbox,
            "btn-4": self.action_go_autofix,
            "btn-5": self.action_go_reports,
            "btn-6": self.action_go_benchmark,
            "btn-7": self.action_go_settings,
            "btn-q": self.action_quit,
        }
        if bid in actions:
            if asyncio.iscoroutinefunction(actions[bid]):
                await actions[bid]()
            else:
                actions[bid]()

    def compose(self) -> ComposeResult:
        config = load_config()
        # Clean Professional Header
        yield Header(show_clock=True)
        
        with Vertical(id="main-box"):
            # Enterprise Banner
            with Container(classes="logo-box"):
                yield Static("🛡️  ENTERPRISE SECURITY SCANNER", classes="title-text")
                yield Static(f"[dim]v4.0.0 • AI Provider: {config['ai_provider'].upper()}[/]", classes="title-text")
            
            # Main Dashboard Grid
            with Grid(classes="dashboard-grid"):
                yield Button("🔍  LOCAL SCAN", id="btn-1", classes="dashboard-card")
                yield Button("🌐  URL SCAN", id="btn-2", classes="dashboard-card")
                yield Button("🎯  BLACK BOX", id="btn-3", classes="dashboard-card")
                yield Button("🔧  AUTO FIX", id="btn-4", classes="dashboard-card")
                yield Button("📊  REPORTS", id="btn-5", classes="dashboard-card")
                yield Button("📈  BENCHMARK", id="btn-6", classes="dashboard-card")
                yield Button("⚙️  SETTINGS", id="btn-7", classes="dashboard-card")
                yield Button("🚪  EXIT", id="btn-q", classes="dashboard-card")
            
            # Status Bar
            with Horizontal(classes="status-bar"):
                yield Static("● SYSTEM STATUS: ONLINE", classes="status-ok")
                yield Static(f"  │  OPERATOR: {os.getenv('USER', os.getenv('USERNAME', 'Admin'))}", classes="status-text")
        
        yield Footer()


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
    
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("s", "save", "Save"),
    ]

    def compose(self) -> ComposeResult:
        config = load_config()
        yield Header(show_clock=True)
        yield Static("⚙️  SETTINGS", classes="screen-title")
        
        with Vertical(id="main-box"):
            # AI Provider Selection
            with Container(classes="settings-group"):
                yield Static("🤖 AI PROVIDER", classes="settings-label")
                yield Static("[dim]Choose AI engine for vulnerability verification[/dim]")
                yield Select(
                    [
                        ("🤗 HuggingFace (Free - Recommended)", "huggingface"),
                        ("🔷 Google Gemini (API Key Required)", "gemini"),
                        ("🟢 OpenAI GPT-4 (API Key Required)", "openai"),
                        ("🟣 Anthropic Claude (API Key Required)", "anthropic"),
                        ("⚫ No AI (Offline Mode)", "none"),
                    ],
                    value=config.get("ai_provider", "huggingface"),
                    id="ai-select",
                    allow_blank=False,
                )
            
            # Output Directory
            with Container(classes="settings-group"):
                yield Static("📁 OUTPUT DIRECTORY", classes="settings-label")
                yield Static("[dim]Where to save scan reports[/dim]")
                yield Input(value=config.get("output_dir", "./output"), id="output-dir", placeholder="./output")
            
            # Scan Depth
            with Container(classes="settings-group"):
                yield Static("🔢 MAX FILES TO SCAN", classes="settings-label")
                yield Static("[dim]Maximum number of files per scan (higher = slower)[/dim]")
                yield Input(value=str(config.get("scan_depth", 100)), id="scan-depth", placeholder="100")
            
            # Toggles Section
            with Container(classes="settings-group"):
                yield Static("🔧 OPTIONS", classes="settings-label")
                
                with Horizontal():
                    yield Switch(value=config.get("enable_ai", True), id="enable-ai")
                    yield Static("  Enable AI Verification")
                
                yield Static("")
                
                with Horizontal():
                    yield Switch(value=config.get("auto_open_reports", True), id="auto-open")
                    yield Static("  Auto-open Reports in Browser")
            
            # Buttons
            with Center(classes="btn-row"):
                yield Button("💾 SAVE [S]", id="btn-save", classes="-primary")
                yield Button("🔄 RESET", id="btn-reset", classes="-warning")
                yield Button("⬅ BACK [Esc]", id="btn-back")
            
            # Status
            yield Static("", id="status-msg")
        
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "btn-back":
            self.app.pop_screen()
        elif bid == "btn-save":
            self.action_save()
        elif bid == "btn-reset":
            self._reset_settings()

    def action_save(self):
        """Save settings to config file."""
        try:
            ai_select = self.query_one("#ai-select", Select)
            output_dir = self.query_one("#output-dir", Input)
            scan_depth = self.query_one("#scan-depth", Input)
            enable_ai = self.query_one("#enable-ai", Switch)
            auto_open = self.query_one("#auto-open", Switch)
            
            config = {
                "ai_provider": ai_select.value if ai_select.value else "huggingface",
                "output_dir": output_dir.value or "./output",
                "scan_depth": int(scan_depth.value) if scan_depth.value.isdigit() else 100,
                "enable_ai": enable_ai.value,
                "auto_open_reports": auto_open.value,
            }
            save_config(config)
            self.notify("✅ Settings saved successfully!", severity="information")
        except Exception as e:
            self.notify(f"❌ Error saving: {e}", severity="error")

    def _reset_settings(self):
        """Reset to default settings."""
        save_config(DEFAULT_CONFIG)
        self.notify("🔄 Settings reset to defaults!", severity="warning")
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
        
        c.write("[bold #38bdf8]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #38bdf8]║[/]          [bold]📈 PERFORMANCE BENCHMARKING[/]                         [bold #38bdf8]║[/]")
        c.write("[bold #38bdf8]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write(f"[dim]Target Path:[/] {path}")
        c.write("[dim]Mode:[/]        Full System Benchmark")
        c.write("")
        
        try:
            from benchmark import PerformanceMonitor, Benchmark
            from scanner import scan_single_file, load_rules
            
            c.write("[#38bdf8]🚀 Initializing Benchmark Suite...[/]")
            c.write("[dim]Preparing test environment...[/dim]")
            await asyncio.sleep(0.5) # UI update
            
            # Initialize Monitor before the scan task
            monitor = PerformanceMonitor("Local Scan Benchmark")
            c.write("[#38bdf8]▸ Starting Performance Monitor...[/]")
            monitor.start()

            # Create a wrapped scan function that records per-file metrics
            def benchmark_scan_task(target_path):
                rules = load_rules()
                target_p = Path(target_path).resolve()
                files = list(target_p.rglob("*")) if target_p.is_dir() else [target_p]
                files = [f for f in files if f.is_file()]
                # Limit for benchmark speed if too large
                processed_files = files[:500]

                for f in processed_files:
                    try:
                        scan_single_file(f, rules)
                        try:
                            line_count = f.read_text(errors="ignore").count("\n")
                        except Exception:
                            line_count = 0
                        monitor.record_file_scanned(line_count)
                    except Exception:
                        pass
                return len(processed_files)

            # Run the task in a thread to not block UI
            c.write("[#38bdf8]▸ Executing Scan Operation...[/]")
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, benchmark_scan_task, path)

            metrics = monitor.stop()
            
            # Add results to history
            bench = Benchmark()
            bench.add_result(metrics)
            
            c.write("")
            c.write("[bold #38bdf8]═══════════════════════════════════════════════════════════════[/]")
            c.write("[bold #38bdf8]✓ BENCHMARK COMPLETE[/]")
            c.write("[bold #38bdf8]═══════════════════════════════════════════════════════════════[/]")
            c.write("")
            
            # Display beautifully in the log
            c.write(f"[bold]📊 METRICS REPORT[/]")
            c.write(f"   Duration:          [bold]{metrics.duration_seconds:.4f}s[/]")
            c.write(f"   Files Processed:   [bold]{metrics.files_scanned}[/]")
            c.write(f"   Throughput:        [bold #38bdf8]{metrics.files_per_second:.1f}[/] files/sec")
            c.write(f"   Peak Memory:       [bold]{metrics.peak_memory_mb:.2f} MB[/]")
            c.write(f"   CPU Usage (Avg):   [bold]{metrics.avg_cpu_percent:.1f}%[/]")
            
            # Compare with baseline
            comparison = bench.compare_with_baseline(metrics)
            if comparison['has_baseline']:
                c.write("")
                c.write("[bold]📈 COMPARISON (vs Avg)[/]")
                
                def fmt_diff(val, inverse=False):
                    is_good = val < 0 if not inverse else val > 0
                    color = "#39ff14" if is_good else "#ef4444"
                    return f"[{color}]{val:+.1f}%[/{color}]"
                
                c.write(f"   Speed Delta:       {fmt_diff(comparison['speed_change_percent'], inverse=True)}")
                c.write(f"   Memory Delta:      {fmt_diff(comparison['memory_change_percent'])}")
            
        except ImportError as e:
            c.write(f"[bold red]✖ Dependency Error: {e}[/]")
        except Exception as e:
            c.write(f"[bold red]✖ Benchmark Error: {e}[/]")
            import traceback
            c.write(f"[dim]{traceback.format_exc()[:300]}[/dim]")


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
                        ("🤗 HuggingFace (Free)", "huggingface"),
                        ("Google Gemini", "gemini"),
                        ("OpenAI GPT-4", "openai"),
                        ("Anthropic Claude", "anthropic"),
                        ("No AI (Offline)", "none"),
                    ],
                    value=config.get("ai_provider", "huggingface"),
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
        """Run comprehensive security scan."""
        c = self.query_one("#console", RichLog)
        progress = self.query_one("#progress", ProgressBar)
        c.clear()
        
        c.write("[bold #39ff14]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #39ff14]║[/]          [bold]🛡️ SECURITY SCAN STARTING[/]                           [bold #39ff14]║[/]")
        c.write("[bold #39ff14]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write(f"[dim]Target:[/] {path}")
        c.write(f"[dim]AI Provider:[/] {ai_provider}")
        c.write("")
        
        progress.update(total=100, progress=5)
        
        try:
            # Import scanner modules
            from scanner import scan_single_file, load_rules, calculate_entropy
            from vulnerability_scanner import VulnerabilityScanner
            
            start_time = time.time()
            
            # Step 1: Load rules
            c.write("[#3b82f6]▸ Loading detection rules...[/]")
            progress.update(progress=10)
            await asyncio.sleep(0.05)
            
            rules = load_rules()
            c.write(f"[#39ff14]  ✓ Loaded {len(rules)} detection patterns[/]")
            
            # Step 2: Collect files
            c.write("[#3b82f6]▸ Collecting files to scan...[/]")
            progress.update(progress=15)
            
            target = Path(path).resolve()
            if not target.exists():
                c.write(f"[bold red]✖ ERROR: Path not found: {target}[/]")
                progress.update(progress=100)
                return
            
            # Collect all files, excluding hidden and common non-code files
            IGNORE_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', '.venv', 'dist', 'build', '.idea', '.vscode'}
            IGNORE_EXTS = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.jpg', '.png', '.gif', '.ico', '.woff', '.ttf'}
            
            all_files = []
            if target.is_file():
                all_files = [target]
            else:
                for f in target.rglob("*"):
                    if f.is_file():
                        # Skip ignored directories
                        if any(part in IGNORE_DIRS for part in f.parts):
                            continue
                        # Skip ignored extensions
                        if f.suffix.lower() in IGNORE_EXTS:
                            continue
                        all_files.append(f)
            
            # Limit files based on config
            config = load_config()
            max_files = config.get("scan_depth", 100)
            files = all_files[:max_files]
            
            c.write(f"[#39ff14]  ✓ Found {len(files)} files to scan[/]")
            if len(all_files) > max_files:
                c.write(f"[dim]  (Limited to {max_files} files - change in Settings)[/dim]")
            
            progress.update(progress=20)
            
            # Step 3: Scan for secrets
            c.write("")
            c.write("[#3b82f6]▸ Scanning for secrets and credentials...[/]")
            
            secrets_found = []
            for i, f in enumerate(files):
                try:
                    # Use the proper scan_single_file function
                    findings = scan_single_file(f, rules)
                    if findings:
                        for finding in findings:
                            # Calculate entropy for filtering
                            match_text = finding.get('match', '')
                            entropy = calculate_entropy(match_text)
                            
                            if entropy > 3.0:  # Only high-entropy matches
                                secrets_found.append(finding)
                                c.write(f"[bold red]🔑 SECRET:[/] {f.name}:{finding.get('line', '?')}")
                                c.write(f"[dim]   Pattern: {match_text[:50]}...[/dim]" if len(match_text) > 50 else f"[dim]   Pattern: {match_text}[/dim]")
                except Exception as e:
                    pass
                
                # Update progress
                pct = 20 + int((i / max(len(files), 1)) * 35)
                progress.update(progress=pct)
                
                if i % 25 == 0:
                    await asyncio.sleep(0.01)  # Allow UI updates
            
            c.write(f"[#39ff14]  ✓ Secret scan complete: {len(secrets_found)} found[/]")
            progress.update(progress=60)
            
            # Step 4: Vulnerability scanning (Python files only)
            c.write("")
            c.write("[#3b82f6]▸ Scanning for code vulnerabilities...[/]")
            
            vulns_found = []
            vuln_scanner = VulnerabilityScanner()
            py_files = [f for f in files if f.suffix == '.py']
            
            for i, f in enumerate(py_files):
                try:
                    vulns = vuln_scanner.scan_file(str(f))
                    if vulns:
                        for v in vulns:
                            vulns_found.append(v)
                            severity_colors = {
                                "critical": "#ef4444",
                                "high": "#f97316", 
                                "medium": "#fbbf24",
                                "low": "#22c55e"
                            }
                            color = severity_colors.get(v.severity, "#6b7280")
                            c.write(f"[bold {color}]⚠ {v.severity.upper()}:[/] {v.title}")
                            c.write(f"[dim]   {f.name}:{v.line_number}[/dim]")
                except Exception as e:
                    pass
                
                pct = 60 + int((i / max(len(py_files), 1)) * 25)
                progress.update(progress=pct)
                
                if i % 10 == 0:
                    await asyncio.sleep(0.01)
            
            c.write(f"[#39ff14]  ✓ Vulnerability scan complete: {len(vulns_found)} found[/]")
            progress.update(progress=90)
            
            # Step 5: AI Verification (if enabled)
            if ai_provider != "none" and config.get("enable_ai", True) and secrets_found:
                c.write("")
                c.write(f"[#3b82f6]▸ AI verification with {ai_provider}...[/]")
                
                try:
                    if ai_provider == "huggingface":
                        from ai_providers.huggingface_provider import HuggingFaceProvider
                        provider = HuggingFaceProvider()
                        if provider.initialize(quiet=True):
                            verified = 0
                            for finding in secrets_found[:5]:  # Limit AI calls
                                is_secret = provider.verify(finding.get('match', ''), quiet=True)
                                if is_secret:
                                    verified += 1
                                await asyncio.sleep(0.1)
                            c.write(f"[#39ff14]  ✓ AI verified {verified}/{min(len(secrets_found), 5)} as real secrets[/]")
                        else:
                            c.write("[dim]  AI verification skipped (no HF_TOKEN)[/dim]")
                except Exception as e:
                    c.write(f"[dim]  AI verification error: {e}[/dim]")
            
            progress.update(progress=100)
            
            # Final Summary
            elapsed = time.time() - start_time
            
            c.write("")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write("[bold #39ff14]                    ✓ SCAN COMPLETE                            [/]")
            c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
            c.write("")
            c.write("[bold]📊 RESULTS SUMMARY[/]")
            c.write(f"   Files Scanned:    [bold]{len(files)}[/]")
            c.write(f"   Secrets Found:    [bold red]{len(secrets_found)}[/]")
            c.write(f"   Vulnerabilities:  [bold #fbbf24]{len(vulns_found)}[/]")
            c.write(f"   Scan Duration:    [bold]{elapsed:.2f}s[/]")
            c.write("")
            
            # Risk Assessment
            if len(secrets_found) > 0 or any(v.severity in ['critical', 'high'] for v in vulns_found):
                c.write("[bold red]⚠ SECURITY ISSUES DETECTED![/]")
                c.write("[dim]Review findings above and fix before deploying.[/dim]")
            else:
                c.write("[bold #39ff14]✓ No critical security issues detected.[/]")
            
        except ImportError as e:
            c.write(f"[bold red]✖ Module Error: {e}[/]")
            c.write("[dim]Make sure all dependencies are installed.[/dim]")
            progress.update(progress=100)
        except Exception as e:
            c.write(f"[bold red]✖ Scan Error: {e}[/]")
            import traceback
            c.write(f"[dim]{traceback.format_exc()[:500]}[/dim]")
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
        
        c.write("[bold #39ff14]╔══════════════════════════════════════════════════════════════╗[/]")
        c.write("[bold #39ff14]║[/]          [bold]🌐 CLONING & SCANNING REPOSITORY[/]                    [bold #39ff14]║[/]")
        c.write("[bold #39ff14]╚══════════════════════════════════════════════════════════════╝[/]")
        c.write("")
        c.write(f"[dim]URL:[/] {url}")
        c.write("")
        progress.update(progress=10)
        
        try:
            from url_scanner import URLScanner
            from scanner import scan_single_file, load_rules, calculate_entropy
            from vulnerability_scanner import VulnerabilityScanner
            
            c.write("[#3b82f6]▸ Cloning repository...[/]")
            c.write("[dim]  This may take a moment for large repos...[/dim]")
            progress.update(progress=20)
            await asyncio.sleep(0.1)
            
            with URLScanner() as scanner:
                local_path = scanner.scan_url(url)
                c.write(f"[#39ff14]  ✓ Repository cloned to temp directory[/]")
                progress.update(progress=40)
                
                c.write("[#3b82f6]▸ Loading detection rules...[/]")
                rules = load_rules()
                vuln_scanner = VulnerabilityScanner()
                
                # Collect files
                IGNORE_DIRS = {'.git', '__pycache__', 'node_modules', 'venv', '.venv'}
                files = []
                for f in Path(local_path).rglob("*"):
                    if f.is_file() and not any(part in IGNORE_DIRS for part in f.parts):
                        files.append(f)
                files = files[:100]  # Limit for performance
                
                c.write(f"[#39ff14]  ✓ Found {len(files)} files to scan[/]")
                progress.update(progress=50)
                
                # Scan for secrets
                c.write("")
                c.write("[#3b82f6]▸ Scanning for secrets...[/]")
                secrets = []
                for i, f in enumerate(files):
                    try:
                        findings = scan_single_file(f, rules)
                        for finding in findings or []:
                            match_text = finding.get('match', '')
                            entropy = calculate_entropy(match_text)
                            if entropy > 3.0:
                                secrets.append(finding)
                                c.write(f"[bold red]🔑 SECRET:[/] {f.name}:{finding.get('line', '?')}")
                    except Exception:
                        pass

                    if i % 20 == 0 and len(files) > 0:
                        pct = 50 + int((i / len(files)) * 25)
                        progress.update(progress=pct)
                        await asyncio.sleep(0.01)
                
                c.write(f"[#39ff14]  ✓ Secret scan: {len(secrets)} found[/]")
                progress.update(progress=80)
                
                # Scan for vulnerabilities
                c.write("[#3b82f6]▸ Scanning for vulnerabilities...[/]")
                vulns = []
                py_files = [f for f in files if f.suffix == '.py']
                for f in py_files:
                    try:
                        v = vuln_scanner.scan_file(str(f))
                        if v:
                            vulns.extend(v)
                            for vuln in v[:2]:  # Limit output
                                c.write(f"[bold #fbbf24]⚠ {vuln.severity.upper()}:[/] {vuln.title}")
                    except:
                        pass
                
                c.write(f"[#39ff14]  ✓ Vulnerability scan: {len(vulns)} found[/]")
                progress.update(progress=100)
                
                # Summary
                c.write("")
                c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
                c.write("[bold #39ff14]                    ✓ SCAN COMPLETE                            [/]")
                c.write("[bold #39ff14]═══════════════════════════════════════════════════════════════[/]")
                c.write("")
                c.write(f"[bold]📊 RESULTS[/]")
                c.write(f"   Repository: {url.split('/')[-1]}")
                c.write(f"   Files Scanned: [bold]{len(files)}[/]")
                c.write(f"   Secrets Found: [bold red]{len(secrets)}[/]")
                c.write(f"   Vulnerabilities: [bold #fbbf24]{len(vulns)}[/]")
                
        except Exception as e:
            c.write(f"[bold red]✖ Error: {e}[/]")
            import traceback
            c.write(f"[dim]{traceback.format_exc()[:300]}[/dim]")
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
        url = self.query_one("#url-input", Input).value.strip()
        if not url:
            self.notify("Enter a target URL first.", severity="warning")
            return
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

            if not files:
                c.write("[dim]No Python files found in the specified path.[/dim]")
                progress.update(progress=100)
                return

            for i, f in enumerate(files):
                progress.update(progress=int((i / len(files)) * 100))
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

            if not files:
                c.write("[dim]No Python files found in the specified path.[/dim]")
                progress.update(progress=100)
                return

            for i, f in enumerate(files):
                progress.update(progress=int((i / len(files)) * 100))
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
        """Export a summary report of all existing scan results."""
        c = self.query_one("#console", RichLog)
        try:
            output = Path("output")
            output.mkdir(parents=True, exist_ok=True)

            json_reports = sorted(output.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)

            if not json_reports:
                c.write("[dim]No scan results found. Run a scan first to generate a report.[/dim]")
                self.notify("No scan data found – run a scan first.", severity="warning")
                return

            # Build an HTML summary from the most recent JSON reports
            c.write("[#3b82f6]▸ Building report from scan data...[/]")
            import json as _json
            from datetime import datetime as _dt

            rows = []
            for jf in json_reports[:10]:
                try:
                    data = _json.loads(jf.read_text(encoding="utf-8", errors="ignore"))
                    name = jf.stem
                    secrets = len(data.get("secrets", []))
                    vulns   = len(data.get("vulnerabilities", []))
                    rows.append((name, secrets, vulns))
                except Exception:
                    pass

            if not rows:
                c.write("[dim]Could not parse any scan results.[/dim]")
                self.notify("Could not read scan results.", severity="warning")
                return

            ts   = _dt.now().strftime("%Y%m%d_%H%M%S")
            html = output / f"summary_report_{ts}.html"

            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Scanner – Summary Report</title>
<style>
  body{{font-family:monospace;background:#0f172a;color:#e2e8f0;padding:2em}}
  h1{{color:#38bdf8}} table{{border-collapse:collapse;width:100%;margin-top:1em}}
  th,td{{padding:.5em 1em;border:1px solid #334155;text-align:left}}
  th{{background:#1e293b;color:#38bdf8}} tr:nth-child(even){{background:#1e293b}}
  .red{{color:#ef4444}} .green{{color:#39ff14}} .footer{{margin-top:2em;color:#6b7280;font-size:.85em}}
</style>
</head>
<body>
<h1>🛡️ Security Scanner – Summary Report</h1>
<p>Generated: {_dt.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<table>
  <tr><th>Scan Name</th><th>Secrets Found</th><th>Vulnerabilities Found</th></tr>
  {"".join(
      f'<tr><td>{r[0]}</td><td class="{"red" if r[1]>0 else "green"}">{r[1]}</td>'
      f'<td class="{"red" if r[2]>0 else "green"}">{r[2]}</td></tr>'
      for r in rows
  )}
</table>
<p class="footer">Security Scanner Pro v4.0.0</p>
</body>
</html>"""

            html.write_text(html_content, encoding="utf-8")
            c.write(f"[bold #39ff14]✓ Report saved:[/] {html.name}")
            self.notify(f"Report saved: {html.name}", severity="information")
            self._list_reports()

        except Exception as e:
            c.write(f"[bold red]✖ Export error: {e}[/]")
            self.notify(f"Export failed: {e}", severity="error")

    def _open_folder(self):
        import subprocess
        output = Path("output")
        output.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", str(output.resolve())])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(output.resolve())])
            else:
                subprocess.Popen(["xdg-open", str(output.resolve())])
            self.notify(f"Opened: {output.resolve()}", severity="information")
        except FileNotFoundError:
            self.notify(f"Folder: {output.resolve()}", severity="information")
        except Exception as e:
            self.notify(f"Cannot open folder: {e}", severity="error")
    
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
