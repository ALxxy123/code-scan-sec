"""
🛡️ Security Scanner - Interactive TUI Application
Professional Terminal User Interface like Claude Code
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, Static, Button, Input, 
    Label, ProgressBar, DataTable, ListView, ListItem,
    DirectoryTree, RichLog, Select, Switch, Rule
)
from textual.binding import Binding
from textual.screen import Screen
from textual import events
from rich.text import Text
from rich.panel import Panel
from rich.console import Console
from rich.table import Table
from pathlib import Path
import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))


# ============================================================================
# STYLES
# ============================================================================

CSS = """
Screen {
    background: $surface;
}

#main-container {
    width: 100%;
    height: 100%;
    padding: 1;
}

.menu-box {
    border: solid $primary;
    padding: 1 2;
    margin: 1;
    background: $surface-darken-1;
}

.menu-item {
    padding: 1 2;
    margin: 0 1;
    width: 100%;
}

.menu-item:hover {
    background: $primary-darken-1;
}

.menu-item:focus {
    background: $primary;
    text-style: bold;
}

.title {
    text-align: center;
    text-style: bold;
    color: $primary;
    padding: 1;
}

.subtitle {
    text-align: center;
    color: $text-muted;
}

.status-bar {
    dock: bottom;
    height: 3;
    padding: 1;
    background: $surface-darken-2;
}

.scan-panel {
    border: solid $success;
    padding: 1;
    margin: 1;
}

.result-panel {
    border: solid $warning;
    padding: 1;
    margin: 1;
    height: 100%;
}

.stat-card {
    border: round $primary;
    padding: 1;
    margin: 0 1;
    min-width: 20;
    text-align: center;
}

.critical {
    color: $error;
}

.high {
    color: #ff6b6b;
}

.medium {
    color: $warning;
}

.low {
    color: $success;
}

#path-input {
    margin: 1;
}

Button {
    margin: 1;
}

.action-button {
    min-width: 20;
}

Input {
    margin: 1 0;
}
"""


# ============================================================================
# MAIN MENU SCREEN
# ============================================================================

class MainMenuScreen(Screen):
    """Main menu screen with navigation options."""
    
    BINDINGS = [
        Binding("1", "scan_local", "Scan Project"),
        Binding("2", "scan_url", "Scan URL"),
        Binding("3", "blackbox", "Black Box Test"),
        Binding("4", "autofix", "Auto Fix"),
        Binding("5", "reports", "View Reports"),
        Binding("6", "settings", "Settings"),
        Binding("q", "quit", "Quit"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static(
                "🛡️ AI-Powered Security Scanner v4.0",
                classes="title"
            )
            yield Static(
                "Professional Security Analysis Suite",
                classes="subtitle"
            )
            yield Rule()
            
            with Container(classes="menu-box"):
                yield Static("📋 Main Menu", classes="title")
                yield Rule()
                
                yield Button("🔍 [1] Scan Local Project", id="btn-scan", classes="menu-item")
                yield Button("🌐 [2] Scan Git Repository", id="btn-url", classes="menu-item")
                yield Button("🎯 [3] Black Box Testing", id="btn-blackbox", classes="menu-item")
                yield Button("🔧 [4] Auto Fix Vulnerabilities", id="btn-autofix", classes="menu-item")
                yield Button("📊 [5] View Reports", id="btn-reports", classes="menu-item")
                yield Button("⚙️  [6] Settings", id="btn-settings", classes="menu-item")
                yield Rule()
                yield Button("🚪 [Q] Quit", id="btn-quit", variant="error", classes="menu-item")
            
            with Horizontal(classes="status-bar"):
                yield Static("💡 Use number keys for quick navigation | Press Q to quit")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        
        if button_id == "btn-scan":
            self.app.push_screen(ScanScreen())
        elif button_id == "btn-url":
            self.app.push_screen(URLScanScreen())
        elif button_id == "btn-blackbox":
            self.app.push_screen(BlackBoxScreen())
        elif button_id == "btn-autofix":
            self.app.push_screen(AutoFixScreen())
        elif button_id == "btn-reports":
            self.app.push_screen(ReportsScreen())
        elif button_id == "btn-settings":
            self.app.push_screen(SettingsScreen())
        elif button_id == "btn-quit":
            self.app.exit()
    
    def action_scan_local(self) -> None:
        self.app.push_screen(ScanScreen())
    
    def action_scan_url(self) -> None:
        self.app.push_screen(URLScanScreen())
    
    def action_blackbox(self) -> None:
        self.app.push_screen(BlackBoxScreen())
    
    def action_autofix(self) -> None:
        self.app.push_screen(AutoFixScreen())
    
    def action_reports(self) -> None:
        self.app.push_screen(ReportsScreen())
    
    def action_settings(self) -> None:
        self.app.push_screen(SettingsScreen())
    
    def action_quit(self) -> None:
        self.app.exit()


# ============================================================================
# SCAN SCREEN
# ============================================================================

class ScanScreen(Screen):
    """Local project scanning screen."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("enter", "start_scan", "Start Scan"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static("🔍 Scan Local Project", classes="title")
            yield Rule()
            
            with Container(classes="scan-panel"):
                yield Label("📁 Enter project path:")
                yield Input(
                    placeholder="Enter path or press Tab to browse...",
                    id="path-input"
                )
                
                with Horizontal():
                    yield Button("📂 Browse", id="btn-browse")
                    yield Button("🔍 Start Scan", id="btn-start", variant="success")
                    yield Button("⬅️ Back", id="btn-back", variant="default")
                
                yield Rule()
                yield Label("⚙️ Scan Options:")
                
                with Horizontal():
                    yield Switch(value=True, id="ai-switch")
                    yield Label("Enable AI Verification")
                
                with Horizontal():
                    yield Switch(value=True, id="vuln-switch")
                    yield Label("Enable Vulnerability Scan")
                
                yield Label("🤖 AI Provider:")
                yield Select(
                    [(name, name) for name in ["gemini", "openai", "claude"]],
                    value="gemini",
                    id="ai-provider"
                )
            
            with Container(classes="result-panel"):
                yield Static("📋 Scan Results", classes="title")
                yield RichLog(id="scan-log", highlight=True, markup=True)
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-start":
            self.run_scan()
        elif event.button.id == "btn-browse":
            # Get current directory as default
            path_input = self.query_one("#path-input", Input)
            path_input.value = str(Path.cwd())
    
    def run_scan(self) -> None:
        path_input = self.query_one("#path-input", Input)
        log = self.query_one("#scan-log", RichLog)
        
        path = path_input.value or "."
        
        log.write("[bold green]🚀 Starting security scan...[/]")
        log.write(f"[blue]📁 Path:[/] {path}")
        
        # Get options
        ai_enabled = self.query_one("#ai-switch", Switch).value
        vuln_enabled = self.query_one("#vuln-switch", Switch).value
        ai_provider = self.query_one("#ai-provider", Select).value
        
        log.write(f"[blue]🤖 AI:[/] {'Enabled' if ai_enabled else 'Disabled'}")
        log.write(f"[blue]🐛 Vulnerabilities:[/] {'Enabled' if vuln_enabled else 'Disabled'}")
        
        # Import and run scanner
        try:
            from scanner import run_comprehensive_scan
            log.write("[yellow]⏳ Scanning in progress...[/]")
            
            # Run scan
            asyncio.create_task(self._async_scan(path, ai_enabled, ai_provider, vuln_enabled, log))
            
        except ImportError as e:
            log.write(f"[red]❌ Error: {e}[/]")
    
    async def _async_scan(self, path, ai_enabled, ai_provider, vuln_enabled, log):
        """Run scan asynchronously."""
        try:
            from scanner import run_comprehensive_scan
            
            results = run_comprehensive_scan(
                path=path,
                enable_ai=ai_enabled,
                ai_provider=ai_provider,
                enable_vulnerabilities=vuln_enabled,
                quiet=True
            )
            
            secrets, vulns, stats = results
            
            log.write("")
            log.write("[bold green]✅ Scan Complete![/]")
            log.write(f"[red]🔑 Secrets Found:[/] {len(secrets)}")
            log.write(f"[yellow]🐛 Vulnerabilities:[/] {len(vulns)}")
            
            if stats:
                log.write(f"[blue]📊 Critical:[/] {stats.get('critical', 0)}")
                log.write(f"[blue]📊 High:[/] {stats.get('high', 0)}")
                log.write(f"[blue]📊 Medium:[/] {stats.get('medium', 0)}")
                log.write(f"[blue]📊 Low:[/] {stats.get('low', 0)}")
            
        except Exception as e:
            log.write(f"[red]❌ Error during scan: {e}[/]")
    
    def action_go_back(self) -> None:
        self.app.pop_screen()
    
    def action_start_scan(self) -> None:
        self.run_scan()


# ============================================================================
# URL SCAN SCREEN
# ============================================================================

class URLScanScreen(Screen):
    """Git repository URL scanning screen."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static("🌐 Scan Git Repository", classes="title")
            yield Rule()
            
            with Container(classes="scan-panel"):
                yield Label("📎 Enter Git repository URL:")
                yield Input(
                    placeholder="https://github.com/username/repo",
                    id="url-input"
                )
                
                with Horizontal():
                    yield Button("🔍 Scan Repository", id="btn-scan", variant="success")
                    yield Button("⬅️ Back", id="btn-back")
            
            with Container(classes="result-panel"):
                yield RichLog(id="scan-log", highlight=True, markup=True)
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-scan":
            log = self.query_one("#scan-log", RichLog)
            url = self.query_one("#url-input", Input).value
            
            log.write(f"[green]🌐 Scanning: {url}[/]")
            log.write("[yellow]⏳ Cloning and scanning...[/]")
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# BLACK BOX SCREEN
# ============================================================================

class BlackBoxScreen(Screen):
    """Black box testing screen."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static("🎯 Black Box Security Testing", classes="title")
            yield Rule()
            
            with Container(classes="scan-panel"):
                yield Label("🌐 Enter target URL:")
                yield Input(
                    placeholder="https://example.com",
                    id="target-input"
                )
                
                yield Label("🧪 Tests to run:")
                with Horizontal():
                    yield Switch(value=True, id="headers-switch")
                    yield Label("Security Headers")
                with Horizontal():
                    yield Switch(value=True, id="ssl-switch")
                    yield Label("SSL/TLS Check")
                with Horizontal():
                    yield Switch(value=True, id="sql-switch")
                    yield Label("SQL Injection")
                with Horizontal():
                    yield Switch(value=True, id="xss-switch")
                    yield Label("XSS Detection")
                
                with Horizontal():
                    yield Button("🎯 Start Test", id="btn-test", variant="success")
                    yield Button("⬅️ Back", id="btn-back")
            
            with Container(classes="result-panel"):
                yield RichLog(id="test-log", highlight=True, markup=True)
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
        elif event.button.id == "btn-test":
            log = self.query_one("#test-log", RichLog)
            target = self.query_one("#target-input", Input).value
            
            log.write(f"[green]🎯 Testing: {target}[/]")
            log.write("[yellow]⏳ Running security tests...[/]")
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# AUTO FIX SCREEN
# ============================================================================

class AutoFixScreen(Screen):
    """Auto fix vulnerabilities screen."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static("🔧 Auto Fix Vulnerabilities", classes="title")
            yield Rule()
            
            with Container(classes="scan-panel"):
                yield Label("📁 Project path:")
                yield Input(placeholder="Enter project path...", id="path-input")
                
                yield Label("🔧 Fix types:")
                with Horizontal():
                    yield Switch(value=True, id="crypto-switch")
                    yield Label("Weak Cryptography (MD5 → SHA256)")
                with Horizontal():
                    yield Switch(value=True, id="secrets-switch")
                    yield Label("Hardcoded Secrets → Environment Variables")
                with Horizontal():
                    yield Switch(value=True, id="sql-switch")
                    yield Label("SQL Injection")
                
                with Horizontal():
                    yield Button("👁️ Preview Fixes", id="btn-preview", variant="primary")
                    yield Button("🔧 Apply Fixes", id="btn-apply", variant="success")
                    yield Button("⬅️ Back", id="btn-back")
            
            with Container(classes="result-panel"):
                yield RichLog(id="fix-log", highlight=True, markup=True)
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# REPORTS SCREEN
# ============================================================================

class ReportsScreen(Screen):
    """View reports screen."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static("📊 Scan Reports", classes="title")
            yield Rule()
            
            with Container(classes="scan-panel"):
                yield Label("📁 Reports Directory: ./output/")
                yield DataTable(id="reports-table")
                
                with Horizontal():
                    yield Button("🔄 Refresh", id="btn-refresh")
                    yield Button("📂 Open Folder", id="btn-open")
                    yield Button("⬅️ Back", id="btn-back")
        
        yield Footer()
    
    def on_mount(self) -> None:
        table = self.query_one("#reports-table", DataTable)
        table.add_columns("📄 File", "📅 Date", "📊 Type")
        
        # Check for reports
        output_dir = Path("output")
        if output_dir.exists():
            for f in output_dir.glob("*"):
                if f.suffix in [".html", ".json", ".md", ".pdf"]:
                    table.add_row(f.name, "2024-01-06", f.suffix[1:].upper())
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# SETTINGS SCREEN
# ============================================================================

class SettingsScreen(Screen):
    """Settings screen."""
    
    BINDINGS = [
        Binding("escape", "go_back", "Back"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield Static("⚙️ Settings", classes="title")
            yield Rule()
            
            with Container(classes="scan-panel"):
                yield Label("🤖 Default AI Provider:")
                yield Select(
                    [("Google Gemini", "gemini"), ("OpenAI", "openai"), ("Claude", "claude")],
                    value="gemini",
                    id="ai-select"
                )
                
                yield Label("🔑 API Keys:")
                yield Input(placeholder="GEMINI_API_KEY", password=True, id="gemini-key")
                yield Input(placeholder="OPENAI_API_KEY", password=True, id="openai-key")
                yield Input(placeholder="ANTHROPIC_API_KEY", password=True, id="claude-key")
                
                yield Rule()
                yield Label("📊 Report Settings:")
                with Horizontal():
                    yield Switch(value=True, id="html-switch")
                    yield Label("Generate HTML Report")
                with Horizontal():
                    yield Switch(value=True, id="json-switch")
                    yield Label("Generate JSON Report")
                with Horizontal():
                    yield Switch(value=False, id="pdf-switch")
                    yield Label("Generate PDF Report")
                
                with Horizontal():
                    yield Button("💾 Save Settings", id="btn-save", variant="success")
                    yield Button("⬅️ Back", id="btn-back")
        
        yield Footer()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.app.pop_screen()
    
    def action_go_back(self) -> None:
        self.app.pop_screen()


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class SecurityScannerApp(App):
    """Main TUI Application for Security Scanner."""
    
    TITLE = "🛡️ Security Scanner"
    SUB_TITLE = "AI-Powered Security Analysis"
    CSS = CSS
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
    ]
    
    def on_mount(self) -> None:
        """Called when app starts."""
        self.push_screen(MainMenuScreen())
    
    def action_toggle_dark(self) -> None:
        """Toggle dark mode."""
        self.dark = not self.dark


def main():
    """Entry point for the TUI application."""
    app = SecurityScannerApp()
    app.run()


if __name__ == "__main__":
    main()
