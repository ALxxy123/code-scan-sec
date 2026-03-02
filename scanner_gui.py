"""
Enhanced Beautiful GUI for Security Scanner
Now with modern design, statistics, and professional appearance
"""

import customtkinter as ctk
import subprocess
import threading
import sys
import json
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk

SCANNER_SCRIPT_PATH = "scanner.py"
PYTHON_PATH = sys.executable
selected_folder = "."

# Color scheme - Professional and modern
COLORS = {
    'primary': '#667eea',
    'secondary': '#764ba2',
    'success': '#27ae60',
    'danger': '#e74c3c',
    'warning': '#f39c12',
    'info': '#3498db',
    'dark': '#2c3e50',
    'light': '#ecf0f1',
    'bg_dark': '#1a1a2e',
    'bg_light': '#f8f9fa'
}

class ModernSecurityScannerGUI:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("🛡️ AI-Powered Security Scanner v3.1")
        self.app.geometry("1200x800")

        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Statistics
        self.stats = {
            'total_scans': 0,
            'secrets_found': 0,
            'vulnerabilities': 0,
            'files_scanned': 0
        }

        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI"""
        # Main container
        self.main_container = ctk.CTkFrame(self.app, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Header
        self.create_header()

        # Statistics Dashboard
        self.create_stats_dashboard()

        # Control Panel
        self.create_control_panel()

        # Results Area
        self.create_results_area()

        # Footer
        self.create_footer()

    def create_header(self):
        """Create beautiful header"""
        header_frame = ctk.CTkFrame(self.main_container,
                                    fg_color=(COLORS['primary'], COLORS['secondary']),
                                    corner_radius=15)
        header_frame.pack(fill="x", pady=(0, 15))

        # Title with gradient effect
        title_label = ctk.CTkLabel(
            header_frame,
            text="🛡️ AI-Powered Security Scanner",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color="white"
        )
        title_label.pack(pady=(20, 5))

        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="Advanced Vulnerability & Secret Detection with Auto-Fix",
            font=ctk.CTkFont(size=14),
            text_color="#e0e0e0"
        )
        subtitle_label.pack(pady=(0, 20))

    def create_stats_dashboard(self):
        """Create statistics dashboard"""
        stats_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 15))

        # Create 4 stat cards
        self.stat_cards = {}

        stats_config = [
            ('total_scans', '📊 Total Scans', COLORS['info']),
            ('secrets_found', '🔑 Secrets Found', COLORS['danger']),
            ('vulnerabilities', '🐛 Vulnerabilities', COLORS['warning']),
            ('files_scanned', '📂 Files Scanned', COLORS['success'])
        ]

        for i, (key, label, color) in enumerate(stats_config):
            card = self.create_stat_card(stats_frame, label, "0", color)
            card.grid(row=0, column=i, padx=10, sticky="ew")
            stats_frame.grid_columnconfigure(i, weight=1)
            self.stat_cards[key] = card

    def create_stat_card(self, parent, title, value, color):
        """Create a single stat card"""
        card = ctk.CTkFrame(parent, fg_color=color, corner_radius=12)

        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color="white"
        )
        value_label.pack(pady=(15, 5))

        title_label = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color="white"
        )
        title_label.pack(pady=(0, 15))

        # Store value label for updates
        card.value_label = value_label
        return card

    def update_stat_card(self, key, value):
        """Update stat card value"""
        if key in self.stat_cards:
            self.stat_cards[key].value_label.configure(text=str(value))

    def create_control_panel(self):
        """Create control panel"""
        control_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        control_frame.pack(fill="x", pady=(0, 15))

        # Title
        ctk.CTkLabel(
            control_frame,
            text="🔍 Scan Configuration",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10), padx=20, anchor="w")

        # Path selection row
        path_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        path_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            path_frame,
            text="📁 Scan Path:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left", padx=(0, 10))

        self.folder_label = ctk.CTkLabel(
            path_frame,
            text=". (Current Folder)",
            font=ctk.CTkFont(size=13),
            text_color=COLORS['info']
        )
        self.folder_label.pack(side="left", padx=10)

        self.folder_button = ctk.CTkButton(
            path_frame,
            text="Select Folder",
            command=self.select_folder,
            width=120,
            fg_color=COLORS['info'],
            hover_color=COLORS['primary']
        )
        self.folder_button.pack(side="right", padx=5)

        # Options row
        options_frame = ctk.CTkFrame(control_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=10)

        self.ai_check = ctk.CTkCheckBox(
            options_frame,
            text="🤖 Enable AI Verification",
            font=ctk.CTkFont(size=13)
        )
        self.ai_check.pack(side="left", padx=10)
        self.ai_check.select()

        self.vuln_check = ctk.CTkCheckBox(
            options_frame,
            text="🐛 Scan Vulnerabilities",
            font=ctk.CTkFont(size=13)
        )
        self.vuln_check.pack(side="left", padx=10)
        self.vuln_check.select()

        # AI Provider selection
        self.ai_provider_var = tk.StringVar(value="gemini")
        ai_menu = ctk.CTkOptionMenu(
            options_frame,
            values=["gemini", "openai", "claude"],
            variable=self.ai_provider_var,
            width=150
        )
        ai_menu.pack(side="left", padx=10)

        # Scan button
        self.scan_button = ctk.CTkButton(
            control_frame,
            text="🚀 Start Security Scan",
            command=self.start_scan,
            height=45,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLORS['success'],
            hover_color="#229954"
        )
        self.scan_button.pack(fill="x", padx=20, pady=(5, 15))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(control_frame, height=8)
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 15))
        self.progress_bar.set(0)

    def create_results_area(self):
        """Create results display area"""
        results_frame = ctk.CTkFrame(self.main_container, corner_radius=15)
        results_frame.pack(fill="both", expand=True, pady=(0, 10))

        # Title
        ctk.CTkLabel(
            results_frame,
            text="📋 Scan Results",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 10), padx=20, anchor="w")

        # Results textbox
        self.text_box = ctk.CTkTextbox(
            results_frame,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            state="disabled"
        )
        self.text_box.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Configure tags for colored output
        self.text_box.tag_config("header", foreground=COLORS['info'])
        self.text_box.tag_config("success", foreground=COLORS['success'])
        self.text_box.tag_config("danger", foreground=COLORS['danger'])
        self.text_box.tag_config("warning", foreground=COLORS['warning'])
        self.text_box.tag_config("file", foreground="#00FFFF")
        self.text_box.tag_config("bold", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"))

    def create_footer(self):
        """Create footer"""
        footer_frame = ctk.CTkFrame(self.main_container, fg_color="transparent", height=30)
        footer_frame.pack(fill="x")

        status_label = ctk.CTkLabel(
            footer_frame,
            text="✅ Ready to scan | Version 3.1.0",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        status_label.pack(side="left")

        time_label = ctk.CTkLabel(
            footer_frame,
            text=f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        time_label.pack(side="right")

    def select_folder(self):
        """Select folder to scan"""
        global selected_folder
        path = ctk.filedialog.askdirectory()
        if path:
            selected_folder = path
            self.folder_label.configure(text=path)

    def start_scan(self):
        """Start the security scan"""
        self.scan_button.configure(state="disabled", text="⏳ Scanning...")
        self.folder_button.configure(state="disabled")
        self.progress_bar.set(0)

        # Clear results
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", "end")

        # Add header
        self.insert_text("═" * 100 + "\n", "header")
        self.insert_text("🛡️  SECURITY SCAN INITIATED  🛡️\n", "header", "bold")
        self.insert_text("═" * 100 + "\n\n", "header")
        self.insert_text(f"📁 Target: {selected_folder}\n", "file")
        self.insert_text(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "file")
        self.insert_text(f"🤖 AI Provider: {self.ai_provider_var.get().upper()}\n\n", "file")
        self.insert_text("⏳ Scanning in progress...\n\n", "warning")

        self.text_box.configure(state="disabled")

        # Start scan in thread
        scan_thread = threading.Thread(target=self.run_scan_in_thread, daemon=True)
        scan_thread.start()

    def run_scan_in_thread(self):
        """Run scan in background thread"""
        global selected_folder

        # Simulate progress
        for i in range(0, 100, 10):
            self.app.after(i * 20, lambda v=i/100: self.progress_bar.set(v))

        command = [
            PYTHON_PATH,
            SCANNER_SCRIPT_PATH,
            "scan",
            "-p", selected_folder,
            "-o", "json",
            "--quiet"
        ]

        try:
            process = subprocess.run(command,
                                   capture_output=True,
                                   text=True,
                                   encoding='utf-8')

            # Try to read results
            results_file = Path("output/results.json")
            if results_file.exists():
                with open(results_file, "r") as f:
                    findings = json.load(f)

                # Update statistics
                self.stats['total_scans'] += 1
                self.stats['secrets_found'] += len(findings)

                # Update UI
                self.app.after(10, lambda: self.show_results(findings))
            else:
                self.app.after(10, lambda: self.show_error("Results file not found"))

        except Exception as e:
            self.app.after(10, lambda: self.show_error(str(e)))

        finally:
            self.app.after(10, self.scan_complete)

    def show_results(self, findings):
        """Display scan results"""
        self.text_box.configure(state="normal")

        self.insert_text("\n" + "═" * 100 + "\n", "header")
        self.insert_text("✅  SCAN COMPLETE  ✅\n", "success", "bold")
        self.insert_text("═" * 100 + "\n\n", "header")

        if not findings:
            self.insert_text("🎉 EXCELLENT! No secrets found. Your code is clean!\n\n", "success")
        else:
            self.insert_text(f"⚠️  Found {len(findings)} potential secrets!\n\n", "warning", "bold")

            # Display findings in a table
            self.insert_text(f"{'File':<50} {'Line':<8} {'Match':<60}\n", "header", "bold")
            self.insert_text("─" * 120 + "\n", "header")

            for finding in findings[:20]:  # Limit to 20 results
                file_path = finding.get('file', 'N/A')[:48]
                line_num = str(finding.get('line', 'N/A'))
                match_text = finding.get('match', 'N/A')[:58]

                self.insert_text(f"{file_path:<50} ", "file")
                self.insert_text(f"{line_num:<8} ", "warning")
                self.insert_text(f"{match_text:<60}\n", "danger")

            if len(findings) > 20:
                self.insert_text(f"\n... and {len(findings) - 20} more findings\n", "warning")

        # Update stats
        self.update_stat_card('total_scans', self.stats['total_scans'])
        self.update_stat_card('secrets_found', self.stats['secrets_found'])

        self.text_box.configure(state="disabled")
        self.progress_bar.set(1.0)

    def show_error(self, error_msg):
        """Display error message"""
        self.text_box.configure(state="normal")
        self.insert_text("\n" + "═" * 100 + "\n", "header")
        self.insert_text("❌  SCAN FAILED  ❌\n", "danger", "bold")
        self.insert_text("═" * 100 + "\n\n", "header")
        self.insert_text(f"Error: {error_msg}\n", "danger")
        self.text_box.configure(state="disabled")

    def scan_complete(self):
        """Reset UI after scan complete"""
        self.scan_button.configure(state="normal", text="🚀 Start Security Scan")
        self.folder_button.configure(state="normal")

    def insert_text(self, text, *tags):
        """Insert text with tags"""
        self.text_box.insert("end", text, tags)

    def run(self):
        """Run the application"""
        self.app.mainloop()

# Run the application
if __name__ == "__main__":
    gui = ModernSecurityScannerGUI()
    gui.run()
