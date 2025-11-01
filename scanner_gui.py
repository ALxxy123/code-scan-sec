import customtkinter as ctk
import subprocess
import threading
import sys
import json

SCANNER_SCRIPT_PATH = "scanner.py"
PYTHON_PATH = sys.executable 
selected_folder = "." 

def select_folder():
    global selected_folder
    path = ctk.filedialog.askdirectory() 
    if path:
        selected_folder = path
        folder_label.configure(text=f"Selected: {selected_folder}")
        # (تم حذف سطر console.print الخاطئ من هنا)

def start_scan():
    folder_button.configure(state="disabled")
    scan_button.configure(state="disabled")

    text_box.configure(state="normal")
    text_box.delete("1.0", "end")
    text_box.insert("end", f"Starting scan on: {selected_folder}\n")
    text_box.insert("end", "This may take a moment (AI verification is running)...\n\n")

    scan_thread = threading.Thread(target=run_scan_in_thread, daemon=True)
    scan_thread.start()

def run_scan_in_thread():
    global selected_folder

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

        with open("output/results.json", "r") as f:
            findings = json.load(f)

        if not findings:
            app.after(10, lambda: text_box.insert("end", "--- SCAN COMPLETE ---\nNo secrets found. Your code is clean! ✨"))
        else:
            app.after(10, lambda: text_box.insert("end", f"--- SCAN COMPLETE ---\nFound {len(findings)} VERIFIED secrets!\n\n"))

            # --- (هنا الإصلاح) ---
            # (تم حذف خيار "font" من السطر التالي)
            app.after(10, lambda: text_box.tag_config("header", foreground="#3498db"))
            app.after(10, lambda: text_box.tag_config("file", foreground="#00FFFF")) # Cyan
            app.after(10, lambda: text_box.tag_config("secret", foreground="#E74C3C")) # Red

            app.after(10, lambda: text_box.insert("end", f"{'File':<40} {'Line':<5} {'Match':<50}\n", "header"))
            app.after(10, lambda: text_box.insert("end", f"{'-'*40:<40} {'-'*5:<5} {'-'*50:<50}\n", "header"))

            for finding in findings:
                file_line = f"{finding['file']}:{finding['line']}"
                match_text = finding['match']

                app.after(10, lambda f=file_line, m=match_text: (
                    text_box.insert("end", f"{f:<45}", "file"),
                    text_box.insert("end", f"{m:<50}\n", "secret")
                ))

    except Exception as e:
        app.after(10, lambda: text_box.insert("end", f"\n--- SCAN FAILED ---\nError: {e}"))

    app.after(10, lambda: folder_button.configure(state="normal"))
    app.after(10, lambda: scan_button.configure(state="normal"))
    app.after(10, lambda: text_box.configure(state="disabled"))

# --- إعدادات النافذة الرئيسية ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
app = ctk.CTk()
app.title("Security Scan (GUI)")
app.geometry("900x600")

# --- إضافة العناصر (Widgets) ---
top_frame = ctk.CTkFrame(app)
top_frame.pack(pady=10, padx=20, fill="x")

folder_button = ctk.CTkButton(top_frame, text="Select Folder", command=select_folder)
folder_button.pack(side="left", padx=10, pady=10)

folder_label = ctk.CTkLabel(top_frame, text="Selected: . (Current Folder)")
folder_label.pack(side="left", padx=10)

scan_button = ctk.CTkButton(top_frame, text="Start Scan", command=start_scan, fg_color="green")
scan_button.pack(side="right", padx=10, pady=10)

text_box = ctk.CTkTextbox(app, font=("Consolas", 14), state="disabled")
text_box.pack(pady=10, padx=20, fill="both", expand=True)

app.mainloop()
