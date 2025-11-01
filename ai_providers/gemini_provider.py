import os
import time
import re # (جديد) لاستخلاص وقت الانتظار
import google.generativeai as genai
from rich.console import Console
from .base_provider import BaseAIProvider

console = Console()

class GeminiProvider(BaseAIProvider):

    def initialize(self, quiet: bool = False):
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            if not quiet: console.print("[bold yellow]Warning: GEMINI_API_KEY is not set. Gemini AI verification will be skipped.[/bold yellow]")
            return False

        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('models/gemini-flash-latest')
            if not quiet: console.print("[bold green]Gemini AI provider is ENABLED.[/bold green]")
            return True
        except Exception as e:
            if not quiet: console.print(f"[bold red]Error configuring Gemini AI: {e}. Disabling AI.[/bold red]")
            return False

    # --- (هنا الترقية) ---
    def verify(self, match_text: str, quiet: bool = False) -> bool:
        max_retries = 5 # زيادة عدد المحاولات

        for attempt in range(max_retries):
            try:
                prompt = (
                    "Analyze the following string. Is it a secret like an API key, token, or password? "
                    "Respond ONLY with the word 'Yes' or 'No'. String: "
                    f"'{match_text}'"
                )
                response = self.model.generate_content(prompt)
                answer = response.text.strip().lower()

                if "yes" in answer:
                    if not quiet: console.print(f"[AI-Gemini] Verdict: [bold red]SECRET[/bold red] -> {match_text[:20]}...")
                    return True
                else:
                    if not quiet: console.print(f"[AI-Gemini] Verdict: [bold green]SAFE[/bold green] -> {match_text[:20]}...")
                    return False

            except Exception as e:
                error_message = str(e)

                # (جديد) منطق ذكي لقراءة مدة الانتظار
                if "429" in error_message and "Please retry in" in error_message:
                    try:
                        # استخلاص عدد الثواني من رسالة الخطأ
                        wait_time_match = re.search(r"Please retry in (\d+\.\d+)s", error_message)
                        if wait_time_match:
                            wait_time = float(wait_time_match.group(1)) + 1.0 # إضافة ثانية احتياط
                            if not quiet: console.print(f"[AI-WARN] Attempt {attempt + 1}/{max_retries} failed (Rate Limit). Retrying in {wait_time:.0f}s...")
                            time.sleep(wait_time) # الانتظار للمدة المطلوبة
                        else:
                            raise ValueError("Could not parse wait time")
                    except Exception:
                        # إذا فشل الاستخلاص، انتظر 60 ثانية (الحد الأقصى للخطط المجانية)
                        if not quiet: console.print(f"[AI-WARN] Attempt {attempt + 1}/{max_retries} failed (Rate Limit). Retrying in 60s...")
                        time.sleep(60)
                else:
                    if not quiet: console.print(f"[bold red]AI Error (Non-retriable): {e}[/bold red]")
                    return True # الأمان عند الفشل

        if not quiet: console.print(f"[bold red]AI Error: All {max_retries} retries failed for {match_text[:20]}...[/bold red]")
        return True
