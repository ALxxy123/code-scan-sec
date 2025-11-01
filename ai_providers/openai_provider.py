import os
import time
from openai import OpenAI
from rich.console import Console
from .base_provider import BaseAIProvider

console = Console()

class OpenAIProvider(BaseAIProvider):
    """
    AI provider implementation for OpenAI (ChatGPT).
    Handles initialization and secret verification through OpenAI API.
    """

    def initialize(self):
        """
        Initialize and configure the OpenAI API.
        Loads the API key from environment variables and creates the client instance.
        """
        self.api_key = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            console.print("[bold yellow]Warning: OPENAI_API_KEY is not set. OpenAI verification will be skipped.[/bold yellow]")
            return False

        try:
            self.client = OpenAI(api_key=self.api_key)
            console.print("[bold green]OpenAI (ChatGPT) provider is ENABLED.[/bold green]")
            return True
        except Exception as e:
            console.print(f"[bold red]Error configuring OpenAI: {e}. Disabling AI.[/bold red]")
            return False

    def verify(self, match_text: str) -> bool:
        """
        Verify a string using the OpenAI ChatGPT API.
        Returns True if it's identified as a secret, False if safe.
        """
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a secret verifier. Respond ONLY with the word 'Yes' or 'No'."
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this string. Is it a secret (API key, token, password)? String: '{match_text}'"
                    }
                ],
                max_tokens=2,
                temperature=0
            )

            answer = response.choices[0].message.content.strip().lower()

            if "yes" in answer:
                console.print(f"[AI-OpenAI] Verdict: [bold red]SECRET[/bold red] -> {match_text[:20]}...")
                return True
            else:
                console.print(f"[AI-OpenAI] Verdict: [bold green]SAFE[/bold green] -> {match_text[:20]}...")
                return False

        except Exception as e:
            console.print(f"[bold red]OpenAI Error: {e}[/bold red]")
            return True  # Safe fallback on failure
