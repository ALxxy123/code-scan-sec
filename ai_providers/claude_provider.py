"""
Claude AI Provider for secret verification.

Uses Anthropic's Claude API to verify if detected patterns are actually secrets.
"""

import os
import time
import re
from typing import Optional
from ai_providers.base_provider import BaseAIProvider


class ClaudeProvider(BaseAIProvider):
    """
    Claude AI provider implementation.

    Uses Anthropic's Claude API to verify secrets with high accuracy.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        """
        Initialize Claude provider.

        Args:
            api_key: Anthropic API key (if None, reads from ANTHROPIC_API_KEY env var)
            model: Claude model to use
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.client = None

    def initialize(self) -> bool:
        """
        Initialize Claude API client.

        Returns:
            bool: True if initialization successful, False otherwise
        """
        if not self.api_key:
            print("[yellow]⚠ ANTHROPIC_API_KEY not found in environment[/yellow]")
            return False

        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
            return True
        except ImportError:
            print("[red]✗ anthropic package not installed. Install with: pip install anthropic[/red]")
            return False
        except Exception as e:
            print(f"[red]✗ Failed to initialize Claude: {e}[/red]")
            return False

    def verify(self, match_text: str, max_retries: int = 5) -> bool:
        """
        Verify if matched text is actually a secret using Claude.

        Args:
            match_text: The text to verify
            max_retries: Maximum number of retry attempts

        Returns:
            bool: True if it's a real secret, False otherwise
        """
        if not self.client:
            return False

        prompt = f"""Is this a real secret/API key/password or just a placeholder/example?
Text: {match_text}

Reply with ONLY 'Yes' if it's a real secret, or 'No' if it's just a placeholder/example."""

        for attempt in range(max_retries):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=10,
                    temperature=0.0,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )

                # Extract response text
                answer = response.content[0].text.strip().lower()

                # Check if response contains 'yes' or 'no'
                if 'yes' in answer:
                    return True
                elif 'no' in answer:
                    return False
                else:
                    # Ambiguous response, retry
                    if attempt < max_retries - 1:
                        time.sleep(1)
                        continue
                    return False

            except Exception as e:
                error_message = str(e)

                # Check for rate limit errors
                if 'rate_limit' in error_message.lower() or '429' in error_message:
                    # Extract retry-after time if available
                    retry_match = re.search(r'retry after (\d+)', error_message, re.IGNORECASE)
                    if retry_match:
                        wait_time = int(retry_match.group(1))
                    else:
                        # Exponential backoff: 2^attempt seconds
                        wait_time = 2 ** attempt

                    if attempt < max_retries - 1:
                        print(f"[yellow]⚠ Rate limit hit, waiting {wait_time}s...[/yellow]")
                        time.sleep(wait_time)
                        continue

                # Check for overloaded errors
                elif 'overloaded' in error_message.lower() or '529' in error_message:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        print(f"[yellow]⚠ Claude overloaded, waiting {wait_time}s...[/yellow]")
                        time.sleep(wait_time)
                        continue

                # Other errors
                print(f"[red]✗ Claude API error: {e}[/red]")
                return False

        return False
