"""
Hugging Face AI Provider for Security Scanning.

Uses free Hugging Face Inference API with specialized security models:
- CodeAstra-7b: 83% accuracy in vulnerability detection
- Foundation-Sec-8B: Cybersecurity specialized model
- CodeBERT: Fast, lightweight code classification

Free tier: 30,000 requests/month
"""

import os
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from .base_provider import BaseAIProvider

console = Console()

# Available security-focused models (free on HF Inference API)
MODELS = {
    "codeastra": "saimanoj/CodeAstra-7b",
    "foundation-sec": "fdtn-ai/Foundation-Sec-8B", 
    "codebert": "microsoft/codebert-base",
    "codellama": "codellama/CodeLlama-7b-Instruct-hf",
    "starcoder": "bigcode/starcoder2-3b",
}

DEFAULT_MODEL = "codellama"  # Good balance of speed and accuracy


class HuggingFaceProvider(BaseAIProvider):
    """
    Hugging Face Inference API provider for security analysis.
    
    Features:
    - Free tier with 30K requests/month
    - Multiple model options
    - Automatic rate limit handling
    - Fallback to simpler models if needed
    """
    
    def __init__(self, model_name: str = DEFAULT_MODEL):
        self.model_name = model_name
        self.model_id = MODELS.get(model_name, MODELS[DEFAULT_MODEL])
        self.api_url = f"https://api-inference.huggingface.co/models/{self.model_id}"
        self.headers = {}
        self.initialized = False
    
    def initialize(self, quiet: bool = False) -> bool:
        """Initialize with HF_TOKEN from environment or .env file."""
        # Try to load from .env file if exists
        env_file = Path(__file__).parent.parent / ".env"
        if env_file.exists():
            try:
                for line in env_file.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        if key.strip() not in os.environ:
                            os.environ[key.strip()] = value.strip()
            except:
                pass
        
        token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")

        
        if not token:
            if not quiet:
                console.print("[bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]")
                console.print("[bold yellow]⚠ AI Verification Disabled (No HF_TOKEN found)[/bold yellow]")
                console.print("[dim]The scanner will work but without AI-powered verification.[/dim]")
                console.print("")
                console.print("[cyan]To enable FREE AI verification:[/cyan]")
                console.print("  1. Visit: [link=https://huggingface.co/settings/tokens]https://huggingface.co/settings/tokens[/link]")
                console.print("  2. Create a free account & generate token")
                console.print("  3. Add to .env file: HF_TOKEN=hf_your_token")
                console.print("[bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold yellow]")
            return False

        
        self.headers = {"Authorization": f"Bearer {token}"}
        self.initialized = True
        
        if not quiet:
            console.print(f"[bold green]✓ Hugging Face AI enabled[/bold green] [dim]({self.model_name})[/dim]")
        
        return True
    
    def verify(self, match_text: str, quiet: bool = False) -> bool:
        """
        Verify if text contains a real secret using AI.
        
        Returns:
            True if it's likely a real secret
            False if it's safe/placeholder
        """
        if not self.initialized:
            return True  # Assume secret if AI not available
        
        prompt = self._build_prompt(match_text)
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self._query(prompt)
                
                if response is None:
                    return True  # Fail-safe
                
                # Parse response
                answer = self._parse_response(response)
                
                if not quiet:
                    verdict = "[bold red]SECRET[/]" if answer else "[bold green]SAFE[/]"
                    console.print(f"[AI-HF] {verdict} → {match_text[:30]}...")
                
                return answer
                
            except Exception as e:
                error_msg = str(e)
                
                # Rate limit handling
                if "rate limit" in error_msg.lower() or "503" in error_msg:
                    wait_time = 10 * (attempt + 1)
                    if not quiet:
                        console.print(f"[AI-WARN] Rate limit, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                
                # Model loading
                if "loading" in error_msg.lower():
                    if not quiet:
                        console.print("[AI-INFO] Model loading, waiting 20s...")
                    time.sleep(20)
                    continue
                
                if not quiet:
                    console.print(f"[bold red]AI Error: {e}[/bold red]")
                return True  # Fail-safe
        
        return True  # Fail-safe after retries
    
    def _build_prompt(self, text: str) -> str:
        """Build security analysis prompt."""
        return f"""Analyze this code snippet for security issues.

Is this a real secret (API key, password, token) or a placeholder/example?

Code: {text[:500]}

Answer with ONLY 'SECRET' or 'SAFE'. Nothing else."""
    
    def _query(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Query HF Inference API."""
        import requests
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 10,
                "temperature": 0.1,
                "return_full_text": False,
            }
        }
        
        response = requests.post(
            self.api_url,
            headers=self.headers,
            json=payload,
            timeout=60
        )
        
        if response.status_code == 503:
            # Model loading
            raise Exception("Model is loading")
        
        if response.status_code == 429:
            raise Exception("Rate limit exceeded")
        
        if response.status_code != 200:
            raise Exception(f"API error: {response.status_code}")
        
        return response.json()
    
    def _parse_response(self, response: Any) -> bool:
        """Parse API response to determine if secret."""
        if isinstance(response, list) and len(response) > 0:
            text = response[0].get("generated_text", "").lower()
        elif isinstance(response, dict):
            text = response.get("generated_text", "").lower()
        else:
            text = str(response).lower()
        
        # Check for secret indicators
        secret_indicators = ["secret", "yes", "real", "valid", "genuine", "true"]
        safe_indicators = ["safe", "no", "fake", "placeholder", "example", "false"]
        
        for indicator in secret_indicators:
            if indicator in text:
                return True
        
        for indicator in safe_indicators:
            if indicator in text:
                return False
        
        return True  # Default to treating as secret (fail-safe)
    
    def analyze_code(self, code: str, quiet: bool = False) -> Dict[str, Any]:
        """
        Perform deeper code analysis for vulnerabilities.
        
        Returns dict with:
        - vulnerabilities: list of found issues
        - risk_level: low/medium/high/critical
        - suggestions: list of fixes
        """
        if not self.initialized:
            return {"error": "AI not initialized", "vulnerabilities": []}
        
        prompt = f"""Analyze this code for security vulnerabilities.

Code:
```
{code[:2000]}
```

List any security issues found. Format as JSON:
{{"vulnerabilities": ["issue1", "issue2"], "risk_level": "low|medium|high|critical"}}"""
        
        try:
            response = self._query(prompt)
            if response:
                text = response[0].get("generated_text", "") if isinstance(response, list) else str(response)
                # Try to parse JSON from response
                try:
                    # Find JSON in response
                    import re
                    json_match = re.search(r'\{.*\}', text, re.DOTALL)
                    if json_match:
                        return json.loads(json_match.group())
                except:
                    pass
                return {"raw_analysis": text, "vulnerabilities": []}
        except Exception as e:
            if not quiet:
                console.print(f"[bold red]Analysis error: {e}[/bold red]")
            return {"error": str(e), "vulnerabilities": []}

        return {"vulnerabilities": []}


def get_available_models() -> Dict[str, str]:
    """Return available model options."""
    return MODELS.copy()
