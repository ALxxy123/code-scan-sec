"""
Update Checker Module for Security Scan CLI
Check for new versions and notify users
"""

import requests
from typing import Optional, Dict, Tuple
from packaging import version
import json
from pathlib import Path
from datetime import datetime, timedelta


class UpdateChecker:
    """
    Check for updates to the Security Scan CLI tool.

    Features:
    - Check PyPI for latest version
    - Check GitHub releases
    - Cache check results to avoid rate limiting
    - Provide upgrade instructions
    """

    def __init__(
        self,
        current_version: str = "4.0.0",
        package_name: str = "security-scan-cli",
        github_repo: str = "security-scan/cli",
        cache_duration_hours: int = 24
    ):
        """
        Initialize update checker.

        Args:
            current_version: Current installed version
            package_name: Package name on PyPI
            github_repo: GitHub repository in format "owner/repo"
            cache_duration_hours: How long to cache check results
        """
        self.current_version = current_version
        self.package_name = package_name
        self.github_repo = github_repo
        self.cache_duration = timedelta(hours=cache_duration_hours)
        self.cache_file = Path.home() / ".security-scan" / "update_cache.json"
        self.cache_file.parent.mkdir(exist_ok=True)

    def check_for_updates(self, force: bool = False) -> Optional[Dict]:
        """
        Check for available updates.

        Args:
            force: Force check even if cache is valid

        Returns:
            Dictionary with update information or None if no update available
        """
        # Check cache first
        if not force:
            cached_result = self._load_cache()
            if cached_result:
                return cached_result

        # Try PyPI first
        pypi_result = self._check_pypi()
        if pypi_result:
            self._save_cache(pypi_result)
            return pypi_result

        # Fallback to GitHub releases
        github_result = self._check_github()
        if github_result:
            self._save_cache(github_result)
            return github_result

        return None

    def _check_pypi(self) -> Optional[Dict]:
        """Check PyPI for the latest version"""
        try:
            url = f"https://pypi.org/pypi/{self.package_name}/json"
            response = requests.get(url, timeout=5)
            response.raise_for_status()

            data = response.json()
            latest_version = data["info"]["version"]

            if self._is_newer_version(latest_version):
                return {
                    "update_available": True,
                    "current_version": self.current_version,
                    "latest_version": latest_version,
                    "release_date": data["urls"][0]["upload_time"] if data["urls"] else None,
                    "source": "PyPI",
                    "download_url": f"https://pypi.org/project/{self.package_name}/{latest_version}/",
                    "upgrade_command": f"pip install --upgrade {self.package_name}",
                    "release_notes": data["info"]["description"][:500] if data["info"].get("description") else None
                }

        except Exception as e:
            # Silently fail - update checking is not critical
            pass

        return None

    def _check_github(self) -> Optional[Dict]:
        """Check GitHub releases for the latest version"""
        try:
            url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
            response = requests.get(url, timeout=5)
            response.raise_for_status()

            data = response.json()
            latest_version = data["tag_name"].lstrip("v")  # Remove 'v' prefix if present

            if self._is_newer_version(latest_version):
                return {
                    "update_available": True,
                    "current_version": self.current_version,
                    "latest_version": latest_version,
                    "release_date": data["published_at"],
                    "source": "GitHub",
                    "download_url": data["html_url"],
                    "upgrade_command": f"pip install --upgrade {self.package_name}",
                    "release_notes": data.get("body", "")[:500]
                }

        except Exception as e:
            # Silently fail
            pass

        return None

    def _is_newer_version(self, latest: str) -> bool:
        """
        Compare versions to determine if an update is available.

        Args:
            latest: Latest version string

        Returns:
            True if latest version is newer than current
        """
        try:
            return version.parse(latest) > version.parse(self.current_version)
        except Exception:
            return False

    def _load_cache(self) -> Optional[Dict]:
        """Load cached update check result"""
        if not self.cache_file.exists():
            return None

        try:
            with open(self.cache_file, 'r') as f:
                cache_data = json.load(f)

            # Check if cache is still valid
            cached_time = datetime.fromisoformat(cache_data["checked_at"])
            if datetime.now() - cached_time < self.cache_duration:
                return cache_data.get("result")

        except Exception:
            pass

        return None

    def _save_cache(self, result: Dict):
        """Save update check result to cache"""
        try:
            cache_data = {
                "checked_at": datetime.now().isoformat(),
                "result": result
            }

            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)

        except Exception:
            # Silently fail - caching is not critical
            pass

    def get_update_message(self, update_info: Dict) -> str:
        """
        Generate a user-friendly update message.

        Args:
            update_info: Update information dictionary

        Returns:
            Formatted update message
        """
        if not update_info or not update_info.get("update_available"):
            return "✓ You are using the latest version!"

        current = update_info["current_version"]
        latest = update_info["latest_version"]
        source = update_info["source"]
        upgrade_cmd = update_info["upgrade_command"]

        message = f"""
╔══════════════════════════════════════════════════════════════════╗
║                     UPDATE AVAILABLE                              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  Current Version: {current:20s}                            ║
║  Latest Version:  {latest:20s}                            ║
║  Source:          {source:20s}                            ║
║                                                                   ║
║  To upgrade, run:                                                ║
║  {upgrade_cmd:63s} ║
║                                                                   ║
╚══════════════════════════════════════════════════════════════════╝
"""

        return message

    def check_and_notify(self, silent: bool = False) -> bool:
        """
        Check for updates and print notification if available.

        Args:
            silent: If True, don't print anything if up to date

        Returns:
            True if update is available, False otherwise
        """
        update_info = self.check_for_updates()

        if update_info and update_info.get("update_available"):
            print(self.get_update_message(update_info))
            return True
        elif not silent:
            print("✓ You are using the latest version!")
            return False

        return False
