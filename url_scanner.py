"""
URL Scanner Module for Remote Repository Scanning.

This module provides functionality to scan remote repositories and web applications:
- Git repository cloning (GitHub, GitLab, Bitbucket, etc.)
- Direct file downloads from URLs
- Archive extraction (zip, tar.gz, etc.)
- Temporary directory management for remote scans

Version: 3.2.0
Author: Ahmed Mubaraki
"""

from typing import Optional, Dict, Any, List
import os
import tempfile
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn

from logger import get_logger

console = Console()
logger = get_logger()


class URLScanner:
    """Handle scanning of remote projects via URLs."""

    def __init__(self):
        """Initialize URL scanner."""
        self.temp_dir: Optional[Path] = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Scanner/3.2.0'
        })

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp directory."""
        self.cleanup()

    def cleanup(self):
        """Clean up temporary directories."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory: {e}")

    def is_git_url(self, url: str) -> bool:
        """
        Check if URL is a Git repository.

        Args:
            url: URL to check

        Returns:
            bool: True if URL appears to be a Git repository
        """
        git_indicators = [
            '.git',
            'github.com',
            'gitlab.com',
            'bitbucket.org',
            'gitea.',
            'gogs.'
        ]
        return any(indicator in url.lower() for indicator in git_indicators)

    def is_archive_url(self, url: str) -> bool:
        """
        Check if URL points to an archive file.

        Args:
            url: URL to check

        Returns:
            bool: True if URL appears to be an archive
        """
        archive_extensions = ['.zip', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz']
        return any(url.lower().endswith(ext) for ext in archive_extensions)

    def clone_git_repository(self, url: str, depth: int = 1) -> Path:
        """
        Clone a Git repository to temporary directory.

        Args:
            url: Git repository URL
            depth: Clone depth (1 for shallow clone)

        Returns:
            Path: Path to cloned repository

        Raises:
            RuntimeError: If cloning fails
        """
        self.temp_dir = Path(tempfile.mkdtemp(prefix="security_scan_"))
        clone_path = self.temp_dir / "repository"

        console.print(f"[cyan]🔄 Cloning repository from: {url}[/cyan]")
        logger.info(f"Cloning Git repository: {url}")

        try:
            cmd = ["git", "clone"]
            if depth > 0:
                cmd.extend(["--depth", str(depth)])
            cmd.extend([url, str(clone_path)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr}")

            console.print(f"[green]✅ Repository cloned successfully to: {clone_path}[/green]")
            logger.info(f"Repository cloned to: {clone_path}")
            return clone_path

        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone timed out after 5 minutes")
        except FileNotFoundError:
            raise RuntimeError("Git is not installed. Please install git to clone repositories.")
        except Exception as e:
            raise RuntimeError(f"Failed to clone repository: {e}")

    def download_file(self, url: str, destination: Path) -> Path:
        """
        Download a file from URL with progress bar.

        Args:
            url: URL to download from
            destination: Destination path

        Returns:
            Path: Path to downloaded file
        """
        console.print(f"[cyan]⬇️  Downloading from: {url}[/cyan]")
        logger.info(f"Downloading file from: {url}")

        try:
            response = self.session.get(url, stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(
                    f"Downloading {destination.name}",
                    total=total_size
                )

                with open(destination, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            progress.update(task, advance=len(chunk))

            console.print(f"[green]✅ Downloaded to: {destination}[/green]")
            logger.info(f"File downloaded to: {destination}")
            return destination

        except requests.RequestException as e:
            raise RuntimeError(f"Failed to download file: {e}")

    def extract_archive(self, archive_path: Path, extract_to: Path) -> Path:
        """
        Extract archive file.

        Args:
            archive_path: Path to archive file
            extract_to: Directory to extract to

        Returns:
            Path: Path to extracted directory
        """
        console.print(f"[cyan]📦 Extracting archive: {archive_path.name}[/cyan]")
        logger.info(f"Extracting archive: {archive_path}")

        try:
            if archive_path.suffix == '.zip':
                import zipfile
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            else:
                import tarfile
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_to)

            console.print(f"[green]✅ Archive extracted to: {extract_to}[/green]")
            logger.info(f"Archive extracted to: {extract_to}")
            return extract_to

        except Exception as e:
            raise RuntimeError(f"Failed to extract archive: {e}")

    def scan_url(self, url: str, shallow: bool = True) -> Path:
        """
        Scan a remote project from URL.

        Supports:
        - Git repositories (GitHub, GitLab, Bitbucket, etc.)
        - Archive files (zip, tar.gz, etc.)
        - Direct file URLs

        Args:
            url: URL to scan (repository or archive)
            shallow: Use shallow clone for git repos (faster)

        Returns:
            Path: Path to local copy for scanning

        Raises:
            RuntimeError: If download/clone fails
        """
        logger.info(f"Processing URL: {url}")

        # Create temp directory
        self.temp_dir = Path(tempfile.mkdtemp(prefix="security_scan_"))

        try:
            # Handle Git repositories
            if self.is_git_url(url):
                return self.clone_git_repository(url, depth=1 if shallow else 0)

            # Handle archive files
            elif self.is_archive_url(url):
                # Download archive
                parsed = urlparse(url)
                filename = Path(parsed.path).name or "download.zip"
                archive_path = self.temp_dir / filename

                self.download_file(url, archive_path)

                # Extract archive
                extract_dir = self.temp_dir / "extracted"
                extract_dir.mkdir(exist_ok=True)
                return self.extract_archive(archive_path, extract_dir)

            # Handle single file URLs
            else:
                parsed = urlparse(url)
                filename = Path(parsed.path).name or "downloaded_file"
                file_path = self.temp_dir / filename

                self.download_file(url, file_path)
                return file_path

        except Exception as e:
            self.cleanup()
            raise RuntimeError(f"Failed to process URL: {e}")

    def get_scan_info(self, url: str) -> Dict[str, Any]:
        """
        Get information about the URL to be scanned.

        Args:
            url: URL to analyze

        Returns:
            Dict containing URL info
        """
        info = {
            'url': url,
            'type': 'unknown',
            'estimated_time': 'unknown'
        }

        if self.is_git_url(url):
            info['type'] = 'git_repository'
            info['estimated_time'] = '30-120 seconds'
        elif self.is_archive_url(url):
            info['type'] = 'archive'
            info['estimated_time'] = '10-60 seconds'
        else:
            info['type'] = 'single_file'
            info['estimated_time'] = '5-10 seconds'

        return info


def scan_remote_url(url: str, scanner_function, shallow: bool = True, **scan_kwargs) -> Dict[str, Any]:
    """
    Convenience function to scan a remote URL.

    Args:
        url: URL to scan
        scanner_function: Function to call with the downloaded path
        shallow: Use shallow clone for git repos
        **scan_kwargs: Additional arguments to pass to scanner_function

    Returns:
        Dict: Scan results
    """
    with URLScanner() as url_scanner:
        try:
            # Download/clone the remote resource
            local_path = url_scanner.scan_url(url, shallow=shallow)

            # Run the scanner on the local path
            console.print(f"\n[cyan]🔍 Starting security scan of downloaded content...[/cyan]\n")
            results = scanner_function(str(local_path), **scan_kwargs)

            return results

        except Exception as e:
            logger.error(f"Failed to scan URL: {e}")
            console.print(f"[bold red]❌ Error scanning URL: {e}[/bold red]")
            raise
