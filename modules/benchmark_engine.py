"""
Benchmark Engine for Security Scan CLI
Performance measurement and comparison
"""

import time
import psutil
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from .data_models import BenchmarkResult, ScanType


class BenchmarkEngine:
    """
    Performance benchmarking for security scans.

    Tracks:
    - Scan duration
    - Files/lines processed per second
    - Memory usage
    - CPU utilization
    - Network metrics (for URL scans)
    """

    def __init__(self):
        """Initialize benchmark engine"""
        self.start_time = None
        self.end_time = None
        self.process = psutil.Process()
        self.initial_memory = 0
        self.peak_memory = 0
        self.cpu_samples = []

    def start(self):
        """Start benchmarking"""
        self.start_time = time.time()
        self.initial_memory = self.process.memory_info().rss / (1024 * 1024)  # MB
        self.peak_memory = self.initial_memory
        self.cpu_samples = []

    def sample(self):
        """Sample current performance metrics"""
        if self.start_time is None:
            return

        # Update peak memory
        current_memory = self.process.memory_info().rss / (1024 * 1024)
        self.peak_memory = max(self.peak_memory, current_memory)

        # Sample CPU
        try:
            cpu_percent = self.process.cpu_percent(interval=0.1)
            self.cpu_samples.append(cpu_percent)
        except:
            pass

    def stop(
        self,
        scan_type: ScanType,
        target: str,
        files_scanned: int = 0,
        lines_scanned: int = 0,
        findings_detected: int = 0,
        network_latency_ms: Optional[float] = None,
        download_speed_mbps: Optional[float] = None
    ) -> BenchmarkResult:
        """
        Stop benchmarking and return results.

        Args:
            scan_type: Type of scan performed
            target: What was scanned
            files_scanned: Number of files processed
            lines_scanned: Number of lines processed
            findings_detected: Total findings
            network_latency_ms: Network latency (for URL scans)
            download_speed_mbps: Download speed (for URL scans)

        Returns:
            Benchmark result
        """
        self.end_time = time.time()
        duration = self.end_time - self.start_time

        # Calculate averages
        avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0

        # Calculate speeds
        files_per_second = files_scanned / duration if duration > 0 else 0
        lines_per_second = lines_scanned / duration if duration > 0 else 0

        result = BenchmarkResult(
            scan_type=scan_type,
            target=target,
            duration_seconds=duration,
            files_scanned=files_scanned,
            lines_scanned=lines_scanned,
            findings_detected=findings_detected,
            files_per_second=files_per_second,
            lines_per_second=lines_per_second,
            peak_memory_mb=self.peak_memory,
            avg_cpu_percent=avg_cpu,
            network_latency_ms=network_latency_ms,
            download_speed_mbps=download_speed_mbps
        )

        return result

    def get_summary(self, result: BenchmarkResult) -> str:
        """
        Get human-readable benchmark summary.

        Args:
            result: Benchmark result

        Returns:
            Formatted summary string
        """
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                   BENCHMARK RESULTS                          ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Scan Type:        {result.scan_type.value.upper():20s}                ║
║  Target:           {result.target[:30]:30s}    ║
║                                                              ║
║  Duration:         {result.duration_seconds:6.2f} seconds                        ║
║  Files Scanned:    {result.files_scanned:6d}                                 ║
║  Lines Scanned:    {result.lines_scanned:6d}                                 ║
║  Findings:         {result.findings_detected:6d}                                 ║
║                                                              ║
║  Performance:                                                ║
║    Files/sec:      {result.files_per_second:6.2f}                                 ║
║    Lines/sec:      {result.lines_per_second:8.0f}                               ║
║    Peak Memory:    {result.peak_memory_mb:6.1f} MB                              ║
║    Avg CPU:        {result.avg_cpu_percent:5.1f}%                                ║
"""

        if result.network_latency_ms:
            summary += f"║    Network Latency: {result.network_latency_ms:5.1f} ms                            ║\n"

        if result.download_speed_mbps:
            summary += f"║    Download Speed:  {result.download_speed_mbps:5.1f} Mbps                          ║\n"

        summary += "║                                                              ║\n"
        summary += "╚══════════════════════════════════════════════════════════════╝"

        return summary


class PerformanceMonitor:
    """
    Continuous performance monitoring during scans.

    Can be used as a context manager:
    ```python
    with PerformanceMonitor() as monitor:
        # perform scan
        pass

    stats = monitor.get_stats()
    ```
    """

    def __init__(self, sample_interval: float = 1.0):
        """
        Initialize performance monitor.

        Args:
            sample_interval: How often to sample metrics (seconds)
        """
        self.sample_interval = sample_interval
        self.benchmark = BenchmarkEngine()
        self.running = False

    def __enter__(self):
        """Start monitoring"""
        self.benchmark.start()
        self.running = True
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop monitoring"""
        self.running = False
        return False

    def sample(self):
        """Sample current metrics"""
        if self.running:
            self.benchmark.sample()

    def get_result(
        self,
        scan_type: ScanType,
        target: str,
        **kwargs
    ) -> BenchmarkResult:
        """Get benchmark result"""
        return self.benchmark.stop(scan_type, target, **kwargs)
