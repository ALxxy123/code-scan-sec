"""
Performance Benchmarking Module for Security Scanner.

This module provides comprehensive performance metrics and benchmarking:
- Scan performance metrics (speed, throughput, efficiency)
- Resource usage monitoring (CPU, memory, I/O)
- Comparative benchmarks (different scan modes, AI providers)
- Performance regression detection
- Optimization recommendations
- Historical performance tracking

Version: 3.2.0
Author: Ahmed Mubaraki
"""

from typing import Dict, Any, List, Optional, Callable
import time
import psutil
import os
from datetime import datetime
from pathlib import Path
import json
from functools import wraps
from dataclasses import dataclass, asdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

from logger import get_logger

console = Console()
logger = get_logger()


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    scan_name: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    files_scanned: int
    lines_scanned: int
    secrets_found: int
    vulnerabilities_found: int

    # Performance metrics
    files_per_second: float
    lines_per_second: float

    # Resource usage
    peak_memory_mb: float
    avg_cpu_percent: float

    # AI metrics (if applicable)
    ai_calls: int = 0
    ai_response_time_avg: float = 0.0

    # Quality metrics
    false_positive_rate: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        data['end_time'] = self.end_time.isoformat()
        return data


class PerformanceMonitor:
    """Monitor and track performance metrics during scans."""

    def __init__(self, scan_name: str = "default"):
        """
        Initialize performance monitor.

        Args:
            scan_name: Name of the scan being monitored
        """
        self.scan_name = scan_name
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        # Counters
        self.files_scanned = 0
        self.lines_scanned = 0
        self.secrets_found = 0
        self.vulnerabilities_found = 0
        self.ai_calls = 0

        # Resource tracking
        self.process = psutil.Process(os.getpid())
        self.initial_memory = 0
        self.peak_memory = 0
        self.cpu_samples: List[float] = []

        # AI timing
        self.ai_response_times: List[float] = []

        logger.info(f"Initialized PerformanceMonitor for: {scan_name}")

    def start(self):
        """Start monitoring."""
        self.start_time = datetime.now()
        self.initial_memory = self.process.memory_info().rss / (1024 * 1024)  # MB
        logger.info(f"Started performance monitoring at {self.start_time}")

    def stop(self) -> PerformanceMetrics:
        """
        Stop monitoring and return metrics.

        Returns:
            PerformanceMetrics object
        """
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Calculate rates
        files_per_sec = self.files_scanned / duration if duration > 0 else 0
        lines_per_sec = self.lines_scanned / duration if duration > 0 else 0

        # Resource metrics
        avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0

        # AI metrics
        avg_ai_time = sum(self.ai_response_times) / len(self.ai_response_times) if self.ai_response_times else 0

        metrics = PerformanceMetrics(
            scan_name=self.scan_name,
            start_time=self.start_time,
            end_time=self.end_time,
            duration_seconds=duration,
            files_scanned=self.files_scanned,
            lines_scanned=self.lines_scanned,
            secrets_found=self.secrets_found,
            vulnerabilities_found=self.vulnerabilities_found,
            files_per_second=files_per_sec,
            lines_per_second=lines_per_sec,
            peak_memory_mb=self.peak_memory,
            avg_cpu_percent=avg_cpu,
            ai_calls=self.ai_calls,
            ai_response_time_avg=avg_ai_time
        )

        logger.info(f"Stopped performance monitoring. Duration: {duration:.2f}s")
        return metrics

    def update_resource_usage(self):
        """Update resource usage metrics."""
        try:
            # Memory
            current_memory = self.process.memory_info().rss / (1024 * 1024)  # MB
            self.peak_memory = max(self.peak_memory, current_memory)

            # CPU
            cpu_percent = self.process.cpu_percent(interval=0.1)
            self.cpu_samples.append(cpu_percent)
        except Exception as e:
            logger.debug(f"Error updating resource usage: {e}")

    def record_file_scanned(self, line_count: int = 0):
        """
        Record a file being scanned.

        Args:
            line_count: Number of lines in the file
        """
        self.files_scanned += 1
        self.lines_scanned += line_count
        self.update_resource_usage()

    def record_secret_found(self):
        """Record a secret being found."""
        self.secrets_found += 1

    def record_vulnerability_found(self):
        """Record a vulnerability being found."""
        self.vulnerabilities_found += 1

    def record_ai_call(self, response_time: float):
        """
        Record an AI API call.

        Args:
            response_time: Response time in seconds
        """
        self.ai_calls += 1
        self.ai_response_times.append(response_time)


class Benchmark:
    """Run performance benchmarks and comparisons."""

    def __init__(self, results_dir: Path = Path("benchmark_results")):
        """
        Initialize benchmark runner.

        Args:
            results_dir: Directory to store benchmark results
        """
        self.results_dir = results_dir
        self.results_dir.mkdir(exist_ok=True)
        self.results_file = self.results_dir / "benchmark_history.json"
        self.history: List[Dict[str, Any]] = self._load_history()

    def _load_history(self) -> List[Dict[str, Any]]:
        """Load benchmark history from file."""
        if self.results_file.exists():
            try:
                with open(self.results_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load benchmark history: {e}")
        return []

    def _save_history(self):
        """Save benchmark history to file."""
        try:
            with open(self.results_file, 'w') as f:
                json.dump(self.history, f, indent=2)
            logger.info(f"Saved benchmark history to {self.results_file}")
        except Exception as e:
            logger.error(f"Failed to save benchmark history: {e}")

    def add_result(self, metrics: PerformanceMetrics):
        """
        Add benchmark result to history.

        Args:
            metrics: Performance metrics to add
        """
        self.history.append(metrics.to_dict())
        self._save_history()

    def compare_with_baseline(self, metrics: PerformanceMetrics, baseline_name: str = None) -> Dict[str, Any]:
        """
        Compare metrics with baseline or historical average.

        Args:
            metrics: Current metrics
            baseline_name: Name of baseline scan (if None, use historical average)

        Returns:
            Dict with comparison results
        """
        if not self.history:
            return {
                'has_baseline': False,
                'message': 'No baseline data available'
            }

        # Find baseline
        if baseline_name:
            baseline_results = [h for h in self.history if h.get('scan_name') == baseline_name]
            if not baseline_results:
                return {
                    'has_baseline': False,
                    'message': f'No baseline found with name: {baseline_name}'
                }
            baseline = baseline_results[-1]  # Most recent
        else:
            # Use average of last 5 runs
            recent = self.history[-5:]
            baseline = {
                'duration_seconds': sum(r['duration_seconds'] for r in recent) / len(recent),
                'files_per_second': sum(r['files_per_second'] for r in recent) / len(recent),
                'peak_memory_mb': sum(r['peak_memory_mb'] for r in recent) / len(recent),
                'avg_cpu_percent': sum(r['avg_cpu_percent'] for r in recent) / len(recent),
            }

        # Calculate differences
        duration_diff = ((metrics.duration_seconds - baseline['duration_seconds']) / baseline['duration_seconds']) * 100
        speed_diff = ((metrics.files_per_second - baseline['files_per_second']) / baseline['files_per_second']) * 100 if baseline['files_per_second'] > 0 else 0
        memory_diff = ((metrics.peak_memory_mb - baseline['peak_memory_mb']) / baseline['peak_memory_mb']) * 100 if baseline['peak_memory_mb'] > 0 else 0

        return {
            'has_baseline': True,
            'baseline': baseline,
            'current': metrics.to_dict(),
            'duration_change_percent': duration_diff,
            'speed_change_percent': speed_diff,
            'memory_change_percent': memory_diff,
            'performance_improved': duration_diff < 0,  # Faster is better
            'efficiency_improved': memory_diff < 0,  # Less memory is better
        }

    def display_metrics(self, metrics: PerformanceMetrics, comparison: Optional[Dict[str, Any]] = None):
        """
        Display performance metrics in a beautiful format.

        Args:
            metrics: Performance metrics to display
            comparison: Optional comparison data
        """
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]📊 Performance Benchmark Results[/bold cyan]",
            border_style="cyan"
        ))

        # Main metrics table
        table = Table(title="Scan Performance", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="yellow")
        table.add_column("Unit", style="dim")

        # Add rows
        table.add_row("Duration", f"{metrics.duration_seconds:.2f}", "seconds")
        table.add_row("Files Scanned", str(metrics.files_scanned), "files")
        table.add_row("Lines Scanned", f"{metrics.lines_scanned:,}", "lines")
        table.add_row("Throughput (Files)", f"{metrics.files_per_second:.2f}", "files/sec")
        table.add_row("Throughput (Lines)", f"{metrics.lines_per_second:,.0f}", "lines/sec")
        table.add_row("", "", "")  # Separator
        table.add_row("Peak Memory", f"{metrics.peak_memory_mb:.2f}", "MB")
        table.add_row("Avg CPU", f"{metrics.avg_cpu_percent:.1f}", "%")

        if metrics.ai_calls > 0:
            table.add_row("", "", "")  # Separator
            table.add_row("AI Calls", str(metrics.ai_calls), "calls")
            table.add_row("Avg AI Response", f"{metrics.ai_response_time_avg:.3f}", "seconds")

        console.print(table)

        # Findings table
        findings_table = Table(title="Scan Results", show_header=True, header_style="bold green")
        findings_table.add_column("Type", style="green")
        findings_table.add_column("Count", justify="right", style="yellow")

        findings_table.add_row("🔑 Secrets Found", str(metrics.secrets_found))
        findings_table.add_row("🐛 Vulnerabilities Found", str(metrics.vulnerabilities_found))

        console.print(findings_table)

        # Comparison
        if comparison and comparison.get('has_baseline'):
            console.print("\n")
            comp_table = Table(title="📈 Comparison with Baseline", show_header=True, header_style="bold magenta")
            comp_table.add_column("Metric", style="magenta")
            comp_table.add_column("Change", justify="right")
            comp_table.add_column("Status", justify="center")

            def format_change(value: float, lower_is_better: bool = True) -> Tuple[str, str]:
                """Format change percentage with color."""
                if abs(value) < 1:
                    return f"{value:+.1f}%", "🔵"

                is_improvement = (value < 0) if lower_is_better else (value > 0)
                color = "green" if is_improvement else "red"
                symbol = "✅" if is_improvement else "⚠️"
                return f"[{color}]{value:+.1f}%[/{color}]", symbol

            duration_text, duration_symbol = format_change(comparison['duration_change_percent'], lower_is_better=True)
            speed_text, speed_symbol = format_change(comparison['speed_change_percent'], lower_is_better=False)
            memory_text, memory_symbol = format_change(comparison['memory_change_percent'], lower_is_better=True)

            comp_table.add_row("Duration", duration_text, duration_symbol)
            comp_table.add_row("Speed", speed_text, speed_symbol)
            comp_table.add_row("Memory Usage", memory_text, memory_symbol)

            console.print(comp_table)

        console.print("\n")

    def run_comparison_benchmark(
        self,
        scan_function: Callable,
        configs: List[Dict[str, Any]],
        test_path: str
    ) -> List[PerformanceMetrics]:
        """
        Run comparative benchmarks with different configurations.

        Args:
            scan_function: Function to benchmark
            configs: List of configuration dictionaries
            test_path: Path to scan

        Returns:
            List of performance metrics for each configuration
        """
        console.print(Panel.fit(
            "[bold cyan]🏁 Running Comparative Benchmark[/bold cyan]",
            border_style="cyan"
        ))

        results = []

        for i, config in enumerate(configs, 1):
            config_name = config.get('name', f'Config {i}')
            console.print(f"\n[cyan]Testing configuration: {config_name}[/cyan]")

            monitor = PerformanceMonitor(scan_name=config_name)
            monitor.start()

            try:
                # Run scan with this configuration
                scan_function(test_path, **config.get('params', {}))

                # Get metrics
                metrics = monitor.stop()
                results.append(metrics)
                self.add_result(metrics)

                console.print(f"[green]✅ Completed: {config_name}[/green]")

            except Exception as e:
                console.print(f"[red]❌ Failed: {config_name} - {e}[/red]")
                logger.error(f"Benchmark failed for {config_name}: {e}")

        # Display comparison
        if len(results) > 1:
            self._display_comparison(results)

        return results

    def _display_comparison(self, results: List[PerformanceMetrics]):
        """Display comparison of multiple benchmark results."""
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]📊 Benchmark Comparison[/bold cyan]",
            border_style="cyan"
        ))

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Configuration", style="cyan")
        table.add_column("Duration (s)", justify="right")
        table.add_column("Speed (f/s)", justify="right")
        table.add_column("Memory (MB)", justify="right")
        table.add_column("Findings", justify="right")

        for metrics in results:
            total_findings = metrics.secrets_found + metrics.vulnerabilities_found
            table.add_row(
                metrics.scan_name,
                f"{metrics.duration_seconds:.2f}",
                f"{metrics.files_per_second:.2f}",
                f"{metrics.peak_memory_mb:.2f}",
                str(total_findings)
            )

        console.print(table)

        # Find best performer
        fastest = min(results, key=lambda m: m.duration_seconds)
        most_efficient = min(results, key=lambda m: m.peak_memory_mb)
        most_findings = max(results, key=lambda m: m.secrets_found + m.vulnerabilities_found)

        console.print("\n[bold]🏆 Best Performers:[/bold]")
        console.print(f"  ⚡ Fastest: [green]{fastest.scan_name}[/green] ({fastest.duration_seconds:.2f}s)")
        console.print(f"  💾 Most Efficient: [green]{most_efficient.scan_name}[/green] ({most_efficient.peak_memory_mb:.2f}MB)")
        console.print(f"  🎯 Most Findings: [green]{most_findings.scan_name}[/green] ({most_findings.secrets_found + most_findings.vulnerabilities_found} total)")
        console.print()


def benchmark_decorator(monitor: PerformanceMonitor):
    """
    Decorator to automatically track performance metrics.

    Args:
        monitor: PerformanceMonitor instance

    Example:
        @benchmark_decorator(monitor)
        def my_scan_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            monitor.start()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                metrics = monitor.stop()
                logger.info(f"Function {func.__name__} completed in {metrics.duration_seconds:.2f}s")
        return wrapper
    return decorator


# Convenience function
def run_benchmark(
    scan_name: str,
    scan_function: Callable,
    *args,
    save_results: bool = True,
    compare_baseline: bool = True,
    **kwargs
) -> PerformanceMetrics:
    """
    Run a benchmark for a scan function.

    Args:
        scan_name: Name of the benchmark
        scan_function: Function to benchmark
        *args: Arguments to pass to scan_function
        save_results: Whether to save results to history
        compare_baseline: Whether to compare with baseline
        **kwargs: Keyword arguments to pass to scan_function

    Returns:
        PerformanceMetrics object
    """
    monitor = PerformanceMonitor(scan_name)
    benchmark = Benchmark()

    monitor.start()

    try:
        result = scan_function(*args, **kwargs)
    finally:
        metrics = monitor.stop()

    if save_results:
        benchmark.add_result(metrics)

    comparison = None
    if compare_baseline:
        comparison = benchmark.compare_with_baseline(metrics)

    benchmark.display_metrics(metrics, comparison)

    return metrics
