"""
Plugin System for Security Scan CLI
Extensible architecture allowing custom plugins for scanning and analysis
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Type, Tuple
from pathlib import Path
import importlib.util
import inspect
import yaml
from .data_models import ScanResult, SecretFinding, VulnerabilityFinding, PluginMetadata


class BasePlugin(ABC):
    """
    Abstract base class for all scanner plugins.

    All plugins must inherit from this class and implement the required methods.
    """

    def __init__(self):
        """Initialize plugin"""
        self.metadata = self.get_metadata()
        self.enabled = True

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """
        Return plugin metadata.

        Returns:
            PluginMetadata object with plugin information
        """
        pass

    @abstractmethod
    def scan(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the plugin's scanning logic.

        Args:
            target: Path or URL to scan
            config: Configuration dictionary

        Returns:
            List of findings as dictionaries
        """
        pass

    def validate_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Check if all required dependencies are available.

        Returns:
            Tuple of (all_available: bool, missing: List[str])
        """
        missing = []
        for dep in self.metadata.dependencies:
            try:
                importlib.import_module(dep)
            except ImportError:
                missing.append(dep)

        return len(missing) == 0, missing

    def pre_scan(self, target: str, config: Dict[str, Any]) -> bool:
        """
        Pre-scan hook called before scan() method.

        Args:
            target: Scan target
            config: Configuration

        Returns:
            True to continue with scan, False to skip
        """
        return True

    def post_scan(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Post-scan hook called after scan() method.

        Args:
            findings: Raw findings from scan()

        Returns:
            Processed findings
        """
        return findings

    def get_config_schema(self) -> Dict[str, Any]:
        """
        Return configuration schema for this plugin.

        Returns:
            Dictionary describing expected configuration parameters
        """
        return {}


class PluginManager:
    """
    Manages plugin loading, registration, and execution.

    Features:
    - Load plugins from directory
    - Register plugins dynamically
    - Execute plugins in order
    - Handle plugin failures gracefully
    """

    def __init__(self, plugin_dir: Path = Path("plugins")):
        """
        Initialize plugin manager.

        Args:
            plugin_dir: Directory containing plugin files
        """
        self.plugin_dir = plugin_dir
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_order: List[str] = []

    def load_plugins(self) -> int:
        """
        Load all plugins from the plugin directory.

        Returns:
            Number of successfully loaded plugins
        """
        loaded_count = 0

        # Look for Python files in plugin directory
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue  # Skip private files

            try:
                plugin_instance = self._load_plugin_from_file(plugin_file)
                if plugin_instance:
                    self.register_plugin(plugin_instance)
                    loaded_count += 1
            except Exception as e:
                print(f"Warning: Failed to load plugin {plugin_file.name}: {e}")

        return loaded_count

    def _load_plugin_from_file(self, plugin_file: Path) -> Optional[BasePlugin]:
        """
        Load a plugin from a Python file.

        Args:
            plugin_file: Path to plugin file

        Returns:
            Plugin instance or None if loading failed
        """
        # Load module from file
        spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find plugin class (must inherit from BasePlugin)
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                try:
                    return obj()
                except Exception as e:
                    print(f"Error instantiating plugin {name}: {e}")
                    return None

        return None

    def register_plugin(self, plugin: BasePlugin) -> bool:
        """
        Register a plugin instance.

        Args:
            plugin: Plugin instance to register

        Returns:
            True if registered successfully
        """
        # Validate dependencies
        deps_ok, missing = plugin.validate_dependencies()
        if not deps_ok:
            print(f"Warning: Plugin '{plugin.metadata.name}' missing dependencies: {missing}")
            return False

        self.plugins[plugin.metadata.name] = plugin
        self.plugin_order.append(plugin.metadata.name)

        return True

    def unregister_plugin(self, plugin_name: str) -> bool:
        """
        Unregister a plugin.

        Args:
            plugin_name: Name of plugin to unregister

        Returns:
            True if unregistered successfully
        """
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            if plugin_name in self.plugin_order:
                self.plugin_order.remove(plugin_name)
            return True
        return False

    def execute_plugins(self, target: str, config: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Execute all enabled plugins.

        Args:
            target: Scan target (path or URL)
            config: Configuration dictionary

        Returns:
            Dictionary mapping plugin names to their findings
        """
        all_findings = {}

        for plugin_name in self.plugin_order:
            plugin = self.plugins[plugin_name]

            # Skip disabled plugins
            if not plugin.enabled:
                continue

            try:
                # Pre-scan hook
                if not plugin.pre_scan(target, config):
                    continue

                # Execute scan
                findings = plugin.scan(target, config)

                # Post-scan hook
                findings = plugin.post_scan(findings)

                all_findings[plugin_name] = findings

            except Exception as e:
                print(f"Error executing plugin '{plugin_name}': {e}")
                all_findings[plugin_name] = []

        return all_findings

    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """
        Get a specific plugin by name.

        Args:
            plugin_name: Name of the plugin

        Returns:
            Plugin instance or None
        """
        return self.plugins.get(plugin_name)

    def list_plugins(self) -> List[PluginMetadata]:
        """
        List all registered plugins.

        Returns:
            List of plugin metadata
        """
        return [plugin.metadata for plugin in self.plugins.values()]

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = True
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        if plugin_name in self.plugins:
            self.plugins[plugin_name].enabled = False
            return True
        return False

    def save_plugin_config(self, config_file: Path = None):
        """
        Save plugin configuration to YAML file.

        Args:
            config_file: Path to config file (default: plugins/config.yaml)
        """
        if config_file is None:
            config_file = self.plugin_dir / "config.yaml"

        config_data = {
            "plugins": {}
        }

        for name, plugin in self.plugins.items():
            config_data["plugins"][name] = {
                "enabled": plugin.enabled,
                "version": plugin.metadata.version,
                "config": plugin.get_config_schema()
            }

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False)

    def load_plugin_config(self, config_file: Path = None):
        """
        Load plugin configuration from YAML file.

        Args:
            config_file: Path to config file
        """
        if config_file is None:
            config_file = self.plugin_dir / "config.yaml"

        if not config_file.exists():
            return

        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)

        if not config_data or "plugins" not in config_data:
            return

        for name, plugin_config in config_data["plugins"].items():
            if name in self.plugins:
                self.plugins[name].enabled = plugin_config.get("enabled", True)


# Example plugin implementation
class ExampleSecretPlugin(BasePlugin):
    """
    Example plugin that detects custom patterns.

    This demonstrates how to create a custom plugin.
    """

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="example-secret-detector",
            version="1.0.0",
            author="Security Team",
            description="Example plugin for detecting custom secret patterns",
            enabled=True,
            dependencies=["re"]
        )

    def scan(self, target: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan for custom patterns.

        This is just an example - real implementation would scan files.
        """
        findings = []

        # Example: Detect custom patterns
        # In real implementation, you would:
        # 1. Read files from target
        # 2. Apply your custom detection logic
        # 3. Return findings

        return findings

    def get_config_schema(self) -> Dict[str, Any]:
        return {
            "patterns": {
                "type": "list",
                "description": "Custom regex patterns to detect",
                "default": []
            },
            "entropy_threshold": {
                "type": "float",
                "description": "Entropy threshold for detection",
                "default": 4.0
            }
        }
