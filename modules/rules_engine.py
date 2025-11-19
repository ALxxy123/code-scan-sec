"""
Enhanced Rules Engine for Security Scan CLI
Advanced rule management with custom rules support
"""

import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from functools import lru_cache
from .data_models import CustomRule, SeverityLevel


class RulesEngine:
    """
    Advanced rules engine for security scanning.

    Features:
    - Load rules from multiple sources (built-in, custom, external)
    - Rule caching for performance
    - Rule validation and compilation
    - Dynamic rule updates
    - Rule filtering and selection
    """

    def __init__(
        self,
        builtin_rules_file: Path = Path("rules.txt"),
        vulnerability_rules_file: Path = Path("vulnerability_rules.yaml"),
        custom_rules_file: Path = Path("custom_rules.yaml")
    ):
        """
        Initialize rules engine.

        Args:
            builtin_rules_file: Path to built-in secret detection rules
            vulnerability_rules_file: Path to vulnerability detection rules
            custom_rules_file: Path to custom rules file
        """
        self.builtin_rules_file = builtin_rules_file
        self.vulnerability_rules_file = vulnerability_rules_file
        self.custom_rules_file = custom_rules_file

        self.secret_patterns: Dict[str, re.Pattern] = {}
        self.vulnerability_rules: Dict[str, List[Dict]] = {}
        self.custom_rules: List[CustomRule] = []

        self._load_all_rules()

    def _load_all_rules(self):
        """Load all rules from configured sources"""
        self._load_secret_rules()
        self._load_vulnerability_rules()
        self._load_custom_rules()

    @lru_cache(maxsize=1)
    def _load_secret_rules(self) -> Dict[str, re.Pattern]:
        """Load and compile secret detection rules"""
        if not self.builtin_rules_file.exists():
            return {}

        with open(self.builtin_rules_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Parse rule: NAME:PATTERN
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        rule_name, pattern = parts
                        try:
                            compiled_pattern = re.compile(pattern, re.IGNORECASE)
                            self.secret_patterns[rule_name.strip()] = compiled_pattern
                        except re.error as e:
                            print(f"Warning: Invalid regex pattern for rule '{rule_name}': {e}")

        return self.secret_patterns

    def _load_vulnerability_rules(self):
        """Load vulnerability detection rules from YAML"""
        if not self.vulnerability_rules_file.exists():
            return

        try:
            with open(self.vulnerability_rules_file, 'r') as f:
                data = yaml.safe_load(f)

            if data and 'vulnerabilities' in data:
                self.vulnerability_rules = data['vulnerabilities']

                # Compile regex patterns for performance
                for category, rules in self.vulnerability_rules.items():
                    for rule in rules:
                        if 'pattern' in rule:
                            try:
                                rule['compiled_pattern'] = re.compile(rule['pattern'], re.IGNORECASE | re.MULTILINE)
                            except re.error as e:
                                print(f"Warning: Invalid regex in vulnerability rule '{rule.get('name')}': {e}")

        except Exception as e:
            print(f"Error loading vulnerability rules: {e}")

    def _load_custom_rules(self):
        """Load custom user-defined rules"""
        if not self.custom_rules_file.exists():
            return

        try:
            with open(self.custom_rules_file, 'r') as f:
                data = yaml.safe_load(f)

            if data and 'custom_rules' in data:
                for rule_data in data['custom_rules']:
                    try:
                        rule = CustomRule(**rule_data)
                        self.custom_rules.append(rule)

                        # Add to secret patterns if it's a secret detection rule
                        if rule.category in ['secret', 'credential', 'api_key']:
                            try:
                                pattern = re.compile(rule.pattern, re.IGNORECASE)
                                self.secret_patterns[rule.name] = pattern
                            except re.error as e:
                                print(f"Warning: Invalid regex in custom rule '{rule.name}': {e}")

                    except Exception as e:
                        print(f"Warning: Failed to load custom rule: {e}")

        except Exception as e:
            print(f"Error loading custom rules: {e}")

    def add_custom_rule(self, rule: CustomRule) -> bool:
        """
        Add a custom rule at runtime.

        Args:
            rule: Custom rule to add

        Returns:
            True if added successfully
        """
        try:
            # Validate pattern
            compiled = re.compile(rule.pattern, re.IGNORECASE)

            # Add to custom rules
            self.custom_rules.append(rule)

            # Add to appropriate category
            if rule.category in ['secret', 'credential', 'api_key']:
                self.secret_patterns[rule.name] = compiled

            return True

        except Exception as e:
            print(f"Error adding custom rule: {e}")
            return False

    def remove_custom_rule(self, rule_name: str) -> bool:
        """
        Remove a custom rule.

        Args:
            rule_name: Name of rule to remove

        Returns:
            True if removed successfully
        """
        # Remove from custom rules list
        self.custom_rules = [r for r in self.custom_rules if r.name != rule_name]

        # Remove from secret patterns
        if rule_name in self.secret_patterns:
            del self.secret_patterns[rule_name]
            return True

        return False

    def get_secret_patterns(self, enabled_only: bool = True) -> Dict[str, re.Pattern]:
        """
        Get all secret detection patterns.

        Args:
            enabled_only: Only return enabled rules

        Returns:
            Dictionary of pattern name to compiled regex
        """
        if not enabled_only:
            return self.secret_patterns

        # Filter by enabled custom rules
        enabled_patterns = dict(self.secret_patterns)

        for rule in self.custom_rules:
            if not rule.enabled and rule.name in enabled_patterns:
                del enabled_patterns[rule.name]

        return enabled_patterns

    def get_vulnerability_rules(
        self,
        category: Optional[str] = None,
        severity: Optional[SeverityLevel] = None,
        language: Optional[str] = None
    ) -> List[Dict]:
        """
        Get vulnerability rules with optional filtering.

        Args:
            category: Filter by category
            severity: Filter by severity level
            language: Filter by programming language

        Returns:
            List of matching vulnerability rules
        """
        rules = []

        # Get rules from specific category or all categories
        if category and category in self.vulnerability_rules:
            rules = self.vulnerability_rules[category]
        else:
            for cat_rules in self.vulnerability_rules.values():
                rules.extend(cat_rules)

        # Apply filters
        if severity:
            rules = [r for r in rules if r.get('severity') == severity.value]

        if language:
            rules = [r for r in rules if not r.get('languages') or language in r.get('languages', [])]

        return rules

    def validate_rule(self, pattern: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a regex pattern.

        Args:
            pattern: Regex pattern to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            re.compile(pattern)
            return True, None
        except re.error as e:
            return False, str(e)

    def export_rules(self, output_file: Path):
        """
        Export all rules to a YAML file.

        Args:
            output_file: Path to output file
        """
        export_data = {
            "secret_patterns": {
                name: pattern.pattern
                for name, pattern in self.secret_patterns.items()
            },
            "vulnerability_rules": self.vulnerability_rules,
            "custom_rules": [
                rule.dict() for rule in self.custom_rules
            ]
        }

        with open(output_file, 'w') as f:
            yaml.dump(export_data, f, default_flow_style=False, sort_keys=False)

    def import_rules(self, input_file: Path) -> int:
        """
        Import rules from a YAML file.

        Args:
            input_file: Path to input file

        Returns:
            Number of rules imported
        """
        count = 0

        try:
            with open(input_file, 'r') as f:
                data = yaml.safe_load(f)

            # Import secret patterns
            if 'secret_patterns' in data:
                for name, pattern in data['secret_patterns'].items():
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE)
                        self.secret_patterns[name] = compiled
                        count += 1
                    except re.error:
                        pass

            # Import custom rules
            if 'custom_rules' in data:
                for rule_data in data['custom_rules']:
                    try:
                        rule = CustomRule(**rule_data)
                        self.custom_rules.append(rule)
                        count += 1
                    except Exception:
                        pass

        except Exception as e:
            print(f"Error importing rules: {e}")

        return count

    def save_custom_rules(self):
        """Save custom rules to file"""
        if not self.custom_rules:
            return

        rules_data = {
            "custom_rules": [rule.dict() for rule in self.custom_rules]
        }

        with open(self.custom_rules_file, 'w') as f:
            yaml.dump(rules_data, f, default_flow_style=False, sort_keys=False)

    def reload_rules(self):
        """Reload all rules from files"""
        self.secret_patterns.clear()
        self.vulnerability_rules.clear()
        self.custom_rules.clear()

        # Clear cache
        self._load_secret_rules.cache_clear()

        # Reload
        self._load_all_rules()

    def get_rule_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about loaded rules.

        Returns:
            Dictionary with rule statistics
        """
        vuln_count = sum(len(rules) for rules in self.vulnerability_rules.values())

        return {
            "total_secret_patterns": len(self.secret_patterns),
            "total_vulnerability_rules": vuln_count,
            "total_custom_rules": len(self.custom_rules),
            "vulnerability_categories": list(self.vulnerability_rules.keys()),
            "custom_rules_enabled": sum(1 for r in self.custom_rules if r.enabled),
            "custom_rules_disabled": sum(1 for r in self.custom_rules if not r.enabled),
        }

    def search_rules(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for rules matching a query.

        Args:
            query: Search query

        Returns:
            List of matching rules
        """
        results = []
        query_lower = query.lower()

        # Search secret patterns
        for name, pattern in self.secret_patterns.items():
            if query_lower in name.lower() or query_lower in pattern.pattern.lower():
                results.append({
                    "type": "secret_pattern",
                    "name": name,
                    "pattern": pattern.pattern
                })

        # Search vulnerability rules
        for category, rules in self.vulnerability_rules.items():
            for rule in rules:
                if (query_lower in rule.get('name', '').lower() or
                    query_lower in rule.get('description', '').lower() or
                    query_lower in category.lower()):
                    results.append({
                        "type": "vulnerability",
                        "category": category,
                        **rule
                    })

        # Search custom rules
        for rule in self.custom_rules:
            if (query_lower in rule.name.lower() or
                query_lower in rule.description.lower()):
                results.append({
                    "type": "custom",
                    **rule.dict()
                })

        return results


def create_default_custom_rules_file(output_path: Path = Path("custom_rules.yaml")):
    """
    Create a default custom rules file with examples.

    Args:
        output_path: Where to save the file
    """
    example_rules = {
        "custom_rules": [
            {
                "name": "Internal API Key",
                "pattern": r"INTERNAL_API_KEY[\s=:]+['\"]?([A-Za-z0-9_\-]{32,})['\"]?",
                "severity": "high",
                "category": "api_key",
                "description": "Detects hardcoded internal API keys",
                "recommendation": "Move API keys to environment variables or secure vault",
                "enabled": True,
                "languages": ["python", "javascript", "java"]
            },
            {
                "name": "Database Password",
                "pattern": r"DB_PASSWORD[\s=:]+['\"]?([^'\"\\s]+)['\"]?",
                "severity": "critical",
                "category": "credential",
                "description": "Detects hardcoded database passwords",
                "recommendation": "Use environment variables or secret management system",
                "enabled": True,
                "languages": ["python", "java", "php"]
            },
            {
                "name": "TODO Security",
                "pattern": r"TODO:?\s*(security|vuln|fix|hack|exploit)",
                "severity": "info",
                "category": "code_smell",
                "description": "Detects TODO comments about security issues",
                "recommendation": "Address security TODOs before deploying to production",
                "enabled": True,
                "languages": []
            }
        ]
    }

    with open(output_path, 'w') as f:
        yaml.dump(example_rules, f, default_flow_style=False, sort_keys=False)
