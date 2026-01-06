#!/usr/bin/env python3
"""
Verify all regex patterns in vulnerability_rules.yaml
Run this script to ensure all patterns are valid and compilable.
"""

import yaml
import re
import sys
from pathlib import Path


def validate_patterns(yaml_file: str) -> bool:
    """Validate all regex patterns in the vulnerability rules file."""
    
    print("=" * 60)
    print("🔍 Validating Regex Patterns in vulnerability_rules.yaml")
    print("=" * 60)
    
    with open(yaml_file, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    if not data or 'vulnerabilities' not in data:
        print("❌ No vulnerabilities section found!")
        return False
    
    total_rules = 0
    valid_rules = 0
    errors = []
    
    for category, rules in data['vulnerabilities'].items():
        for rule in rules:
            total_rules += 1
            name = rule.get('name', 'Unnamed')
            pattern = rule.get('pattern', '')
            
            try:
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                valid_rules += 1
            except re.error as e:
                errors.append({
                    'category': category,
                    'name': name,
                    'pattern': pattern[:50] + '...' if len(pattern) > 50 else pattern,
                    'error': str(e)
                })
    
    # Print results
    print(f"\n📊 Results:")
    print(f"   Total Rules: {total_rules}")
    print(f"   Valid Rules: {valid_rules}")
    print(f"   Invalid Rules: {len(errors)}")
    
    if errors:
        print(f"\n❌ Found {len(errors)} invalid patterns:\n")
        for i, err in enumerate(errors, 1):
            print(f"   {i}. [{err['category']}] {err['name']}")
            print(f"      Pattern: {err['pattern']}")
            print(f"      Error: {err['error']}\n")
        return False
    else:
        print("\n✅ All regex patterns are valid!")
        return True


if __name__ == "__main__":
    script_dir = Path(__file__).parent
    yaml_file = script_dir / "vulnerability_rules.yaml"
    
    if not yaml_file.exists():
        print(f"❌ File not found: {yaml_file}")
        sys.exit(1)
    
    success = validate_patterns(str(yaml_file))
    sys.exit(0 if success else 1)
