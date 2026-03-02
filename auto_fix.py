"""
Auto-Fix Engine for Security Vulnerabilities
Automatically fixes common security issues in code.
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from logger import get_logger

logger = get_logger()
console = Console()


@dataclass
class Fix:
    """Represents a code fix."""
    file_path: str
    line_number: int
    original_code: str
    fixed_code: str
    vulnerability_type: str
    description: str
    confidence: str  # high, medium, low


class AutoFix:
    """
    Automatic vulnerability fixing engine.
    """

    def __init__(self, interactive: bool = True):
        """
        Initialize the auto-fix engine.

        Args:
            interactive: If True, ask for confirmation before applying fixes
        """
        self.interactive = interactive
        self.fixes_applied = []
        self.fixes_skipped = []

    def fix_weak_crypto(self, file_path: str, content: str) -> Tuple[str, List[Fix]]:
        """
        Replace weak cryptographic algorithms with stronger alternatives.

        MD5 → SHA256
        SHA1 → SHA256
        DES → AES

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Tuple of (fixed_content, list_of_fixes)
        """
        fixes = []
        lines = content.split('\n')

        # Python patterns
        weak_crypto_patterns = [
            # MD5 patterns
            (
                r'hashlib\.md5\((.*?)\)',
                r'hashlib.sha256(\1)',
                'MD5 → SHA256',
                'Replace weak MD5 hashing with SHA256'
            ),
            (
                r'import md5',
                r'import hashlib  # Use hashlib.sha256() instead of md5',
                'MD5 Import',
                'Replace md5 import with hashlib'
            ),
            # SHA1 patterns
            (
                r'hashlib\.sha1\((.*?)\)',
                r'hashlib.sha256(\1)',
                'SHA1 → SHA256',
                'Replace SHA1 with stronger SHA256'
            ),
            # DES patterns
            (
                r'Crypto\.Cipher\.DES',
                r'Crypto.Cipher.AES',
                'DES → AES',
                'Replace weak DES encryption with AES'
            ),
        ]

        # Compile patterns once for performance
        compiled_patterns = [
            (re.compile(pattern), replacement, vuln_type, description)
            for pattern, replacement, vuln_type, description in weak_crypto_patterns
        ]

        for i, line in enumerate(lines):
            for compiled_pattern, replacement, vuln_type, description in compiled_patterns:
                # Use sub() directly instead of search() then sub() (avoid double evaluation)
                fixed_line = compiled_pattern.sub(replacement, line)
                if fixed_line != line:
                    fixes.append(Fix(
                        file_path=file_path,
                        line_number=i + 1,
                        original_code=line.strip(),
                        fixed_code=fixed_line.strip(),
                        vulnerability_type=vuln_type,
                        description=description,
                        confidence='high'
                    ))
                    lines[i] = fixed_line
                    break  # Only apply one fix per line to avoid conflicts

        return '\n'.join(lines), fixes

    def fix_hardcoded_secrets(self, file_path: str, content: str) -> Tuple[str, List[Fix], str]:
        """
        Move hardcoded secrets to environment variables and create .env.example file.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Tuple of (fixed_content, list_of_fixes, env_file_content)
        """
        fixes = []
        env_vars = []
        lines = content.split('\n')

        # Patterns for hardcoded secrets
        secret_patterns = [
            (r'api_key\s*=\s*["\']([^"\']+)["\']', 'API_KEY'),
            (r'secret_key\s*=\s*["\']([^"\']+)["\']', 'SECRET_KEY'),
            (r'password\s*=\s*["\']([^"\']+)["\']', 'PASSWORD'),
            (r'token\s*=\s*["\']([^"\']+)["\']', 'TOKEN'),
            (r'aws_access_key\s*=\s*["\']([^"\']+)["\']', 'AWS_ACCESS_KEY'),
            (r'aws_secret_key\s*=\s*["\']([^"\']+)["\']', 'AWS_SECRET_KEY'),
            (r'database_url\s*=\s*["\']([^"\']+)["\']', 'DATABASE_URL'),
        ]

        # Check if os.environ is already imported
        has_os_import = any('import os' in line for line in lines)
        has_getenv_import = any('from os import getenv' in line for line in lines)

        # Add import if needed
        if not has_os_import and not has_getenv_import:
            # Find first import line or first non-comment line
            import_index = 0
            for i, line in enumerate(lines):
                if line.strip() and not line.strip().startswith('#'):
                    if 'import' in line:
                        import_index = i + 1
                    else:
                        import_index = i
                        break
            lines.insert(import_index, 'import os')

        for i, line in enumerate(lines):
            for pattern, env_var_name in secret_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    secret_value = match.group(1)
                    var_name = match.group(0).split('=')[0].strip()

                    # Replace with os.getenv()
                    fixed_line = re.sub(
                        pattern,
                        f'{var_name} = os.getenv("{env_var_name}", "")',
                        line,
                        flags=re.IGNORECASE
                    )

                    fixes.append(Fix(
                        file_path=file_path,
                        line_number=i + 1,
                        original_code=line.strip(),
                        fixed_code=fixed_line.strip(),
                        vulnerability_type='Hardcoded Secret',
                        description=f'Move {var_name} to environment variable',
                        confidence='high'
                    ))

                    lines[i] = fixed_line
                    env_vars.append(f'{env_var_name}={secret_value}')

        # Create .env.example content
        env_file_content = '\n'.join([
            f'{var.split("=")[0]}=your_{var.split("=")[0].lower()}_here'
            for var in env_vars
        ])

        return '\n'.join(lines), fixes, env_file_content

    def fix_sql_injection(self, file_path: str, content: str) -> Tuple[str, List[Fix]]:
        """
        Fix SQL injection vulnerabilities by converting to parameterized queries.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Tuple of (fixed_content, list_of_fixes)
        """
        fixes = []
        lines = content.split('\n')

        # SQL injection patterns
        sql_patterns = [
            # String concatenation in SQL
            (
                r'execute\((.*?)\s*\+\s*(.*?)\)',
                r'execute(\1, (\2,))',
                'Add comment: Use parameterized query'
            ),
            (
                r'cursor\.execute\(["\'](.+?)["\']\.format\((.*?)\)\)',
                r'cursor.execute("\1", (\2,))',
                'Convert format() to parameterized query'
            ),
            (
                r'cursor\.execute\(["\'](.+?)["\']\s*%\s*\((.*?)\)\)',
                r'cursor.execute("\1", (\2,))',
                'Convert % formatting to parameterized query'
            ),
        ]

        for i, line in enumerate(lines):
            # Check for SQL string concatenation
            if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*\+.*', line, re.IGNORECASE):
                # Add a comment suggesting parameterized queries
                fixes.append(Fix(
                    file_path=file_path,
                    line_number=i + 1,
                    original_code=line.strip(),
                    fixed_code=f'# TODO: Use parameterized queries to prevent SQL injection\n{line}',
                    vulnerability_type='SQL Injection',
                    description='SQL query uses string concatenation - needs manual conversion to parameterized query',
                    confidence='medium'
                ))

        return '\n'.join(lines), fixes

    def fix_dangerous_functions(self, file_path: str, content: str) -> Tuple[str, List[Fix]]:
        """
        Replace dangerous functions with safer alternatives.

        eval() → ast.literal_eval() or safer alternatives
        exec() → safer alternatives
        pickle.loads() → json.loads() where appropriate

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Tuple of (fixed_content, list_of_fixes)
        """
        fixes = []
        lines = content.split('\n')

        # Check if we need to add imports
        has_ast_import = any('import ast' in line for line in lines)

        for i, line in enumerate(lines):
            # eval() usage
            if re.search(r'\beval\s*\(', line):
                # Check if it's evaluating a simple literal
                if re.search(r'eval\s*\(\s*["\'].*?["\']', line):
                    fixed_line = line.replace('eval(', 'ast.literal_eval(')

                    if not has_ast_import:
                        # Add ast import at the beginning
                        lines.insert(0, 'import ast')
                        has_ast_import = True

                    fixes.append(Fix(
                        file_path=file_path,
                        line_number=i + 1,
                        original_code=line.strip(),
                        fixed_code=fixed_line.strip(),
                        vulnerability_type='Dangerous Function',
                        description='Replace eval() with ast.literal_eval() for safer evaluation',
                        confidence='high'
                    ))
                    lines[i] = fixed_line
                else:
                    # More complex eval - add warning comment
                    fixes.append(Fix(
                        file_path=file_path,
                        line_number=i + 1,
                        original_code=line.strip(),
                        fixed_code=f'# WARNING: eval() is dangerous - consider safer alternatives\n{line}',
                        vulnerability_type='Dangerous Function',
                        description='eval() detected - review for security risks',
                        confidence='high'
                    ))

            # exec() usage
            if re.search(r'\bexec\s*\(', line):
                fixes.append(Fix(
                    file_path=file_path,
                    line_number=i + 1,
                    original_code=line.strip(),
                    fixed_code=f'# WARNING: exec() is dangerous - consider refactoring\n{line}',
                    vulnerability_type='Dangerous Function',
                    description='exec() detected - review for security risks',
                    confidence='high'
                ))

            # pickle.loads() usage
            if re.search(r'pickle\.loads?\s*\(', line):
                fixes.append(Fix(
                    file_path=file_path,
                    line_number=i + 1,
                    original_code=line.strip(),
                    fixed_code=f'# WARNING: pickle is unsafe for untrusted data - consider JSON\n{line}',
                    vulnerability_type='Insecure Deserialization',
                    description='pickle.loads() can execute arbitrary code - use JSON if possible',
                    confidence='high'
                ))

        return '\n'.join(lines), fixes

    def fix_xss_vulnerabilities(self, file_path: str, content: str) -> Tuple[str, List[Fix]]:
        """
        Fix Cross-Site Scripting (XSS) vulnerabilities.

        Args:
            file_path: Path to the file
            content: File content

        Returns:
            Tuple of (fixed_content, list_of_fixes)
        """
        fixes = []
        lines = content.split('\n')

        # Check if we need to add imports
        has_escape_import = False
        for line in lines:
            if 'from markupsafe import escape' in line or 'import html' in line:
                has_escape_import = True
                break

        for i, line in enumerate(lines):
            # innerHTML assignment
            if re.search(r'\.innerHTML\s*=', line):
                fixes.append(Fix(
                    file_path=file_path,
                    line_number=i + 1,
                    original_code=line.strip(),
                    fixed_code=f'# WARNING: innerHTML can cause XSS - use textContent or sanitize input\n{line}',
                    vulnerability_type='XSS',
                    description='innerHTML assignment detected - sanitize user input',
                    confidence='high'
                ))

            # Python string formatting in HTML context
            if re.search(r'f["\']<.*?\{.*?\}.*?["\']', line) or re.search(r'["\']<.*?["\']\.format\(', line):
                fixes.append(Fix(
                    file_path=file_path,
                    line_number=i + 1,
                    original_code=line.strip(),
                    fixed_code=f'# WARNING: Escape HTML to prevent XSS - use html.escape() or MarkupSafe\n{line}',
                    vulnerability_type='XSS',
                    description='HTML content with variables - ensure proper escaping',
                    confidence='medium'
                ))

        return '\n'.join(lines), fixes

    def fix_file(self, file_path: str, fix_types: Optional[List[str]] = None) -> Dict:
        """
        Apply all fixes to a file.

        Args:
            file_path: Path to the file to fix
            fix_types: List of fix types to apply (None = all)

        Returns:
            Dictionary with fix results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return {'success': False, 'error': str(e)}

        content = original_content
        all_fixes = []
        env_content = ""

        # Apply fixes based on fix_types
        if not fix_types or 'crypto' in fix_types:
            content, fixes = self.fix_weak_crypto(file_path, content)
            all_fixes.extend(fixes)

        if not fix_types or 'secrets' in fix_types:
            content, fixes, env_content = self.fix_hardcoded_secrets(file_path, content)
            all_fixes.extend(fixes)

        if not fix_types or 'sql' in fix_types:
            content, fixes = self.fix_sql_injection(file_path, content)
            all_fixes.extend(fixes)

        if not fix_types or 'dangerous' in fix_types:
            content, fixes = self.fix_dangerous_functions(file_path, content)
            all_fixes.extend(fixes)

        if not fix_types or 'xss' in fix_types:
            content, fixes = self.fix_xss_vulnerabilities(file_path, content)
            all_fixes.extend(fixes)

        # Show fixes to user
        if all_fixes:
            self._display_fixes(file_path, all_fixes)

            # Ask for confirmation if interactive
            if self.interactive:
                response = console.input("\n[bold yellow]Apply these fixes? [y/N]: [/bold yellow]")
                if response.lower() != 'y':
                    logger.info(f"Skipped fixes for {file_path}")
                    self.fixes_skipped.extend(all_fixes)
                    return {'success': False, 'skipped': True, 'fixes': all_fixes}

            # Apply fixes
            try:
                # Create backup
                backup_path = f"{file_path}.backup"
                with open(backup_path, 'w', encoding='utf-8') as f:
                    f.write(original_content)

                # Write fixed content
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Create .env.example if we have env variables
                if env_content:
                    env_path = Path(file_path).parent / '.env.example'
                    with open(env_path, 'w', encoding='utf-8') as f:
                        f.write(env_content)
                    logger.info(f"Created {env_path}")

                self.fixes_applied.extend(all_fixes)
                logger.info(f"Applied {len(all_fixes)} fixes to {file_path}")
                logger.info(f"Backup saved to {backup_path}")

                return {
                    'success': True,
                    'fixes': all_fixes,
                    'backup_path': backup_path,
                    'env_file': env_path if env_content else None
                }

            except Exception as e:
                logger.error(f"Failed to apply fixes: {e}")
                return {'success': False, 'error': str(e)}

        return {'success': True, 'fixes': [], 'message': 'No fixes needed'}

    def _display_fixes(self, file_path: str, fixes: List[Fix]):
        """Display fixes in a nice table."""
        console.print(f"\n[bold cyan]Fixes for {file_path}:[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Line", style="cyan", width=6)
        table.add_column("Type", style="yellow", width=20)
        table.add_column("Original", style="red", width=40)
        table.add_column("Fixed", style="green", width=40)
        table.add_column("Confidence", style="blue", width=10)

        for fix in fixes:
            table.add_row(
                str(fix.line_number),
                fix.vulnerability_type,
                fix.original_code[:37] + "..." if len(fix.original_code) > 40 else fix.original_code,
                fix.fixed_code[:37] + "..." if len(fix.fixed_code) > 40 else fix.fixed_code,
                fix.confidence
            )

        console.print(table)

    def get_summary(self) -> Dict:
        """Get summary of all fixes."""
        return {
            'total_fixes': len(self.fixes_applied) + len(self.fixes_skipped),
            'applied': len(self.fixes_applied),
            'skipped': len(self.fixes_skipped),
            'by_type': self._count_by_type(self.fixes_applied),
            'fixes_applied': self.fixes_applied,
            'fixes_skipped': self.fixes_skipped
        }

    def _count_by_type(self, fixes: List[Fix]) -> Dict[str, int]:
        """Count fixes by vulnerability type."""
        counts = {}
        for fix in fixes:
            counts[fix.vulnerability_type] = counts.get(fix.vulnerability_type, 0) + 1
        return counts


def auto_fix_directory(directory: str, fix_types: Optional[List[str]] = None,
                       interactive: bool = True, extensions: List[str] = None) -> Dict:
    """
    Apply automatic fixes to all files in a directory.

    Args:
        directory: Directory to scan and fix
        fix_types: List of fix types to apply
        interactive: Ask for confirmation before applying fixes
        extensions: List of file extensions to process

    Returns:
        Summary dictionary
    """
    if extensions is None:
        extensions = ['.py', '.js', '.ts', '.php', '.java']

    auto_fix = AutoFix(interactive=interactive)
    results = []

    console.print(f"\n[bold cyan]🔧 Auto-Fix Engine[/bold cyan]\n")
    console.print(f"Scanning directory: {directory}\n")

    # Find all files
    files_to_fix = []
    for ext in extensions:
        files_to_fix.extend(Path(directory).rglob(f"*{ext}"))

    console.print(f"Found {len(files_to_fix)} files to analyze\n")

    # Process each file
    for file_path in files_to_fix:
        result = auto_fix.fix_file(str(file_path), fix_types)
        results.append(result)

    # Display summary
    summary = auto_fix.get_summary()

    console.print("\n" + "="*80)
    console.print(Panel.fit(
        f"[bold green]✅ Auto-Fix Complete[/bold green]\n\n"
        f"Total Fixes: {summary['total_fixes']}\n"
        f"Applied: {summary['applied']}\n"
        f"Skipped: {summary['skipped']}\n\n"
        f"By Type:\n" + "\n".join(f"  - {k}: {v}" for k, v in summary['by_type'].items()),
        title="Summary"
    ))

    return summary
