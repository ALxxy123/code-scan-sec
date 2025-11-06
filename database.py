"""
Database backend for storing scan history and tracking trends.
Supports SQLite (default) and PostgreSQL.
Thread-safe implementation using threading.local() for SQLite connections.
"""

import sqlite3
import json
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import os

from logger import get_logger

logger = get_logger()


class PathJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles Path objects."""

    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


@dataclass
class ScanRecord:
    """Represents a scan record in the database."""
    id: Optional[int] = None
    scan_id: str = ""
    path: str = ""
    start_time: str = ""
    end_time: Optional[str] = None
    status: str = "queued"  # queued, running, completed, failed
    total_secrets: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    ai_provider: str = ""
    ai_enabled: bool = True
    vulnerability_scan_enabled: bool = True
    results_json: str = "{}"
    error_message: Optional[str] = None


class Database:
    """
    Database handler for security scanner.

    Supports both SQLite and PostgreSQL.
    """

    def __init__(self, db_path: str = "security_scanner.db", db_type: str = "sqlite"):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file or PostgreSQL connection string
            db_type: Database type ('sqlite' or 'postgresql')
        """
        self.db_path = db_path
        self.db_type = db_type
        self.conn = None

        # Thread-safe connection storage for SQLite
        self._local = threading.local()
        self._lock = threading.Lock()

        if db_type == "sqlite":
            self._init_sqlite()
        elif db_type == "postgresql":
            self._init_postgresql()
        else:
            raise ValueError(f"Unsupported database type: {db_type}")

        self._create_tables()
        logger.info(f"Database initialized: {db_type} (thread-safe)")

    def _get_connection(self):
        """
        Get thread-local database connection.

        For SQLite: Creates a new connection per thread for thread safety.
        For PostgreSQL: Returns the shared connection (thread-safe by default).

        Returns:
            Database connection object
        """
        if self.db_type == "sqlite":
            # Check if this thread has a connection
            if not hasattr(self._local, 'conn') or self._local.conn is None:
                self._local.conn = sqlite3.connect(self.db_path)
                self._local.conn.row_factory = sqlite3.Row
                logger.debug(f"Created new SQLite connection for thread {threading.current_thread().name}")
            return self._local.conn
        else:
            # PostgreSQL connections are thread-safe
            return self.conn

    def _init_sqlite(self):
        """Initialize SQLite connection (main connection for table creation)."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name

    def _init_postgresql(self):
        """Initialize PostgreSQL connection."""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor

            self.conn = psycopg2.connect(self.db_path, cursor_factory=RealDictCursor)
        except ImportError:
            raise ImportError("psycopg2 is required for PostgreSQL support. Install with: pip install psycopg2-binary")

    def _create_tables(self):
        """Create database tables if they don't exist."""
        # Use main connection for table creation (initialization only)
        cursor = self.conn.cursor()

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                path TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT NOT NULL,
                total_secrets INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_vulnerabilities INTEGER DEFAULT 0,
                high_vulnerabilities INTEGER DEFAULT 0,
                medium_vulnerabilities INTEGER DEFAULT 0,
                low_vulnerabilities INTEGER DEFAULT 0,
                ai_provider TEXT,
                ai_enabled INTEGER DEFAULT 1,
                vulnerability_scan_enabled INTEGER DEFAULT 1,
                results_json TEXT,
                error_message TEXT
            )
        """)

        # Secrets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                matched_text TEXT NOT NULL,
                ai_verified INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                cwe TEXT,
                owasp TEXT,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                matched_text TEXT,
                description TEXT,
                recommendation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)

        # Trends table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                total_scans INTEGER DEFAULT 0,
                total_secrets INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_vulnerabilities INTEGER DEFAULT 0,
                unique_file_paths INTEGER DEFAULT 0
            )
        """)

        self.conn.commit()
        logger.info("Database tables created/verified")

    def save_scan(self, scan: ScanRecord) -> int:
        """
        Save or update a scan record.

        Args:
            scan: Scan record to save

        Returns:
            Scan ID in database
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        if scan.id:
            # Update existing scan
            cursor.execute("""
                UPDATE scans SET
                    path = ?,
                    start_time = ?,
                    end_time = ?,
                    status = ?,
                    total_secrets = ?,
                    total_vulnerabilities = ?,
                    critical_vulnerabilities = ?,
                    high_vulnerabilities = ?,
                    medium_vulnerabilities = ?,
                    low_vulnerabilities = ?,
                    ai_provider = ?,
                    ai_enabled = ?,
                    vulnerability_scan_enabled = ?,
                    results_json = ?,
                    error_message = ?
                WHERE scan_id = ?
            """, (
                scan.path, scan.start_time, scan.end_time, scan.status,
                scan.total_secrets, scan.total_vulnerabilities,
                scan.critical_vulnerabilities, scan.high_vulnerabilities,
                scan.medium_vulnerabilities, scan.low_vulnerabilities,
                scan.ai_provider, int(scan.ai_enabled),
                int(scan.vulnerability_scan_enabled), scan.results_json,
                scan.error_message, scan.scan_id
            ))
        else:
            # Insert new scan
            cursor.execute("""
                INSERT INTO scans (
                    scan_id, path, start_time, end_time, status,
                    total_secrets, total_vulnerabilities,
                    critical_vulnerabilities, high_vulnerabilities,
                    medium_vulnerabilities, low_vulnerabilities,
                    ai_provider, ai_enabled, vulnerability_scan_enabled,
                    results_json, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.scan_id, scan.path, scan.start_time, scan.end_time,
                scan.status, scan.total_secrets, scan.total_vulnerabilities,
                scan.critical_vulnerabilities, scan.high_vulnerabilities,
                scan.medium_vulnerabilities, scan.low_vulnerabilities,
                scan.ai_provider, int(scan.ai_enabled),
                int(scan.vulnerability_scan_enabled), scan.results_json,
                scan.error_message
            ))

        conn.commit()
        return cursor.lastrowid

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """
        Get scan record by ID.

        Args:
            scan_id: Unique scan identifier

        Returns:
            Scan record or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()

        if row:
            return ScanRecord(**dict(row))
        return None

    def list_scans(self, limit: int = 50, offset: int = 0, status: Optional[str] = None) -> List[ScanRecord]:
        """
        List scans with pagination.

        Args:
            limit: Maximum number of scans to return
            offset: Number of scans to skip
            status: Filter by status (optional)

        Returns:
            List of scan records
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        if status:
            cursor.execute("""
                SELECT * FROM scans
                WHERE status = ?
                ORDER BY start_time DESC
                LIMIT ? OFFSET ?
            """, (status, limit, offset))
        else:
            cursor.execute("""
                SELECT * FROM scans
                ORDER BY start_time DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))

        return [ScanRecord(**dict(row)) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall statistics.

        Returns:
            Dictionary with statistics
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Total scans
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        total_scans = cursor.fetchone()['count']

        # Active scans
        cursor.execute("SELECT COUNT(*) as count FROM scans WHERE status IN ('queued', 'running')")
        active_scans = cursor.fetchone()['count']

        # Total secrets
        cursor.execute("SELECT SUM(total_secrets) as total FROM scans WHERE status = 'completed'")
        total_secrets = cursor.fetchone()['total'] or 0

        # Total vulnerabilities
        cursor.execute("SELECT SUM(total_vulnerabilities) as total FROM scans WHERE status = 'completed'")
        total_vulnerabilities = cursor.fetchone()['total'] or 0

        # Critical vulnerabilities
        cursor.execute("SELECT SUM(critical_vulnerabilities) as total FROM scans WHERE status = 'completed'")
        critical_vulnerabilities = cursor.fetchone()['total'] or 0

        # Average scan time
        cursor.execute("""
            SELECT AVG(
                julianday(end_time) - julianday(start_time)
            ) * 24 * 60 as avg_minutes
            FROM scans
            WHERE status = 'completed' AND end_time IS NOT NULL
        """)
        avg_scan_time = cursor.fetchone()['avg_minutes'] or 0

        return {
            'total_scans': total_scans,
            'active_scans': active_scans,
            'completed_scans': total_scans - active_scans,
            'total_secrets': total_secrets,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'average_scan_time_minutes': round(avg_scan_time, 2)
        }

    def get_trends(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get trend data for the past N days.

        Args:
            days: Number of days to retrieve

        Returns:
            List of daily statistics
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                DATE(start_time) as date,
                COUNT(*) as total_scans,
                SUM(total_secrets) as total_secrets,
                SUM(total_vulnerabilities) as total_vulnerabilities,
                SUM(critical_vulnerabilities) as critical_vulnerabilities
            FROM scans
            WHERE start_time >= datetime('now', ?)
                AND status = 'completed'
            GROUP BY DATE(start_time)
            ORDER BY date DESC
        """, (f'-{days} days',))

        return [dict(row) for row in cursor.fetchall()]

    def get_top_vulnerable_files(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most vulnerable files across all scans.

        Args:
            limit: Maximum number of files to return

        Returns:
            List of files with vulnerability counts
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                file_path,
                COUNT(*) as vulnerability_count,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count
            FROM vulnerabilities
            GROUP BY file_path
            ORDER BY vulnerability_count DESC
            LIMIT ?
        """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def get_vulnerability_categories(self) -> Dict[str, int]:
        """
        Get vulnerability counts by category.

        Returns:
            Dictionary mapping category to count
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY category
            ORDER BY count DESC
        """)

        return {row['category']: row['count'] for row in cursor.fetchall()}

    def cleanup_old_scans(self, days: int = 90):
        """
        Delete scans older than specified days.

        Args:
            days: Number of days to keep
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Delete old secrets
        cursor.execute("""
            DELETE FROM secrets
            WHERE scan_id IN (
                SELECT scan_id FROM scans
                WHERE start_time < datetime('now', ?)
            )
        """, (f'-{days} days',))

        # Delete old vulnerabilities
        cursor.execute("""
            DELETE FROM vulnerabilities
            WHERE scan_id IN (
                SELECT scan_id FROM scans
                WHERE start_time < datetime('now', ?)
            )
        """, (f'-{days} days',))

        # Delete old scans
        cursor.execute("""
            DELETE FROM scans
            WHERE start_time < datetime('now', ?)
        """, (f'-{days} days',))

        conn.commit()
        logger.info(f"Cleaned up scans older than {days} days")

    def export_to_json(self, output_path: str):
        """
        Export entire database to JSON file.

        Args:
            output_path: Path to output JSON file
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Export all tables
        data = {}

        for table in ['scans', 'secrets', 'vulnerabilities', 'trends']:
            cursor.execute(f"SELECT * FROM {table}")
            data[table] = [dict(row) for row in cursor.fetchall()]

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, cls=PathJSONEncoder)

        logger.info(f"Database exported to {output_path}")

    def close(self):
        """Close database connection and all thread-local connections."""
        # Close main connection
        if self.conn:
            self.conn.close()
            self.conn = None

        # Close thread-local connection if exists
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

        logger.info("Database connections closed")


# Singleton database instance
_db_instance: Optional[Database] = None


def get_database(db_path: str = "security_scanner.db", db_type: str = "sqlite") -> Database:
    """
    Get singleton database instance.

    Args:
        db_path: Path to database file or connection string
        db_type: Database type ('sqlite' or 'postgresql')

    Returns:
        Database instance
    """
    global _db_instance

    if _db_instance is None:
        _db_instance = Database(db_path=db_path, db_type=db_type)

    return _db_instance


def close_database():
    """Close singleton database instance."""
    global _db_instance

    if _db_instance:
        _db_instance.close()
        _db_instance = None
