#!/usr/bin/env python3
"""
Test script to verify Path objects can be serialized to JSON properly.
"""

import json
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from database import PathJSONEncoder
from report_generator import PathJSONEncoder as ReportPathJSONEncoder


def test_path_json_serialization():
    """Test that Path objects can be serialized to JSON."""

    # Test data with Path objects
    test_data = {
        "report_paths": {
            "html": Path("/path/to/report.html"),
            "json": Path("/path/to/report.json"),
            "markdown": Path("/path/to/report.md"),
        },
        "scan_info": {
            "path": Path("/project/directory"),
            "file": Path("C:/Graduationproject/system_Backend/CORS_CONFIGURATION_SUMMARY.md"),
        },
        "normal_data": {
            "count": 5,
            "status": "completed"
        }
    }

    print("Testing JSON serialization with Path objects...")
    print("=" * 60)

    try:
        # Test with database PathJSONEncoder
        json_str = json.dumps(test_data, indent=2, cls=PathJSONEncoder)
        print("✅ Database PathJSONEncoder - SUCCESS")
        print("Sample output:")
        print(json_str[:200] + "...\n")

        # Test with report_generator PathJSONEncoder
        json_str2 = json.dumps(test_data, indent=2, cls=ReportPathJSONEncoder)
        print("✅ Report PathJSONEncoder - SUCCESS")
        print("Sample output:")
        print(json_str2[:200] + "...\n")

        # Verify the data can be parsed back
        parsed = json.loads(json_str)
        print("✅ JSON parsing - SUCCESS")
        print(f"Parsed report_paths.html: {parsed['report_paths']['html']}")
        print(f"Parsed scan_info.file: {parsed['scan_info']['file']}")

        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_path_json_serialization()
    sys.exit(0 if success else 1)
