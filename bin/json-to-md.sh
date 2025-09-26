#!/bin/bash

JSON_FILE="output/results.json"
MD_FILE="output/report.md"

if [ ! -f "$JSON_FILE" ]; then
    echo "[ERROR] Results file not found: $JSON_FILE"
    exit 1
fi

# --- استخلاص الإحصائيات باستخدام jq ---
total_findings=$(jq 'length' "$JSON_FILE")
affected_files=$(jq '[.[] | .file] | unique | length' "$JSON_FILE")
scan_date=$(date)

# --- كتابة الملخص في ملف الـ Markdown ---
{
    echo "#  Security Scan Report 🛡️"
    echo ""
    echo "## 📊 Summary"
    echo "- **Total Findings:** $total_findings"
    echo "- **Affected Files:** $affected_files"
    echo "- **Scan Date:** $scan_date"
    echo ""
    echo "---"
    echo ""
    echo "## 📄 Details"
    echo ""
    echo "| File | Line | Rule | Match |"
    echo "|------|------|------|-------|"
} > "$MD_FILE"

# --- إضافة النتائج كجدول ---
jq -r '.[] | "| \(.file) | \(.line) | `\(.rule)` | `\(.match)` |"' "$JSON_FILE" >> "$MD_FILE"

echo "[INFO] Markdown report generated at $MD_FILE"
