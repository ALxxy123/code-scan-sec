#!/bin/bash

JSON_FILE="output/results.json"
HTML_FILE="output/report.html"

if [ ! -f "$JSON_FILE" ]; then
    echo "[ERROR] Results file not found: $JSON_FILE"
    exit 1
fi

# --- استخلاص الإحصائيات ---
total_findings=$(jq 'length' "$JSON_FILE")
affected_files=$(jq '[.[] | .file] | unique | length' "$JSON_FILE")
scan_date=$(date)

# --- بناء رأس صفحة الـ HTML ---
cat <<EOF > "$HTML_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: sans-serif; margin: 2em; background-color: #f4f4f9; color: #333; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .summary { background-color: #ecf0f1; padding: 1em; border-radius: 5px; display: flex; justify-content: space-around; }
        .summary-item { text-align: center; }
        .summary-item .value { font-size: 2em; font-weight: bold; color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin-top: 2em; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        thead { background-color: #3498db; color: white; }
        tbody tr:nth-child(even) { background-color: #f2f2f2; }
        code { background-color: #e4e4e4; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Scan Report</h1>
        
        <h2>📊 Summary</h2>
        <div class="summary">
            <div class="summary-item">
                <span>Total Findings</span>
                <div class="value">$total_findings</div>
            </div>
            <div class="summary-item">
                <span>Affected Files</span>
                <div class="value">$affected_files</div>
            </div>
        </div>
        <p style="text-align:center; margin-top:1em; color:#777;">Scan Date: $scan_date</p>
        
        <h2>📄 Details</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Line</th>
                    <th>Rule</th>
                    <th>Match</th>
                </tr>
            </thead>
            <tbody>
EOF

# --- بناء جدول النتائج من JSON ---
jq -r '.[] | "<tr><td><code>\(.file)</code></td><td>\(.line)</td><td><code>\(.rule)</code></td><td><code>\(.match)</code></td></tr>"' "$JSON_FILE" >> "$HTML_FILE"

# --- إغلاق صفحة الـ HTML ---
cat <<EOF >> "$HTML_FILE"
            </tbody>
        </table>
    </div>
</body>
</html>
EOF

echo "[INFO] HTML report generated at $HTML_FILE"
