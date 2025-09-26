#!/bin/bash

# --- الإعدادات ---
RULES_FILE="config/rules.txt"
IGNORE_FILE="config/ignore.txt"
OUTPUT_DIR="output"
JSON_RESULT_FILE="$OUTPUT_DIR/results.json"

if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq is not installed."
    exit 1
fi

SCAN_PATH="${1:-.}"
echo "[INFO] Scanning directory: $SCAN_PATH"
echo "[INFO] Using rules file: $RULES_FILE"

mkdir -p "$OUTPUT_DIR"

# --- بناء قائمة التجاهل لأمر find ---
ignore_args=()
if [ -f "$IGNORE_FILE" ]; then
    echo "[INFO] Using ignore file: $IGNORE_FILE"
    while IFS= read -r pattern; do
        if [[ -n "$pattern" && ! "$pattern" =~ ^\s*# ]]; then
            # نضيف الوسائط بالشكل الذي يفهمه أمر find
            ignore_args+=('!' '-path' "$pattern")
        fi
    done < "$IGNORE_FILE"
fi

# --- محرك الفحص الرئيسي ---
find "$SCAN_PATH" -type f \
-not -path '*/.git/*' \
-not -path '*/vendor/*' \
-not -path '*/node_modules/*' \
-not -path '*/tests/*' \
-not -path '*/output/*' \
"${ignore_args[@]}" \
-print0 | while IFS= read -r -d $'\0' file; do
    while IFS= read -r rule; do
        if [[ -z "$rule" || "$rule" =~ ^\s*# ]]; then
            continue
        fi

        grep -n -o --text -E "$rule" "$file" | while IFS=: read -r line_number match_content; do
            if [ -z "$match_content" ]; then
                continue
            fi

            jq -n \
              --arg file "$file" \
              --argjson line "$line_number" \
              --arg rule "$rule" \
              --arg match "$match_content" \
              '{file: $file, line: $line, rule: $rule, match: $match}'
        done
    done < "$RULES_FILE"
done | jq -s '.' > "$JSON_RESULT_FILE"

echo "[INFO] Scan complete. Results saved to $JSON_RESULT_FILE"
