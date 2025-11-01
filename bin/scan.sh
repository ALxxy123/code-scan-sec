#!/bin/bash

# This script becomes a full CLI tool

# --- إعدادات المسارات ---
# This allows the script to find its files after installation
export SCAN_TOOL_DIR=${SCAN_TOOL_DIR:-$(dirname "$0")}
export SCAN_CONFIG_DIR=${SCAN_CONFIG_DIR:-$(pwd)/config}

# --- ملفات الإعدادات ---
RULES_FILE="$SCAN_CONFIG_DIR/rules.txt"
IGNORE_FILE="$SCAN_CONFIG_DIR/ignore.txt"
OUTPUT_DIR="output" # المخرجات تكون دائمًا في المجلد الحالي
JSON_RESULT_FILE="$OUTPUT_DIR/results.json"

# --- دالة طباعة المساعدة ---
print_help() {
    echo "Usage: security-scan [OPTIONS]"
    echo ""
    echo "A CLI tool to scan code for hardcoded secrets."
    echo ""
    echo "Options:"
    echo "  -p, --path <dir>     Path to the directory to scan (default: current directory)"
    echo "  -o, --output <format>  Generate report. Formats: 'md', 'html', or 'all'"
    echo "  -r, --rules <file>     Use a custom rules file (default: $RULES_FILE)"
    echo "  --no-ai              Disable AI verification for this run"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Example: security-scan -p ../my-project -o html"
}

# --- القيم الافتراضية ---
SCAN_PATH="."
OUTPUT_FORMAT=""
USE_AI=true

# --- تحليل الخيارات (Flags) باستخدام getopt ---
# This is the core of the CLI logic
TEMP=$(getopt -o p:o:r:h --long path:,output:,rules:,help,no-ai -n 'security-scan' -- "$@")
if [ $? != 0 ]; then echo "Terminating..." >&2; exit 1; fi

eval set -- "$TEMP"

while true; do
    case "$1" in
        -p | --path) SCAN_PATH="$2"; shift 2 ;;
        -o | --output) OUTPUT_FORMAT="$2"; shift 2 ;;
        -r | --rules) RULES_FILE="$2"; shift 2 ;;
        --no-ai) USE_AI=false; shift 1 ;;
        -h | --help) print_help; exit 0 ;;
        --) shift; break ;;
        *) echo "Internal error!"; exit 1 ;;
    esac
done

# --- دالة التحقق عبر الذكاء الاصطناعي (كما هي من قبل) ---
function is_truly_a_secret() {
    if [ "$USE_AI" = false ]; then
        return 0 # Bypass AI check
    fi
    
    local finding="$1"
    if [ -z "$GEMINI_API_KEY" ]; then
        echo "[AI-WARN] GEMINI_API_KEY not set. Skipping AI verification."
        return 0
    fi
    echo "[AI] Verifying: \"$finding\"..."
    local response=$(curl -s -H "Content-Type: application/json" -d '{"contents": [{"parts": [{"text": "Is this string a secret (API key, token, password)? Respond ONLY with Yes or No. String: '"$finding"'"}]}]}' "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=$GEMINI_API_KEY")
    local answer=$(echo "$response" | jq -r '.candidates[0].content.parts[0].text' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [[ "$answer" == "yes" ]]; then
        echo "[AI] Verdict: YES (Secret)"
        return 0
    else
        echo "[AI] Verdict: NO (False Positive)"
        return 1
    fi
}

# --- محرك الفحص الرئيسي ---
echo "[INFO] Starting AI-Powered Security Scan"
echo "[INFO] Target path: $SCAN_PATH"
echo "[INFO] Rules file: $RULES_FILE"
[ "$USE_AI" = false ] && echo "[WARN] AI verification is DISABLED."
mkdir -p "$OUTPUT_DIR"

ignore_args=()
if [ -f "$IGNORE_FILE" ]; then
    while IFS= read -r p; do [[ -n "$p" && ! "$p" =~ ^\s*# ]] && ignore_args+=('!' '-path' "$p"); done < "$IGNORE_FILE"
fi

echo "[]" > "$JSON_RESULT_FILE"

find "$SCAN_PATH" -type f -not -path '*/.git/*' -not -path '*/output/*' "${ignore_args[@]}" -print0 | while IFS= read -r -d $'\0' file; do
    while IFS= read -r rule; do
        if [[ -z "$rule" || "$rule" =~ ^\s*# ]]; then continue; fi
        grep -n -o --text -E "$rule" "$file" | while IFS=: read -r line_number match_content; do
            if [ -z "$match_content" ]; then continue; fi
            if is_truly_a_secret "$match_content"; then
                temp_json=$(jq -n --arg file "$file" --argjson line "$line_number" --arg rule "$rule" --arg match "$match_content" '{file: $file, line: $line, rule: $rule, match: $match}')
                jq ". + [$temp_json]" "$JSON_RESULT_FILE" > "${JSON_RESULT_FILE}.tmp" && mv "${JSON_RESULT_FILE}.tmp" "$JSON_RESULT_FILE"
            fi
        done
    done < "$RULES_FILE"
done

echo "[INFO] Scan complete. AI-verified results saved to $JSON_RESULT_FILE"

# --- معالجة التقارير ---
if [ -n "$OUTPUT_FORMAT" ]; then
    echo "[INFO] Generating reports..."
    if [[ "$OUTPUT_FORMAT" == "all" || "$OUTPUT_FORMAT" == "md" ]]; then
        bash "$SCAN_TOOL_DIR/json-to-md.sh"
    fi
    if [[ "$OUTPUT_FORMAT" == "all" || "$OUTPUT_FORMAT" == "html" ]]; then
        bash "$SCAN_TOOL_DIR/json-to-html.sh"
    fi
    echo "[INFO] Reports generated in $OUTPUT_DIR"
fi
