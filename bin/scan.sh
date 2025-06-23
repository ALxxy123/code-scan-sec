#!/usr/bin/env bash
#
# bin/scan.sh – Professional code security scanner

# 1) تحميل الدوال وطباعة INFO إن نجح
source "$(dirname "${BASH_SOURCE[0]}")/../lib/functions.sh"
load_config

# 2) القيم الافتراضية
SCAN_DIR="."
LOG_FILE="../output/results.log"
JSON_FILE="../output/results.json"

# 3) دالة عرض الاستخدام
usage() {
  cat <<EOF
Usage: $0 [-d dir] [-o out.log] [-j out.json] [-h]
  -d DIR     Directory to scan (default: .)
  -o FILE    Plain-text log (default: output/results.log)
  -j FILE    JSON report (default: output/results.json)
  -h         Show help
EOF
  exit 1
}

# 4) قراءة الخيارات
while getopts "d:o:j:h" opt; do
  case $opt in
    d) SCAN_DIR="$OPTARG" ;;
    o) LOG_FILE="$OPTARG" ;;
    j) JSON_FILE="$OPTARG" ;;
    *) usage ;;
  esac
done

# 5) التحقق من وجود مجلد الفحص
if [[ ! -d "$SCAN_DIR" ]]; then
  log ERROR "Directory not found: $SCAN_DIR"
  exit 1
fi

# 6) تهيئة مجلدات الإخراج
mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$JSON_FILE")"
> "$LOG_FILE"
echo '[]' > "$JSON_FILE"

log INFO "Scanning directory: $SCAN_DIR"
log INFO "Logging to: $LOG_FILE"
log INFO "JSON output: $JSON_FILE"

# 7) اختيار أداة البحث الأسرع
if command -v rg &>/dev/null; then
  # ripgrep إذا موجود
  SEARCH_TOOL() {
    rg --no-heading --line-number --color=always \
       $(printf -- "--glob '!%s' " "${IGNORE[@]}") \
       "$1" "$SCAN_DIR"
  }
else
  # fallback إلى grep
  SEARCH_TOOL() {
    grep -R --color=always \
         --exclude-dir=$(printf "{%s}" "$(IFS=,; echo "${IGNORE[*]}")") \
         -n "$1" "$SCAN_DIR"
  }
fi

# 8) تنفيذ الفحص وجمع النتائج
RESULTS_JSON=()
for PATTERN in "${RULES[@]}"; do
  log INFO "Pattern: $PATTERN"
  while IFS= read -r line; do
    echo -e "$line" | tee -a "$LOG_FILE"
    FILE=${line%%:*}
    LN=${line#*:}; LN=${LN%%:*}
    TEXT=${line#*:*:}
    RESULTS_JSON+=("{\"file\":\"$FILE\",\"line\":$LN,\"match\":\"$(echo $TEXT | sed 's/\"/\\\\\"/g')\",\"pattern\":\"$PATTERN\"}")
  done < <(SEARCH_TOOL "$PATTERN")
done

# 9) كتابة تقرير JSON
{
  echo "["
  printf "%s\n" "${RESULTS_JSON[@]}" | sed '$!s/$/,/'
  echo "]"
} > "$JSON_FILE"

log INFO "Scan complete."
