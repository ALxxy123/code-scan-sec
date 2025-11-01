#!/usr/bin/env bash

set -e

# 1) متغيرات أساسية
SCAN_DIR="."
RULES_FILE="config/rules.txt"
JSON_FILE="output/results.json"
TSV_FILE="output/results.tsv"
LOG_FILE="output/results.log"

# إنشاء مجلد output لو مش موجود
mkdir -p output

# 2) اقرأ خيارات المستخدم
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -d|--dir)
        SCAN_DIR="$2"
        shift
        shift
        ;;
        -r|--rules)
        RULES_FILE="$2"
        shift
        shift
        ;;
        *)
        echo "[ERROR] Unknown option: $1"
        exit 1
        ;;
    esac
done

echo "[INFO] Using rules file: $RULES_FILE"
echo "[INFO] Scanning directory: $SCAN_DIR"

# امسح أي نتائج قديمة
> "$TSV_FILE"
> "$LOG_FILE"

# 3) ابحث عن جميع الملفات (مع print0 لتفادي مشاكل الفراغات)
find "$SCAN_DIR" -type f \
    \( -name "*.js" -o -name "*.ts" -o -name "*.php" -o -name "*.env" -o -name "*.json" -o -name "*.txt" \) \
    ! -path "*/vendor/*" \
    ! -path "*/tests/*" -print0 |
while IFS= read -r -d '' file; do

    # 4) اقرأ كل قاعدة من rules.txt
    while IFS= read -r PATTERN || [[ -n "$PATTERN" ]]; do
        [[ -z "$PATTERN" ]] && continue

        echo "[INFO] Scanning with rule: $PATTERN"

        # نفذ grep على الملف
        grep_output=$(grep -n -E "$PATTERN" "$file" 2>/dev/null || true)

        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue

            FILE=${line%%:*}
            rest=${line#*:}
            LN=${rest%%:*}
            TEXT=${rest#*:}

            # نظف النص من الأحرف المخفية وعلامات الاقتباس
            TEXT=$(echo "$TEXT" | tr -d '\000-\037' | sed 's/"/\\"/g')
            CLEAN_TEXT=$(echo "$TEXT" | xargs)

            # استبعاد النتائج غير المفيدة
            if [[ -z "$CLEAN_TEXT" ]] || \
               [[ ${#CLEAN_TEXT} -lt 5 ]] || \
               [[ "$CLEAN_TEXT" =~ ^[[:punct:][:space:][:digit:]]+$ ]] || \
               [[ "$CLEAN_TEXT" == "\"\"" ]] || \
               [[ "$CLEAN_TEXT" == "''" ]]; then
                continue
            fi

            # سجّل في ملف log
            echo "$FILE:$LN:$CLEAN_TEXT" | tee -a "$LOG_FILE"

            # أضفها للـ TSV
            echo -e "$FILE\t$LN\t$CLEAN_TEXT" >> "$TSV_FILE"
        done <<< "$grep_output"

    done < "$RULES_FILE"

done

# 5) تحويل TSV إلى JSON باستخدام jq
if [[ -s "$TSV_FILE" ]]; then
    jq -R -s '
      split("\n")[:-1]
      | map(split("\t"))
      | map({
          file: .[0],
          line: (.[1] | tonumber),
          match: .[2]
      })' "$TSV_FILE" > "$JSON_FILE"
else
    echo "[]" > "$JSON_FILE"
fi

echo "[INFO] Scan complete. Results saved to $JSON_FILE"

# تنظيف ملف rules المؤقت لو موجود
rm -f /tmp/rulefile.txt
