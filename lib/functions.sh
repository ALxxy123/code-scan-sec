#!/usr/bin/env bash
#
# lib/functions.sh
# دوال مساعدة لتحميل الإعدادات وطباعة السجلات

# تحديد مسار السكربت الحالي
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ألوان ANSI للطباعة
INFO='\033[1;34m[INFO]\033[0m'
WARN='\033[1;33m[WARN]\033[0m'
ERROR='\033[1;31m[ERROR]\033[0m'

# دالة طباعة سجل بمستوى (INFO, WARN, ERROR)
log() {
  level="$1"; shift
  printf "%b %s\n" "${!level}" "$*"
}

# دالة لقراءة config/rules.txt و config/ignore.txt
load_config() {
  RULES=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    RULES+=("$line")
  done < "$SCRIPT_DIR/../config/rules.txt"

  IGNORE=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    IGNORE+=("$line")
  done < "$SCRIPT_DIR/../config/ignore.txt"
}
