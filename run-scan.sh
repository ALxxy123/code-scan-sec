#!/usr/bin/env bash

TARGET_DIR=${1:-.}

# أنشئ مجلد output لو ما كان موجود
mkdir -p output

# نفّذ الأداة بفحص كل الملفات (تقدر تخليها -c لو تبغى بس الملفات المتغيرة)
bin/scan.sh -d "$TARGET_DIR"

# اعرض النتيجة
echo -e "\n📄 Log file:"
cat output/results.log

echo -e "\n🧾 JSON report:"
cat output/results.json
