# 🛡️ Security Scan Report

## 📊 Summary
- **Total Findings:** 3
- **Affected Files:** 2
- **Scan Date:** 2025-11-01 21:15:06

---

## 📄 Details

| File | Line | Rule | Match |
|------|------|------|-------|
| `test.js` | 4 | `token\s*[:=]\s*['"][^'"]+['"];?` | `token = "ghp_ABC123DEF456";` |
| `tmp.secret.js` | 3 | `password\s*[:=]\s*['"][^'"]+['"];?` | `password = 'mySuperSecretPassword123';` |
| `tmp.secret.js` | 4 | `token\s*[:=]\s*['"][^'"]+['"];?` | `token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";` |
