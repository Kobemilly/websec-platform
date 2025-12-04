# 漏洞規則更新指南

## 概述

WebSecScan 平台現已支援**檔案型規則庫**,所有漏洞檢測規則已從程式碼中抽取到 JSON 檔案。這使得規則更新更加靈活,無需修改程式碼即可新增或調整檢測規則。

## 規則檔案位置

```
scanner/rules/
├── manifest.json          # 規則版本清單
├── sql_injection.json     # SQL 注入規則
├── xss_payloads.json      # XSS 跨站腳本規則
├── csrf_patterns.json     # CSRF 跨站請求偽造規則
└── backups/              # 規則備份目錄
```

## 規則檔案格式

### SQL Injection (sql_injection.json)

```json
{
  "version": "1.0.0",
  "last_updated": "2025-01-26T10:00:00Z",
  "description": "SQL 注入漏洞檢測規則庫",
  "payloads": [
    {
      "id": "sqli-001",
      "payload": "'",
      "description": "單引號錯誤測試",
      "detection_method": "error",
      "severity": "high",
      "enabled": true,
      "expected_response": "",
      "sleep_time": 0
    }
  ],
  "error_patterns": [
    {
      "id": "err-001",
      "pattern": "SQL syntax.*?error",
      "database": "generic",
      "confidence": "high",
      "enabled": true
    }
  ]
}
```

### XSS (xss_payloads.json)

```json
{
  "version": "1.0.0",
  "last_updated": "2025-01-26T10:00:00Z",
  "description": "XSS 漏洞檢測規則庫",
  "payloads": [
    {
      "id": "xss-001",
      "payload": "<script>alert(\"XSS\")</script>",
      "description": "Basic script alert",
      "type": "reflected",
      "severity": "high",
      "category": "basic",
      "enabled": true
    }
  ],
  "detection_patterns": [
    {
      "id": "det-001",
      "pattern": "<script[^>]*>.*?alert.*?</script>",
      "description": "Script tag with alert",
      "confidence": "high"
    }
  ],
  "input_patterns": [
    "input[type=\"text\"]",
    "textarea",
    "[contenteditable]"
  ]
}
```

### CSRF (csrf_patterns.json)

```json
{
  "version": "1.0.0",
  "last_updated": "2025-01-26T10:00:00Z",
  "description": "CSRF 漏洞檢測規則庫",
  "csrf_token_names": [
    "csrf_token",
    "csrftoken",
    "_token"
  ],
  "sensitive_actions": [
    "login",
    "delete",
    "update"
  ],
  "detection_rules": [
    {
      "id": "csrf-001",
      "name": "Missing CSRF Token",
      "description": "表單缺少 CSRF 令牌",
      "severity": "high",
      "enabled": true
    }
  ]
}
```

## 如何更新規則

### 方式 1: 直接編輯 JSON 檔案

1. **備份現有規則**
   ```bash
   cd scanner/rules
   cp sql_injection.json backups/sql_injection_$(date +%Y%m%d).json
   ```

2. **編輯規則檔案**
   ```bash
   vi sql_injection.json
   ```

3. **新增或修改規則項目**
   - 確保 `id` 欄位唯一
   - 設定適當的 `severity` (low, medium, high, critical)
   - 使用 `enabled: false` 暫時停用規則
   - 更新檔案頂部的 `last_updated` 時間戳記

4. **驗證 JSON 格式**
   ```bash
   python -m json.tool sql_injection.json > /dev/null && echo "✅ JSON 格式正確"
   ```

### 方式 2: 程式化更新

```python
import json
from datetime import datetime

# 讀取現有規則
with open('scanner/rules/sql_injection.json', 'r') as f:
    rules = json.load(f)

# 新增新規則
new_payload = {
    "id": "sqli-014",
    "payload": "'; DROP TABLE users--",
    "description": "經典 Drop Table 攻擊",
    "detection_method": "error",
    "severity": "critical",
    "enabled": True
}
rules['payloads'].append(new_payload)

# 更新時間戳記
rules['last_updated'] = datetime.utcnow().isoformat() + 'Z'

# 儲存更新
with open('scanner/rules/sql_injection.json', 'w') as f:
    json.dump(rules, f, indent=2, ensure_ascii=False)
```

## 規則重新載入

### 自動載入 (重啟掃描器)

規則會在掃描器啟動時自動載入:

```bash
cd scanner
python main.py
```

### 熱重載 (不重啟)

透過 Python API 重新載入規則:

```python
from modules.sql_injection_scanner import SQLInjectionScanner

scanner = SQLInjectionScanner()
# 更新規則檔案後...
scanner.reload_rules()  # 重新載入規則
```

## 版本管理

### 更新 manifest.json

每次更新規則後,記得更新 `manifest.json`:

```json
{
  "version": "1.1.0",
  "rules_files": [
    {
      "name": "sql_injection.json",
      "version": "1.1.0",
      "last_updated": "2025-01-26T12:00:00Z",
      "payload_count": 14
    }
  ],
  "changelog": [
    {
      "version": "1.1.0",
      "date": "2025-01-26",
      "changes": [
        "新增 2 個 SQL 注入 payloads",
        "修正錯誤模式 regex"
      ]
    }
  ]
}
```

## 規則啟用/停用

### 停用特定規則

在 JSON 中將 `enabled` 設為 `false`:

```json
{
  "id": "sqli-005",
  "payload": "...",
  "enabled": false  // 此規則將被跳過
}
```

### 批次停用

```python
import json

with open('scanner/rules/sql_injection.json', 'r+') as f:
    rules = json.load(f)
    
    # 停用所有時間型盲注規則
    for payload in rules['payloads']:
        if payload['detection_method'] == 'time':
            payload['enabled'] = False
    
    f.seek(0)
    json.dump(rules, f, indent=2)
    f.truncate()
```

## 規則測試

### 驗證規則載入

```bash
cd scanner
python -c "
from modules.sql_injection_scanner import SQLInjectionScanner
scanner = SQLInjectionScanner()
print(f'Loaded {len(scanner.payloads)} payloads')
print(f'Loaded {len(scanner.error_patterns)} error patterns')
"
```

### 測試單一 Payload

```python
import asyncio
import aiohttp
from modules.sql_injection_scanner import SQLInjectionScanner

async def test_payload():
    scanner = SQLInjectionScanner()
    async with aiohttp.ClientSession() as session:
        # 測試特定 payload
        target_url = "http://testsite.com/api/user?id=1"
        results = await scanner.scan(session, {'url': target_url}, [target_url])
        print(f"Found {len(results)} vulnerabilities")

asyncio.run(test_payload())
```

## 最佳實務

1. **備份優先**: 修改前務必備份原始規則
2. **增量更新**: 一次只更新少量規則,便於驗證
3. **版本標記**: 更新 version 和 last_updated 欄位
4. **測試驗證**: 更新後先在測試環境驗證
5. **文件記錄**: 在 changelog 記錄變更原因
6. **審查機制**: 重要規則變更需經過 code review

## 常見問題

### Q: 規則更新後沒有生效?

A: 確認以下事項:
- JSON 格式正確 (`python -m json.tool <file>`)
- 規則的 `enabled` 欄位為 `true`
- 已執行 `reload_rules()` 或重啟掃描器
- 檔案路徑正確 (`scanner/rules/`)

### Q: 如何回滾到舊版本規則?

A: 從備份目錄還原:
```bash
cp backups/sql_injection_20250126.json sql_injection.json
```

### Q: 可以動態新增規則嗎?

A: 可以!透過 API 或管理介面更新 JSON 檔案後,呼叫 `reload_rules()` 即可。

## 相關文件

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
