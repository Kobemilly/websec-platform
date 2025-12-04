# WebSecScan 平台開發總結

## 專案概述
企業級 OWASP Top 10 網站安全掃描平台，提供自動化漏洞檢測、實時進度監控和專業報告生成。

**GitHub 倉庫**: https://github.com/Kobemilly/websec-platform

## 技術架構

### 後端 (Node.js)
- **框架**: Express 4.18
- **端口**: 8085 (0.0.0.0)
- **功能**: 
  - API 路由管理
  - Python 掃描器調度
  - 掃描結果處理
  - 實時進度追蹤

### 前端 (Pure HTML/JS)
- **服務**: serve (port 3005)
- **功能**:
  - 掃描任務管理
  - 實時進度顯示
  - 漏洞詳情展示（可折疊）
  - 報告導出

### 掃描引擎 (Python)
- **框架**: asyncio + aiohttp
- **入口**: `scanner/main_cli.py`
- **模組**: 7 個安全掃描器

## 核心功能實現

### 1. 外部化規則庫系統
**目標**: 將硬編碼的漏洞檢測規則提取到 JSON 文件

**實現文件**:
```
scanner/rules/
├── manifest.json          # 規則清單
├── sql_injection.json     # 12 payloads, 17 error patterns
├── xss_payloads.json      # 14 payloads, 9 detection patterns
└── csrf_patterns.json     # 11 token names, 13 sensitive actions
```

**掃描器改造**:
- `sql_injection_scanner.py`: 從 JSON 加載 payloads 和 error patterns
- `xss_scanner.py`: 從 JSON 加載 XSS payloads 和檢測模式
- `csrf_scanner.py`: 從 JSON 加載 token 名稱和敏感操作
- 支援熱重載 (`reload_rules()` 方法)

**規則 JSON 結構**:
```json
{
  "version": "1.0.0",
  "last_updated": "2025-12-04",
  "payloads": [
    {
      "id": "sql_001",
      "payload": "' OR '1'='1",
      "category": "authentication_bypass",
      "detection_method": "error_based",
      "severity": "high",
      "enabled": true
    }
  ],
  "error_patterns": [
    "MySQL syntax error",
    "PostgreSQL ERROR:"
  ]
}
```

### 2. 專業漏洞報告模板
**目標**: 提供詳細、專業的漏洞描述而非簡化文字

**實現文件**:
```
scanner/templates/vulnerability_templates.json
scanner/utils/vulnerability_templates.py
```

**模板內容包含**:
- CVSS 3.1 評分 (Base Score + Vector String)
- 詳細技術描述
- 攻擊場景示例
- 具體修復建議（含代碼示例）
- 參考資源連結

**示例模板** (HTTP 無加密):
```json
{
  "http_no_encryption": {
    "title": "HTTP 協議未加密傳輸",
    "description": "目標網站使用 HTTP 協議...",
    "severity": "medium",
    "cvss_score": 7.4,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "remediation": {
      "summary": "啟用 HTTPS...",
      "steps": [
        "1. 獲取 SSL/TLS 證書",
        "2. 配置 Web 伺服器"
      ],
      "code_examples": {
        "nginx": "...",
        "apache": "..."
      }
    }
  }
}
```

**整合到掃描器**:
- `ssl_tls_scanner.py`: 使用 `http_no_encryption` 模板
- `info_disclosure_scanner.py`: 使用 `info_disclosure_server` 模板

### 3. Python 命令列掃描器
**目標**: 讓後端能夠通過命令列參數調用掃描器

**創建**: `scanner/main_cli.py`

**支援參數**:
```bash
python3 main_cli.py \
  --target http://example.com \
  --scan-type comprehensive \
  --modules ssl_tls,info_disclosure \
  --scan-id scan_123456 \
  --output-dir results \
  --output-format json
```

**關鍵修復**:
1. **Async Context Manager**: 使用 `async with engine` 初始化 aiohttp session
2. **Progress Callback**: 改為 async 函數避免 await 錯誤
3. **模組名稱對應**: 使用正確的模組名稱 (ssl_tls vs ssl_tls_scanner)
4. **結果序列化**: VulnerabilityResult 對象轉換為字典

### 4. 後端整合 Python 掃描器
**修改**: `backend/src/server.js`

**關鍵改進**:
```javascript
// 1. 調用 Python scanner 而非模擬數據
const pythonArgs = [
  SCANNER_MAIN,  // main_cli.py
  '--target', scanSession.url,
  '--scan-type', scanSession.scan_type,
  '--scan-id', scanSession.id,  // 關鍵: 傳遞掃描 ID
  '--modules', scanSession.modules.join(',')
];

// 2. 解析進度輸出 (stderr)
const progressMatch = error.match(/Progress: (\d+)%/);
const messageMatch = error.match(/Status: (.+)/);

// 3. 讀取完整結果保留所有字段
const scanResults = JSON.parse(resultData);
scanSession.results = scanResults;  // 不轉換，直接使用

// 4. 完善統計數據
scanSession.statistics = {
  total_requests: scanResults.statistics?.total_requests || 0,
  successful_requests: scanResults.statistics?.successful_requests || 0,
  failed_requests: scanResults.statistics?.failed_requests || 0,
  modules_executed: scanResults.statistics?.modules_executed || 0,
  pages_scanned: scanResults.statistics?.pages_scanned || 0,
  vulnerabilities_found: scanResults.vulnerabilities?.length || 0
};
```

### 5. 前端漏洞詳情增強
**修改**: `frontend/public/index.html` 的 `displayResults()` 函數

**新增顯示內容**:

**基本卡片**:
- 📍 漏洞標題 + 嚴重程度徽章
- 🎯 風險評分徽章 (risk_score)
- ✓ 信心度徽章 (confidence: likely/confirmed/possible)
- 🔖 CWE 分類 (CWE-200)
- 🛡️ OWASP 分類 (A02:2021)
- 🔗 可點擊的受影響 URL

**可折疊詳情區** (點擊展開/收起):
- 💡 **修復建議**: 格式化的 pre 區塊，保留換行和縮排
- 📤 **請求詳情**: HTTP 方法、Payload
- 🔍 **響應證據**: 黃色背景區塊，限制高度可滾動
- ⏱️ **發現時間**: 時間戳顯示

**視覺優化**:
```javascript
// 多徽章並排
badges.style.display = 'flex';
badges.style.gap = '0.5rem';

// 格式化修復建議
recText.style.whiteSpace = 'pre-wrap';
recText.style.background = '#f8f9fa';
recText.style.padding = '0.75rem';

// 響應證據高亮
evidText.style.background = '#fff3cd';
evidText.style.maxHeight = '150px';
evidText.style.overflow = 'auto';
```

## 開發環境配置

### VS Code Remote SSH + Port Forwarding
**主機**: 10.64.11.49

**端口轉發**:
- 3005 → Frontend (serve)
- 8085 → Backend (Node.js Express)
- 3030 → OWASP Juice Shop (測試目標)

**啟動命令**:
```bash
cd /root/.claude/skills/my-skill/websec-platform
npm start  # 啟動 backend, frontend, scanner
```

### Docker 測試環境
**OWASP Juice Shop**:
```bash
docker run -d -p 3030:3000 bkimminich/juice-shop
```

**bWAPP**:
```bash
docker run -d -p 8082:80 raesene/bwapp
```

## 重要問題修復記錄

### 問題 1: 掃描失敗 - "無法讀取掃描結果"
**原因**: 
- 後端期待 `scan_result_${scanId}.json`
- 但 Python scanner 生成的 scan_id 不同

**解決**: 
- 後端添加 `--scan-id` 參數傳遞給 Python
- 確保文件名一致

### 問題 2: "object NoneType can't be used in 'await' expression"
**原因**: 
- `progress_callback` 是普通函數
- 但在 scanner_engine.py 中被 `await` 調用

**解決**:
```python
# 改為 async 函數
async def progress_callback(percent, message):
    print(f"Progress: {int(percent)}%", file=sys.stderr, flush=True)
```

### 問題 3: "'NoneType' object has no attribute 'get'"
**原因**: 
- ScannerEngine 的 `self.session` 未初始化
- 沒有使用 async context manager

**解決**:
```python
# 使用 async with
async with engine:
    scan_result = await engine.scan_target(scan_target, progress_callback)
```

### 問題 4: 模組未執行 (modules_executed: 0)
**原因**: 
- 模組名稱不匹配
- CLI 傳遞 `ssl_tls_scanner`
- 但註冊的是 `ssl_tls`

**解決**:
```python
# 修改默認模組名稱
modules = ['sql_injection', 'xss', 'csrf', 'ssl_tls', 'info_disclosure']
```

### 問題 5: 掃描進度統計不更新
**原因**: 
- `vulnerabilities_found` 字段缺失
- 後端只複製 statistics 未計算漏洞數

**解決**:
```javascript
scanSession.statistics = {
  ...scanResults.statistics,
  vulnerabilities_found: scanResults.vulnerabilities?.length || 0
};
```

### 問題 6: 前端漏洞顯示過於簡化
**原因**: 
- 只顯示 title, url, description, recommendation
- 未展示 risk_score, confidence, CWE, OWASP 等字段

**解決**: 
- 重寫 `displayResults()` 函數
- 添加徽章、可折疊區塊、格式化顯示

## 測試驗證

### 成功掃描示例
```bash
# 掃描 Juice Shop
curl -X POST http://localhost:8085/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://10.64.11.49:3030",
    "scan_type": "basic",
    "modules": ["ssl_tls", "info_disclosure"]
  }'

# 結果
{
  "scan_id": "scan_1764830941644_d1a50ad1",
  "status": "completed",
  "vulnerabilities": 46,  // 發現 46 個漏洞
  "statistics": {
    "pages_scanned": 14,
    "modules_executed": 2,
    "vulnerabilities_found": 46
  },
  "risk_score": 5.87
}
```

### 漏洞發現統計
- 敏感文件洩露: 多個 (.env, config.php, wp-config.php 等)
- 信息洩露: Phone, Email 等敏感資訊
- 所有漏洞包含完整的模板字段

## 檔案結構

```
websec-platform/
├── backend/
│   ├── src/
│   │   ├── server.js           # 主服務器（已改進）
│   │   ├── routes/scans.js     # API 路由
│   │   └── services/
│   └── package.json
├── frontend/
│   └── public/
│       └── index.html          # 前端頁面（已增強）
├── scanner/
│   ├── main_cli.py             # 命令列入口（新增）
│   ├── core/
│   │   └── scanner_engine.py  # 掃描引擎核心
│   ├── modules/                # 7 個掃描模組
│   │   ├── sql_injection_scanner.py    # 已改造
│   │   ├── xss_scanner.py              # 已改造
│   │   ├── csrf_scanner.py             # 已改造
│   │   ├── ssl_tls_scanner.py          # 已整合模板
│   │   └── info_disclosure_scanner.py  # 已整合模板
│   ├── rules/                  # 外部規則庫（新增）
│   │   ├── manifest.json
│   │   ├── sql_injection.json
│   │   ├── xss_payloads.json
│   │   └── csrf_patterns.json
│   ├── templates/              # 漏洞模板（新增）
│   │   └── vulnerability_templates.json
│   └── utils/
│       └── vulnerability_templates.py  # 模板管理器（新增）
├── README.md
├── RULES_UPDATE_GUIDE.md       # 規則更新指南
├── PROJECT_SUMMARY.md          # 本文檔
└── .gitignore
```

## Git 版本控制

### 初始提交
```bash
git init
git add .
git commit -m "feat: WebSecScan 企業級安全掃描平台 v1.0"
git branch -M main
```

### GitHub 推送
```bash
# 使用 GitHub CLI
gh repo create kobemilly/websec-platform \
  --public \
  --description "Enterprise OWASP Top 10 Security Scanning Platform" \
  --source=. \
  --push

# 結果
✓ Created repository Kobemilly/websec-platform
✓ Pushed 97 objects (408.76 KiB)
✓ 74 files, 55,520 insertions
```

**倉庫地址**: https://github.com/Kobemilly/websec-platform

## 未來改進方向

### 1. 完整的模板覆蓋
- 為所有 7 個掃描模組創建專業模板
- 每個漏洞類型包含詳細的 CVSS 評分
- 提供多種語言的修復代碼示例

### 2. 請求統計改進
- 在 scanner_engine.py 中追蹤實際 HTTP 請求數
- 更新 `total_requests`, `successful_requests`, `failed_requests`
- 實時更新到前端進度條

### 3. 掃描器性能優化
- 實現請求緩存減少重複掃描
- 支援斷點續傳
- 優化並發控制策略

### 4. 報告導出增強
- 完整的 PDF 報告生成（含圖表）
- HTML 報告模板
- Excel 格式導出

### 5. 用戶認證系統
- 實現 JWT 認證
- 用戶角色權限管理
- 掃描歷史記錄

### 6. 測試覆蓋
- 單元測試 (Python pytest)
- API 集成測試 (Jest)
- E2E 測試 (Playwright)

## 關鍵學習點

1. **異步編程**: Python asyncio 與 Node.js 的協作
2. **進程通信**: Node.js spawn Python 進程並解析輸出
3. **數據序列化**: Python dataclass → JSON → JavaScript Object
4. **前端優化**: 可折疊元素、動態內容渲染
5. **Git 工作流**: GitHub CLI 快速創建和推送倉庫

## 部署指南

### 生產環境要求
- Node.js 16+
- Python 3.9+
- 2GB+ RAM
- Linux/Unix 系統

### 快速啟動
```bash
# 1. 克隆倉庫
git clone https://github.com/Kobemilly/websec-platform.git
cd websec-platform

# 2. 安裝依賴
npm install
cd scanner && pip3 install -r requirements.txt && cd ..

# 3. 啟動服務
npm start

# 4. 訪問
# Frontend: http://localhost:3005
# Backend: http://localhost:8085
```

---

**開發日期**: 2025-12-04  
**版本**: v1.0  
**作者**: kobemilly  
**倉庫**: https://github.com/Kobemilly/websec-platform
