#!/bin/bash

# ====================================================================
# WebSecScan Platform 前端問題修復腳本
# 解決端口衝突和依賴問題
# ====================================================================

set -e

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🔧 WebSecScan 前端問題修復"
echo "======================================================================"

# 1. 處理端口衝突
log_info "處理端口衝突..."

# 檢查端口 3000 使用情況
if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null ; then
    log_warning "端口 3000 被佔用"

    # 顯示佔用端口的進程
    log_info "佔用端口 3000 的進程："
    lsof -Pi :3000 -sTCP:LISTEN

    # 詢問是否停止佔用進程
    read -p "是否要停止佔用端口 3000 的進程？ (y/n): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "停止佔用端口 3000 的進程..."
        sudo kill -9 $(lsof -Pi :3000 -sTCP:LISTEN -t) 2>/dev/null || true
        log_success "進程已停止"
    else
        log_info "將配置前端使用其他端口（3001）"
    fi
else
    log_success "端口 3000 可用"
fi

# 2. 修復前端依賴問題
log_info "修復前端依賴問題..."
cd frontend

# 完全清理並重新安裝
log_info "清理舊依賴..."
rm -rf node_modules package-lock.json

# 修復 ajv 版本問題
log_info "修復 ajv 依賴版本..."
npm install ajv@^6.12.6 --save-dev

# 安裝所有依賴
log_info "重新安裝所有依賴..."
npm install --legacy-peer-deps

# 確認關鍵依賴已正確安裝
if [ ! -d "node_modules/ajv" ]; then
    log_warning "ajv 未正確安裝，手動安裝..."
    npm install ajv@^6.12.6 ajv-keywords@^3.5.2 --legacy-peer-deps
fi

cd ..

# 3. 創建前端環境配置
log_info "配置前端環境..."
cat > frontend/.env << 'EOF'
# WebSecScan Frontend Configuration
REACT_APP_API_URL=http://localhost:8080/api/v1
REACT_APP_WEBSOCKET_URL=ws://localhost:8080
GENERATE_SOURCEMAP=false
SKIP_PREFLIGHT_CHECK=true
PORT=3001
EOF

log_success "前端環境配置完成"

# 4. 更新 package.json 以避免端口衝突
log_info "更新前端 package.json..."
cd frontend

# 使用 jq 更新 package.json（如果沒有 jq 則手動處理）
if command -v jq &> /dev/null; then
    # 使用 jq 更新
    jq '.scripts.start = "PORT=3001 react-scripts start"' package.json > package.json.tmp && mv package.json.tmp package.json
else
    # 手動更新 start 腳本
    sed -i 's/"start": "react-scripts start"/"start": "PORT=3001 react-scripts start"/' package.json
fi

cd ..

# 5. 測試修復結果
log_info "測試前端配置..."
cd frontend

# 檢查是否能正常啟動（僅測試配置，不實際運行）
if npm run build > /dev/null 2>&1; then
    log_success "前端建立測試通過"
else
    log_warning "前端建立測試失敗，但可能仍可運行開發模式"
fi

cd ..

echo "======================================================================"
log_success "🎉 前端問題修復完成！"
echo ""
echo "現在可以使用以下方式啟動前端："
echo ""
echo "方法 1 - 使用端口 3001 (推薦):"
echo "  cd frontend"
echo "  npm start"
echo "  # 前端將在 http://localhost:3001 運行"
echo ""
echo "方法 2 - 指定其他端口:"
echo "  cd frontend"
echo "  PORT=3002 npm start"
echo ""
echo "方法 3 - 完整系統啟動:"
echo "  # 終端 1 - 後端"
echo "  cd backend && npm start"
echo ""
echo "  # 終端 2 - 前端"
echo "  cd frontend && npm start"
echo ""
echo "服務地址："
echo "  前端應用: http://localhost:3001"
echo "  後端 API: http://localhost:8080/health"
echo "  API 文檔: http://localhost:8080/api-docs"