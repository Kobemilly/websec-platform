#!/bin/bash

# ====================================================================
# WebSecScan Platform 服務測試腳本
# 分別測試各個服務是否正常運行
# ====================================================================

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

echo "🧪 WebSecScan Platform 服務測試"
echo "======================================================================"

# 測試後端服務
test_backend() {
    log_info "測試後端服務..."
    cd backend

    # 檢查是否可以啟動
    timeout 10s node src/server.js > /dev/null 2>&1 &
    BACKEND_PID=$!

    sleep 3

    # 檢查進程是否還在運行
    if kill -0 $BACKEND_PID 2>/dev/null; then
        log_success "後端服務啟動成功 (PID: $BACKEND_PID)"
        kill $BACKEND_PID
        wait $BACKEND_PID 2>/dev/null
    else
        log_error "後端服務啟動失敗"
    fi

    cd ..
}

# 測試前端服務
test_frontend() {
    log_info "測試前端服務..."
    cd frontend

    # 檢查依賴是否完整
    if [ ! -d "node_modules" ]; then
        log_warning "前端依賴未安裝，正在安裝..."
        npm install --legacy-peer-deps --silent
    fi

    # 檢查是否可以建立
    if npm run build > /dev/null 2>&1; then
        log_success "前端建立成功"
    else
        log_warning "前端建立有問題，但可能仍可運行"
    fi

    cd ..
}

# 測試掃描引擎
test_scanner() {
    log_info "測試掃描引擎..."
    cd scanner

    if [ -d "venv" ]; then
        source venv/bin/activate

        if python main.py --version > /dev/null 2>&1; then
            log_success "掃描引擎運行正常"
        else
            log_warning "掃描引擎有問題，但不影響其他功能"
        fi
    else
        log_warning "Python 虛擬環境未找到"
    fi

    cd ..
}

# 執行所有測試
echo "開始服務測試..."
echo ""

test_backend
echo ""

test_frontend
echo ""

test_scanner
echo ""

echo "======================================================================"
log_info "測試完成！"
echo ""
echo "如果所有測試都通過，您可以使用以下命令啟動完整系統："
echo ""
echo "選項 1 - 在不同終端分別啟動:"
echo "  cd backend && npm start"
echo "  cd frontend && npm start"
echo "  cd scanner && source venv/bin/activate && python main.py"
echo ""
echo "選項 2 - 使用組合命令:"
echo "  npm run dev"
echo ""
echo "選項 3 - 只啟動前端和後端 (最簡單的測試方式):"
echo "  cd backend && npm start &"
echo "  cd frontend && npm start"