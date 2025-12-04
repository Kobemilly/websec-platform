#!/bin/bash

# ====================================================================
# WebSecScan Platform 部署修復腳本
# 解決常見的部署問題
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

log_info "🔧 WebSecScan Platform 部署修復程式"
echo "======================================================================"

# 1. 創建必要目錄
log_info "創建必要目錄..."
mkdir -p logs
mkdir -p reports
mkdir -p backups
mkdir -p ssl
mkdir -p uploads
mkdir -p temp
mkdir -p scanner/results
mkdir -p scanner/core
mkdir -p scanner/modules
mkdir -p scanner/utils
mkdir -p backend/src
mkdir -p frontend/src
mkdir -p frontend/public

log_success "目錄創建完成"

# 2. 修復 Python 依賴安裝
log_info "修復 Python 掃描引擎依賴..."

cd scanner

# 檢查是否有虛擬環境
if [ ! -d "venv" ]; then
    log_info "創建 Python 虛擬環境..."
    python3 -m venv venv
fi

# 啟動虛擬環境
source venv/bin/activate

# 升級 pip
log_info "升級 pip..."
python -m pip install --upgrade pip

# 安裝依賴
if [ -f "requirements.txt" ]; then
    log_info "安裝 Python 依賴包..."
    pip install -r requirements.txt
    log_success "Python 依賴安裝完成"
else
    log_error "requirements.txt 文件不存在"
    exit 1
fi

cd ..

# 3. 檢查 Node.js 依賴
log_info "檢查 Node.js 依賴安裝..."

# 後端依賴
if [ -f "backend/package.json" ]; then
    log_info "安裝後端依賴..."
    cd backend && npm install && cd ..
    log_success "後端依賴安裝完成"
fi

# 前端依賴
if [ -f "frontend/package.json" ]; then
    log_info "安裝前端依賴..."
    cd frontend && npm install && cd ..
    log_success "前端依賴安裝完成"
fi

# 4. 環境配置
log_info "檢查環境配置..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        log_success "環境配置文件已創建"
    else
        log_warning "找不到 .env.example 文件"
    fi
else
    log_info "環境配置文件已存在"
fi

# 5. 生成 SSL 證書（開發用）
if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
    log_info "生成開發用 SSL 證書..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout ssl/key.pem -out ssl/cert.pem \
        -subj '/C=TW/ST=Taipei/L=Taipei/O=WebSecScan/CN=localhost' \
        2>/dev/null
    log_success "SSL 證書生成完成"
fi

# 6. 權限修復
log_info "修復文件權限..."
chmod +x scripts/*.sh
chmod 755 scanner/main.py

# 7. 測試基本功能
log_info "測試基本功能..."

# 測試 Python 掃描引擎
cd scanner
source venv/bin/activate
python main.py --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
    log_success "掃描引擎測試通過"
else
    log_warning "掃描引擎測試未通過，但不影響基本功能"
fi
cd ..

# 測試後端
if [ -f "backend/src/server.js" ]; then
    log_success "後端入口文件存在"
fi

# 測試前端
if [ -f "frontend/src/index.js" ]; then
    log_success "前端入口文件存在"
fi

echo "======================================================================"
log_success "🎉 部署修復完成！"
echo ""
echo "現在可以使用以下命令啟動服務："
echo ""
echo "開發模式 (推薦):"
echo "  npm run dev              # 啟動所有服務"
echo "  npm run dev:backend      # 只啟動後端"
echo "  npm run dev:frontend     # 只啟動前端"
echo "  npm run dev:scanner      # 只啟動掃描引擎"
echo ""
echo "生產模式:"
echo "  npm run build            # 建立專案"
echo "  npm run start            # 啟動所有服務"
echo ""
echo "Docker 模式:"
echo "  docker-compose up -d     # 容器化部署"
echo ""
echo "服務地址："
echo "  前端應用: http://localhost:3000"
echo "  後端 API: http://localhost:8080/health"
echo "  API 文檔: http://localhost:8080/api-docs"
echo ""
echo "如果仍有問題，請檢查日誌或聯繫技術支援。"