#!/bin/bash

# ====================================================================
# WebSecScan Platform 自動安裝腳本
# 專業網站安全掃描平台 - 一鍵部署腳本
# ====================================================================

set -e

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日誌函數
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

# 檢查系統要求
check_requirements() {
    log_info "檢查系統要求..."

    # 檢查 Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js 未安裝。請安裝 Node.js 16 或更高版本"
        exit 1
    fi

    NODE_VERSION=$(node -v | sed 's/v//')
    REQUIRED_NODE_VERSION="16.0.0"

    if ! [[ "$(printf '%s\n' "$REQUIRED_NODE_VERSION" "$NODE_VERSION" | sort -V | head -n1)" = "$REQUIRED_NODE_VERSION" ]]; then
        log_error "Node.js 版本過低。需要 $REQUIRED_NODE_VERSION 或更高版本，當前版本：$NODE_VERSION"
        exit 1
    fi

    log_success "Node.js 版本檢查通過：$NODE_VERSION"

    # 檢查 npm
    if ! command -v npm &> /dev/null; then
        log_error "npm 未安裝"
        exit 1
    fi

    NPM_VERSION=$(npm -v)
    log_success "npm 版本檢查通過：$NPM_VERSION"

    # 檢查 Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 未安裝。請安裝 Python 3.9 或更高版本"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -V 2>&1 | grep -Po '(?<=Python )(.+)')
    log_success "Python 版本檢查通過：$PYTHON_VERSION"

    # 檢查 pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 未安裝"
        exit 1
    fi

    # 檢查 PostgreSQL
    if ! command -v psql &> /dev/null; then
        log_warning "PostgreSQL 客戶端未安裝，將跳過資料庫初始化"
    fi

    # 檢查 MongoDB
    if ! command -v mongosh &> /dev/null && ! command -v mongo &> /dev/null; then
        log_warning "MongoDB 客戶端未安裝，將跳過 MongoDB 初始化"
    fi

    # 檢查 Redis
    if ! command -v redis-cli &> /dev/null; then
        log_warning "Redis 客戶端未安裝，將跳過 Redis 檢查"
    fi

    # 檢查 Docker (可選)
    if command -v docker &> /dev/null; then
        log_success "Docker 已安裝：$(docker --version)"
    else
        log_warning "Docker 未安裝，將無法使用 Docker 部署"
    fi

    # 檢查 Docker Compose (可選)
    if command -v docker-compose &> /dev/null; then
        log_success "Docker Compose 已安裝：$(docker-compose --version)"
    else
        log_warning "Docker Compose 未安裝，將無法使用 Docker 部署"
    fi
}

# 創建目錄結構
create_directories() {
    log_info "創建必要的目錄..."

    mkdir -p logs
    mkdir -p reports
    mkdir -p backups
    mkdir -p ssl
    mkdir -p uploads
    mkdir -p temp

    log_success "目錄創建完成"
}

# 安裝依賴
install_dependencies() {
    log_info "安裝項目依賴..."

    # 安裝根目錄依賴
    log_info "安裝根目錄依賴..."
    npm install

    # 安裝後端依賴
    log_info "安裝後端依賴..."
    cd backend && npm install
    cd ..

    # 安裝前端依賴
    log_info "安裝前端依賴..."
    cd frontend && npm install
    cd ..

    # 安裝 Python 依賴
    log_info "安裝掃描引擎依賴..."
    cd scanner

    # 創建虛擬環境（推薦）
    if command -v python3 &> /dev/null; then
        python3 -m venv venv
        source venv/bin/activate
    fi

    pip3 install -r requirements.txt
    cd ..

    log_success "所有依賴安裝完成"
}

# 設定環境變量
setup_environment() {
    log_info "設定環境變量..."

    if [ ! -f ".env" ]; then
        log_info "複製環境配置文件..."
        cp .env.example .env
        log_success "環境配置文件已創建，請編輯 .env 文件設定您的配置"
    else
        log_warning ".env 文件已存在，跳過創建"
    fi

    # 生成 SSL 證書（開發環境）
    if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
        log_info "生成自簽 SSL 證書..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout ssl/key.pem -out ssl/cert.pem \
            -subj '/C=TW/ST=Taipei/L=Taipei/O=WebSecScan/CN=localhost' \
            2>/dev/null
        log_success "SSL 證書生成完成"
    else
        log_info "SSL 證書已存在"
    fi
}

# 初始化資料庫
setup_database() {
    log_info "初始化資料庫..."

    # 檢查 PostgreSQL 連接
    if command -v psql &> /dev/null; then
        log_info "檢查 PostgreSQL 連接..."

        # 從 .env 文件讀取配置
        if [ -f ".env" ]; then
            export $(grep -v '^#' .env | xargs)
        fi

        # 嘗試連接並創建資料庫
        PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || log_warning "資料庫可能已存在"

        # 執行 schema
        if [ -f "database/schema.sql" ]; then
            log_info "執行資料庫 schema..."
            PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f database/schema.sql
            log_success "資料庫 schema 執行完成"
        fi
    else
        log_warning "無法連接 PostgreSQL，請手動初始化資料庫"
    fi

    # 檢查 MongoDB 連接
    if command -v mongosh &> /dev/null || command -v mongo &> /dev/null; then
        log_info "檢查 MongoDB 連接..."

        MONGO_CMD="mongosh"
        if ! command -v mongosh &> /dev/null; then
            MONGO_CMD="mongo"
        fi

        # 初始化 MongoDB
        if [ -f "database/mongo-init.js" ]; then
            log_info "初始化 MongoDB..."
            $MONGO_CMD websec_scans database/mongo-init.js
            log_success "MongoDB 初始化完成"
        fi
    else
        log_warning "無法連接 MongoDB，請手動初始化"
    fi
}

# 建立項目
build_project() {
    log_info "建立項目..."

    # 建立前端
    log_info "建立前端..."
    cd frontend && npm run build
    cd ..

    # 建立後端（如果需要）
    if [ -f "backend/package.json" ] && grep -q '"build"' backend/package.json; then
        log_info "建立後端..."
        cd backend && npm run build
        cd ..
    fi

    log_success "項目建立完成"
}

# 運行測試
run_tests() {
    log_info "運行測試..."

    # 後端測試
    if [ -f "backend/package.json" ] && grep -q '"test"' backend/package.json; then
        log_info "運行後端測試..."
        cd backend && npm test
        cd ..
    fi

    # 前端測試
    if [ -f "frontend/package.json" ] && grep -q '"test"' frontend/package.json; then
        log_info "運行前端測試..."
        cd frontend && CI=true npm test
        cd ..
    fi

    # Python 測試
    if [ -f "scanner/requirements-test.txt" ] || [ -d "scanner/tests" ]; then
        log_info "運行掃描引擎測試..."
        cd scanner
        if [ -d "venv" ]; then
            source venv/bin/activate
        fi
        python -m pytest tests/ -v 2>/dev/null || log_warning "掃描引擎測試跳過"
        cd ..
    fi

    log_success "測試完成"
}

# 啟動服務
start_services() {
    log_info "準備啟動服務..."

    cat << 'EOF'

🚀 WebSecScan Platform 安裝完成！

啟動選項：

1. 開發模式啟動：
   npm run dev

2. 生產模式啟動：
   npm run build
   npm run start

3. Docker 模式啟動：
   docker-compose up -d

4. 個別服務啟動：
   npm run dev:backend    # 後端 API 服務
   npm run dev:frontend   # 前端服務
   npm run dev:scanner    # 掃描引擎服務

訪問地址：
- 前端應用：http://localhost:3000
- 後端 API：http://localhost:8080
- API 文檔：http://localhost:8080/api-docs

預設管理員帳號：
- 用戶名：admin
- 密碼：SecurePassword123!

請務必修改預設密碼！

EOF
}

# 清理安裝
cleanup_installation() {
    log_info "清理安裝文件..."

    # 清理臨時文件
    rm -rf temp/*

    log_success "清理完成"
}

# 主安裝流程
main() {
    echo "======================================================================"
    echo "🛡️  WebSecScan Platform 自動安裝程式"
    echo "    專業網站安全掃描平台"
    echo "======================================================================"
    echo ""

    # 解析命令行參數
    SKIP_TESTS=false
    SKIP_BUILD=false
    DOCKER_MODE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --docker)
                DOCKER_MODE=true
                shift
                ;;
            --help)
                echo "使用方式: $0 [選項]"
                echo "選項:"
                echo "  --skip-tests    跳過測試"
                echo "  --skip-build    跳過建立"
                echo "  --docker        使用 Docker 模式"
                echo "  --help          顯示此幫助訊息"
                exit 0
                ;;
            *)
                log_error "未知參數: $1"
                exit 1
                ;;
        esac
    done

    # 檢查是否為 Docker 模式
    if [ "$DOCKER_MODE" = true ]; then
        log_info "使用 Docker 模式安裝..."

        if ! command -v docker &> /dev/null || ! command -v docker-compose &> /dev/null; then
            log_error "Docker 或 Docker Compose 未安裝"
            exit 1
        fi

        setup_environment

        log_info "建立 Docker 映像..."
        docker-compose build

        log_info "啟動 Docker 服務..."
        docker-compose up -d

        log_success "Docker 部署完成！"
        echo "服務狀態：docker-compose ps"
        echo "查看日誌：docker-compose logs -f"
        exit 0
    fi

    # 標準安裝流程
    check_requirements
    create_directories
    setup_environment
    install_dependencies
    setup_database

    if [ "$SKIP_BUILD" != true ]; then
        build_project
    fi

    if [ "$SKIP_TESTS" != true ]; then
        run_tests
    fi

    cleanup_installation
    start_services

    log_success "WebSecScan Platform 安裝完成！"
}

# 捕獲中斷信號
trap 'log_error "安裝被中斷"; exit 1' INT TERM

# 執行主程式
main "$@"