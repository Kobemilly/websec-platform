#!/bin/bash
###############################################################################
# WebSecScan Platform 一鍵啟動腳本
# 遵循 SKILL_SEC 標準: 自動處理 Port 衝突並啟動所有服務
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 需要檢查的 Port
PORTS=(3005 8080 8085)

echo -e "${BLUE}🚀 WebSecScan Platform 啟動程序${NC}"
echo "=================================================="

###############################################################################
# 函數: 檢查 Port 是否被占用
###############################################################################
check_port() {
    local port=$1
    lsof -i :$port -t 2>/dev/null || true
}

###############################################################################
# 函數: 詢問用戶是否清理 Port
###############################################################################
ask_kill_port() {
    local port=$1
    local pids=$2
    
    echo -e "${YELLOW}⚠️  Port $port 被以下 Process 占用:${NC}"
    for pid in $pids; do
        process_name=$(ps -p $pid -o comm= 2>/dev/null || echo "Unknown")
        echo "   PID: $pid | Process: $process_name"
    done
    
    read -p "是否終止這些 Process? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for pid in $pids; do
            echo -e "${GREEN}🔨 終止 PID $pid...${NC}"
            kill -9 $pid 2>/dev/null || true
        done
        sleep 1
        return 0
    else
        return 1
    fi
}

###############################################################################
# 步驟 1: 檢查並清理 Port
###############################################################################
echo -e "\n${BLUE}📋 步驟 1/4: 檢查 Port 占用狀況${NC}"

CONFLICTS=0
for port in "${PORTS[@]}"; do
    pids=$(check_port $port)
    if [ -n "$pids" ]; then
        CONFLICTS=$((CONFLICTS + 1))
        if ! ask_kill_port $port "$pids"; then
            echo -e "${RED}❌ 用戶取消清理 Port $port,無法繼續啟動${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}✅ Port $port 可用${NC}"
    fi
done

if [ $CONFLICTS -eq 0 ]; then
    echo -e "${GREEN}✅ 所有 Port 可用${NC}"
fi

###############################################################################
# 步驟 2: 檢查依賴
###############################################################################
echo -e "\n${BLUE}📋 步驟 2/4: 檢查依賴安裝${NC}"

# 檢查根目錄 node_modules
if [ ! -d "$PROJECT_ROOT/node_modules" ]; then
    echo -e "${YELLOW}⚠️  根目錄依賴未安裝,執行 npm install...${NC}"
    cd "$PROJECT_ROOT" && npm install
fi

# 檢查 backend node_modules
if [ ! -d "$PROJECT_ROOT/backend/node_modules" ]; then
    echo -e "${YELLOW}⚠️  Backend 依賴未安裝,執行 npm install...${NC}"
    cd "$PROJECT_ROOT/backend" && npm install
fi

# 檢查 frontend node_modules
if [ ! -d "$PROJECT_ROOT/frontend/node_modules" ]; then
    echo -e "${YELLOW}⚠️  Frontend 依賴未安裝,執行 npm install...${NC}"
    cd "$PROJECT_ROOT/frontend" && npm install
fi

# 檢查 Python venv
if [ ! -d "$PROJECT_ROOT/scanner/venv" ]; then
    echo -e "${YELLOW}⚠️  Scanner venv 未建立,執行 python -m venv venv...${NC}"
    cd "$PROJECT_ROOT/scanner" && python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi

echo -e "${GREEN}✅ 所有依賴已就緒${NC}"

###############################################################################
# 步驟 3: 檢查配置檔案
###############################################################################
echo -e "\n${BLUE}📋 步驟 3/4: 檢查配置檔案${NC}"

if [ ! -f "$PROJECT_ROOT/backend/.env" ]; then
    echo -e "${YELLOW}⚠️  Backend .env 不存在,從 .env.example 複製${NC}"
    if [ -f "$PROJECT_ROOT/backend/.env.example" ]; then
        cp "$PROJECT_ROOT/backend/.env.example" "$PROJECT_ROOT/backend/.env"
    else
        echo -e "${RED}❌ .env.example 不存在,請手動建立 .env${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✅ 配置檔案已就緒${NC}"

###############################################################################
# 步驟 4: 啟動服務
###############################################################################
echo -e "\n${BLUE}📋 步驟 4/4: 啟動所有服務${NC}"
echo "=================================================="

cd "$PROJECT_ROOT"

echo -e "${GREEN}🚀 啟動中...${NC}"
echo -e "${YELLOW}   使用 Ctrl+C 停止所有服務${NC}\n"

# 使用 npm run dev 啟動
npm run dev
