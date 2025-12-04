#!/bin/bash
###############################################################################
# Port 清理工具
# 快速清理 WebSecScan 使用的所有 Port
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PORTS=(3005 8080 8085)

echo -e "${YELLOW}🔨 清理 Port 占用${NC}\n"

for port in "${PORTS[@]}"; do
    pids=$(lsof -i :$port -t 2>/dev/null || true)
    
    if [ -n "$pids" ]; then
        echo -e "${RED}終止 Port $port 的 Process:${NC}"
        for pid in $pids; do
            process_name=$(ps -p $pid -o comm= 2>/dev/null || echo "Unknown")
            echo "   PID: $pid | Process: $process_name"
            kill -9 $pid 2>/dev/null || true
        done
        echo -e "${GREEN}✅ Port $port 已清理${NC}\n"
    else
        echo -e "${GREEN}✅ Port $port 未被占用${NC}\n"
    fi
done

echo -e "${GREEN}✅ 清理完成${NC}"
