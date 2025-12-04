# 🚀 WebSecScan Platform 部署指南

專業網站安全掃描平台的完整部署說明文檔。

## 📋 目錄

- [系統要求](#系統要求)
- [快速開始](#快速開始)
- [npm 方式部署](#npm-方式部署)
- [Docker 方式部署](#docker-方式部署)
- [資料庫設定](#資料庫設定)
- [環境配置](#環境配置)
- [SSL/TLS 配置](#ssltls-配置)
- [監控和日誌](#監控和日誌)
- [故障排除](#故障排除)
- [生產環境建議](#生產環境建議)

## 🖥️ 系統要求

### 最低要求
- **作業系統**: Ubuntu 20.04+ / CentOS 8+ / macOS 10.15+ / Windows 10+
- **CPU**: 2 核心
- **記憶體**: 4GB RAM
- **硬碟**: 20GB 可用空間
- **網路**: 穩定的網路連接

### 建議配置
- **CPU**: 4 核心或更多
- **記憶體**: 8GB RAM 或更多
- **硬碟**: 50GB SSD 存儲
- **網路**: 高速網路連接

### 軟體要求
- **Node.js**: 16.0.0 或更高版本
- **npm**: 8.0.0 或更高版本
- **Python**: 3.9 或更高版本
- **PostgreSQL**: 13 或更高版本
- **MongoDB**: 5.0 或更高版本
- **Redis**: 6.0 或更高版本

### 可選軟體
- **Docker**: 20.10+ (用於容器化部署)
- **Docker Compose**: 2.0+ (用於容器化部署)
- **Nginx**: 1.20+ (用於反向代理)

## ⚡ 快速開始

### 自動安裝 (推薦)

```bash
# 克隆專案
git clone https://github.com/your-org/websec-platform.git
cd websec-platform

# 執行自動安裝腳本
chmod +x scripts/setup.sh
./scripts/setup.sh

# 或者使用 Docker 模式
./scripts/setup.sh --docker
```

### 手動安裝

如果你喜歡手動控制每個步驟，請跳到 [npm 方式部署](#npm-方式部署) 或 [Docker 方式部署](#docker-方式部署)。

## 📦 npm 方式部署

### 1. 克隆專案

```bash
git clone https://github.com/your-org/websec-platform.git
cd websec-platform
```

### 2. 安裝依賴

```bash
# 安裝所有依賴
npm run install:all

# 或者分別安裝
npm install                    # 根目錄依賴
npm run install:backend        # 後端依賴
npm run install:frontend       # 前端依賴
npm run install:scanner        # 掃描引擎依賴
```

### 3. 環境配置

```bash
# 複製環境配置文件
cp .env.example .env

# 編輯配置文件
nano .env  # 或使用你喜歡的編輯器
```

### 4. 資料庫設定

```bash
# 設定 PostgreSQL 和 MongoDB
npm run db:setup

# 或者手動設定
npm run db:postgres:setup
npm run db:mongo:setup
```

### 5. 建立專案

```bash
npm run build
```

### 6. 啟動服務

```bash
# 開發模式 (推薦用於開發)
npm run dev

# 生產模式
npm run start
```

### 7. 驗證部署

訪問以下地址確認服務正常運行：

- **前端應用**: http://localhost:3000
- **後端 API**: http://localhost:8080/api-docs
- **健康檢查**: http://localhost:8080/health

## 🐳 Docker 方式部署

### 1. 前置要求

確保已安裝 Docker 和 Docker Compose：

```bash
# 檢查 Docker 安裝
docker --version
docker-compose --version
```

### 2. 克隆專案

```bash
git clone https://github.com/your-org/websec-platform.git
cd websec-platform
```

### 3. 環境配置

```bash
# 複製並編輯環境配置
cp .env.example .env
nano .env
```

### 4. 建立和啟動服務

```bash
# 建立映像
npm run docker:build

# 啟動所有服務
npm run docker:up

# 查看服務狀態
docker-compose ps
```

### 5. 查看日誌

```bash
# 查看所有服務日誌
npm run docker:logs

# 查看特定服務日誌
docker-compose logs -f backend
docker-compose logs -f scanner
```

### 6. 停止服務

```bash
# 停止服務
npm run docker:down

# 完全清理 (包括數據卷)
npm run docker:clean
```

## 🗄️ 資料庫設定

### PostgreSQL 設定

#### 安裝 PostgreSQL

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
```

**CentOS/RHEL:**
```bash
sudo yum install postgresql postgresql-server postgresql-contrib
sudo postgresql-setup initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

#### 創建資料庫和用戶

```bash
sudo -u postgres psql

CREATE DATABASE websec_db;
CREATE USER websec_user WITH ENCRYPTED PASSWORD 'websec_password';
GRANT ALL PRIVILEGES ON DATABASE websec_db TO websec_user;
ALTER USER websec_user CREATEDB;
\q
```

#### 執行 Schema

```bash
PGPASSWORD=websec_password psql -h localhost -U websec_user -d websec_db -f database/schema.sql
```

### MongoDB 設定

#### 安裝 MongoDB

**Ubuntu/Debian:**
```bash
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-org
sudo systemctl start mongod
sudo systemctl enable mongod
```

**macOS:**
```bash
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb/brew/mongodb-community
```

#### 初始化 MongoDB

```bash
mongosh websec_scans database/mongo-init.js
```

### Redis 設定

#### 安裝 Redis

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install redis-server
```

**CentOS/RHEL:**
```bash
sudo yum install redis
sudo systemctl start redis
sudo systemctl enable redis
```

**macOS:**
```bash
brew install redis
brew services start redis
```

## ⚙️ 環境配置

### 關鍵配置項目

編輯 `.env` 文件中的以下重要配置：

```bash
# 資料庫連接
DB_HOST=localhost
DB_USER=websec_user
DB_PASSWORD=websec_password
MONGODB_URI=mongodb://localhost:27017/websec_scans

# JWT 安全密鑰 (請修改為隨機字串)
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
ENCRYPTION_KEY=your-32-character-encryption-key

# 郵件服務 (用於用戶驗證和通知)
EMAIL_HOST=smtp.gmail.com
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# 掃描引擎配置
SCANNER_MAX_WORKERS=5
SCANNER_TIMEOUT=3600
```

### 生產環境配置

對於生產環境，請務必：

1. **修改所有預設密碼**
2. **使用強隨機密鑰**
3. **啟用 HTTPS**
4. **配置防火牆**
5. **設定定期備份**

## 🔒 SSL/TLS 配置

### 開發環境 (自簽證書)

```bash
# 生成自簽證書
npm run ssl:generate

# 或者手動生成
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/key.pem -out ssl/cert.pem \
    -subj '/CN=localhost'
```

### 生產環境 (Let's Encrypt)

```bash
# 安裝 Certbot
sudo apt install certbot

# 獲取證書
sudo certbot certonly --standalone -d your-domain.com

# 配置自動更新
sudo crontab -e
# 添加: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Nginx 配置

創建 `/etc/nginx/sites-available/websec-platform`:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # 前端
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📊 監控和日誌

### 日誌管理

```bash
# 查看應用日誌
npm run logs

# 查看特定服務日誌
npm run logs:backend
npm run logs:scanner

# 使用 Docker 查看日誌
docker-compose logs -f [service-name]
```

### 健康檢查

```bash
# 檢查所有服務健康狀態
npm run health

# 檢查特定服務
npm run health:backend
npm run health:scanner
```

### 系統監控

使用內建的 Prometheus 和 Grafana 監控：

1. **Prometheus**: http://localhost:9090
2. **Grafana**: http://localhost:3001
   - 用戶名: admin
   - 密碼: admin_password

## 🔧 故障排除

### 常見問題

#### 1. 端口衝突

```bash
# 檢查端口使用情況
lsof -i :3000
lsof -i :8080

# 殺死佔用端口的進程
kill -9 <PID>
```

#### 2. 資料庫連接失敗

```bash
# 檢查 PostgreSQL 狀態
sudo systemctl status postgresql

# 檢查 MongoDB 狀態
sudo systemctl status mongod

# 檢查 Redis 狀態
sudo systemctl status redis
```

#### 3. 權限問題

```bash
# 修復檔案權限
sudo chown -R $USER:$USER .
chmod +x scripts/*.sh
```

#### 4. 記憶體不足

```bash
# 檢查記憶體使用
free -h
top

# 增加 swap 空間
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### 日誌檔案位置

- **應用日誌**: `logs/app.log`
- **掃描日誌**: `logs/scanner.log`
- **Nginx 日誌**: `/var/log/nginx/`
- **PostgreSQL 日誌**: `/var/log/postgresql/`

## 🏭 生產環境建議

### 安全性

1. **防火牆配置**:
   ```bash
   sudo ufw allow ssh
   sudo ufw allow 80
   sudo ufw allow 443
   sudo ufw enable
   ```

2. **定期更新**:
   ```bash
   # 系統更新
   sudo apt update && sudo apt upgrade

   # 應用依賴更新
   npm audit
   npm update
   ```

3. **備份策略**:
   ```bash
   # 設定自動備份
   npm run backup:db

   # 配置 crontab
   0 2 * * * cd /path/to/websec-platform && npm run backup:db
   ```

### 效能優化

1. **資料庫調優**:
   - 配置適當的連接池大小
   - 建立必要的索引
   - 定期清理舊數據

2. **快取配置**:
   - 使用 Redis 進行會話管理
   - 實施 API 響應快取
   - 配置靜態資源快取

3. **負載平衡**:
   - 使用 Nginx 或 HAProxy
   - 配置多個後端實例
   - 實施健康檢查

### 監控設定

1. **應用監控**:
   - 配置 Prometheus 指標收集
   - 設定 Grafana 儀表板
   - 實施警報規則

2. **系統監控**:
   - CPU、記憶體、磁碟使用情況
   - 網路流量監控
   - 服務可用性監控

3. **安全監控**:
   - 掃描結果異常檢測
   - 登入失敗警報
   - 系統入侵檢測

### 災難恢復

1. **資料備份**:
   - 資料庫每日備份
   - 應用程式碼備份
   - 配置檔案備份

2. **恢復程序**:
   - 測試恢復程序
   - 文檔化恢復步驟
   - 定期演練

## 📞 支援與社群

- **GitHub Issues**: https://github.com/your-org/websec-platform/issues
- **文檔**: https://docs.websec-platform.com
- **社群討論**: https://community.websec-platform.com
- **Email**: support@websec-platform.com

## 📄 授權

本專案採用 MIT 授權條款。詳見 [LICENSE](LICENSE) 檔案。

---

**注意**: 這是一個專業的安全工具，請確保在授權的環境中使用，並遵守所有適用的法律法規。