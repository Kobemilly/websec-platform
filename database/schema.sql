-- ====================================================================
-- WebSecScan 資料庫架構設計
-- 專業網站安全掃描平台數據庫 Schema
-- ====================================================================

-- 創建擴展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ====================================================================
-- 用戶管理相關表
-- ====================================================================

-- 用戶表
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    organization VARCHAR(255),
    department VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_role CHECK (role IN ('admin', 'manager', 'analyst', 'user')),
    CONSTRAINT check_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- 用戶會話表
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(512) NOT NULL,
    refresh_token VARCHAR(512),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 用戶權限表
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(user_id, resource, action)
);

-- API 密鑰表
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(20) NOT NULL,
    scopes JSON,
    rate_limit_per_hour INTEGER DEFAULT 1000,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ====================================================================
-- 組織和團隊管理
-- ====================================================================

-- 組織表
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    industry VARCHAR(100),
    size VARCHAR(50),
    country VARCHAR(100),
    subscription_plan VARCHAR(50) DEFAULT 'basic',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 團隊表
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(organization_id, name)
);

-- 團隊成員表
CREATE TABLE team_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(team_id, user_id),
    CONSTRAINT check_team_role CHECK (role IN ('owner', 'admin', 'member'))
);

-- ====================================================================
-- 資產管理
-- ====================================================================

-- 資產組別表
CREATE TABLE asset_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    tags JSON,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(organization_id, name)
);

-- 掃描目標表
CREATE TABLE scan_targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_group_id UUID REFERENCES asset_groups(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    description TEXT,
    target_type VARCHAR(50) NOT NULL DEFAULT 'web_application',
    scan_type VARCHAR(50) NOT NULL DEFAULT 'comprehensive',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    is_active BOOLEAN DEFAULT true,

    -- 掃描配置
    scan_modules JSON,
    scan_schedule VARCHAR(255),
    max_concurrent_scans INTEGER DEFAULT 1,
    timeout_seconds INTEGER DEFAULT 3600,

    -- 認證配置
    authentication_type VARCHAR(50),
    auth_credentials JSON, -- 加密存儲

    -- 網路配置
    use_proxy BOOLEAN DEFAULT false,
    proxy_config JSON,
    custom_headers JSON,

    -- 標籤和分類
    tags JSON,
    business_criticality VARCHAR(20) DEFAULT 'medium',
    compliance_requirements JSON,

    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_target_type CHECK (target_type IN ('web_application', 'api', 'mobile_api', 'web_service')),
    CONSTRAINT check_scan_type CHECK (scan_type IN ('basic', 'comprehensive', 'owasp', 'api', 'custom')),
    CONSTRAINT check_priority CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT check_business_criticality CHECK (business_criticality IN ('critical', 'high', 'medium', 'low'))
);

-- ====================================================================
-- 掃描任務管理
-- ====================================================================

-- 掃描任務表
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id),
    name VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'queued',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',

    -- 掃描配置
    scan_type VARCHAR(50) NOT NULL,
    scan_modules JSON NOT NULL,
    configuration JSON,

    -- 時間管理
    scheduled_at TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    estimated_duration INTEGER, -- 秒
    actual_duration INTEGER, -- 秒

    -- 進度追蹤
    progress INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    steps_completed INTEGER DEFAULT 0,
    total_steps INTEGER,

    -- 結果統計
    vulnerabilities_found INTEGER DEFAULT 0,
    risk_score DECIMAL(4,2),

    -- 錯誤處理
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,

    -- 資源使用
    worker_node VARCHAR(255),
    memory_usage_mb INTEGER,
    cpu_usage_percent DECIMAL(5,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_status CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'scheduled')),
    CONSTRAINT check_progress CHECK (progress >= 0 AND progress <= 100)
);

-- 掃描任務日誌表
CREATE TABLE scan_job_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    log_level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    details JSON,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_log_level CHECK (log_level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'))
);

-- ====================================================================
-- 漏洞管理
-- ====================================================================

-- 漏洞類別表
CREATE TABLE vulnerability_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    owasp_mapping VARCHAR(50),
    cwe_mapping VARCHAR(50),
    severity_default VARCHAR(20),
    remediation_template TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 漏洞表（存儲在 PostgreSQL 用於查詢效能）
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    category_id UUID REFERENCES vulnerability_categories(id),

    -- 基本資訊
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    risk_score DECIMAL(4,2),

    -- 分類資訊
    cwe_id VARCHAR(20),
    owasp_category VARCHAR(100),
    vulnerability_type VARCHAR(100),

    -- 位置資訊
    affected_url VARCHAR(2048),
    request_method VARCHAR(10),
    parameter_name VARCHAR(255),
    injection_point VARCHAR(255),

    -- 驗證資訊
    request_payload TEXT,
    response_evidence TEXT,

    -- 修復建議
    remediation TEXT,
    references JSON,

    -- 狀態管理
    status VARCHAR(50) DEFAULT 'open',
    false_positive BOOLEAN DEFAULT false,
    verified BOOLEAN DEFAULT false,
    assigned_to UUID REFERENCES users(id),

    -- 修復追蹤
    resolution_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),

    -- 時間戳
    first_found_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT check_confidence CHECK (confidence IN ('confirmed', 'likely', 'possible', 'false_positive')),
    CONSTRAINT check_status CHECK (status IN ('open', 'in_progress', 'resolved', 'wont_fix', 'duplicate'))
);

-- 漏洞歷史表（追蹤變更）
CREATE TABLE vulnerability_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    field_name VARCHAR(100) NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by UUID REFERENCES users(id),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reason TEXT
);

-- ====================================================================
-- 報告管理
-- ====================================================================

-- 報告模板表
CREATE TABLE report_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    template_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,
    template_content JSON NOT NULL,
    is_default BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_template_type CHECK (template_type IN ('executive', 'technical', 'compliance', 'custom')),
    CONSTRAINT check_format CHECK (format IN ('pdf', 'html', 'excel', 'csv', 'json'))
);

-- 報告表
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    template_id UUID REFERENCES report_templates(id),
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    format VARCHAR(20) NOT NULL,

    -- 報告範圍
    target_ids JSON, -- Array of target IDs
    job_ids JSON, -- Array of job IDs
    date_range_start TIMESTAMP WITH TIME ZONE,
    date_range_end TIMESTAMP WITH TIME ZONE,

    -- 報告內容配置
    include_executive_summary BOOLEAN DEFAULT true,
    include_technical_details BOOLEAN DEFAULT true,
    include_remediation BOOLEAN DEFAULT true,
    include_compliance_mapping BOOLEAN DEFAULT false,
    compliance_standard VARCHAR(50),

    -- 報告狀態
    status VARCHAR(50) DEFAULT 'generating',
    progress INTEGER DEFAULT 0,

    -- 檔案資訊
    file_path VARCHAR(1024),
    file_size BIGINT,
    file_hash VARCHAR(128),

    -- 分享設定
    is_public BOOLEAN DEFAULT false,
    share_token VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE,

    generated_by UUID REFERENCES users(id),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_report_type CHECK (report_type IN ('executive', 'technical', 'compliance', 'custom')),
    CONSTRAINT check_report_status CHECK (status IN ('generating', 'completed', 'failed', 'expired'))
);

-- ====================================================================
-- 系統配置和設定
-- ====================================================================

-- 系統配置表
CREATE TABLE system_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    category VARCHAR(100) NOT NULL,
    key VARCHAR(255) NOT NULL,
    value JSON,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT false,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(category, key)
);

-- 審計日誌表
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    organization_id UUID REFERENCES organizations(id),
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    action VARCHAR(100) NOT NULL,
    details JSON,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- 索引用於快速查詢
    INDEX idx_audit_logs_user_id (user_id),
    INDEX idx_audit_logs_timestamp (timestamp),
    INDEX idx_audit_logs_resource (resource_type, resource_id)
);

-- ====================================================================
-- 通知和警報
-- ====================================================================

-- 通知模板表
CREATE TABLE notification_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    subject VARCHAR(500),
    content TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_notification_type CHECK (type IN ('email', 'sms', 'webhook', 'in_app'))
);

-- 通知記錄表
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    template_id UUID REFERENCES notification_templates(id),
    type VARCHAR(50) NOT NULL,
    title VARCHAR(500),
    content TEXT,
    data JSON,
    status VARCHAR(50) DEFAULT 'pending',
    sent_at TIMESTAMP WITH TIME ZONE,
    read_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_notification_status CHECK (status IN ('pending', 'sent', 'failed', 'read'))
);

-- ====================================================================
-- 整合和 API
-- ====================================================================

-- 外部整合表
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    config JSON NOT NULL, -- 加密存儲
    is_active BOOLEAN DEFAULT true,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT check_integration_type CHECK (type IN ('jira', 'slack', 'webhook', 'siem', 'email'))
);

-- ====================================================================
-- 索引設定
-- ====================================================================

-- 用戶相關索引
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_organization ON users(organization);

-- 會話索引
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);

-- 掃描目標索引
CREATE INDEX idx_scan_targets_organization_id ON scan_targets(organization_id);
CREATE INDEX idx_scan_targets_url ON scan_targets(url);
CREATE INDEX idx_scan_targets_is_active ON scan_targets(is_active);
CREATE INDEX idx_scan_targets_priority ON scan_targets(priority);

-- 掃描任務索引
CREATE INDEX idx_scan_jobs_target_id ON scan_jobs(target_id);
CREATE INDEX idx_scan_jobs_user_id ON scan_jobs(user_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_scheduled_at ON scan_jobs(scheduled_at);
CREATE INDEX idx_scan_jobs_created_at ON scan_jobs(created_at);

-- 漏洞索引
CREATE INDEX idx_vulnerabilities_job_id ON vulnerabilities(job_id);
CREATE INDEX idx_vulnerabilities_target_id ON vulnerabilities(target_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX idx_vulnerabilities_cwe_id ON vulnerabilities(cwe_id);
CREATE INDEX idx_vulnerabilities_created_at ON vulnerabilities(created_at);

-- 報告索引
CREATE INDEX idx_reports_organization_id ON reports(organization_id);
CREATE INDEX idx_reports_generated_by ON reports(generated_by);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_generated_at ON reports(generated_at);

-- ====================================================================
-- 觸發器和函數
-- ====================================================================

-- 更新 updated_at 欄位的函數
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 為需要的表創建更新觸發器
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scan_targets_updated_at BEFORE UPDATE ON scan_targets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scan_jobs_updated_at BEFORE UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ====================================================================
-- 預設數據
-- ====================================================================

-- 插入預設漏洞類別
INSERT INTO vulnerability_categories (name, description, owasp_mapping, cwe_mapping, severity_default, remediation_template) VALUES
('SQL Injection', 'SQL 注入攻擊漏洞', 'A03:2021', 'CWE-89', 'high', '使用參數化查詢和輸入驗證'),
('Cross-Site Scripting (XSS)', '跨站腳本攻擊漏洞', 'A03:2021', 'CWE-79', 'medium', '實施輸出編碼和 Content Security Policy'),
('Cross-Site Request Forgery (CSRF)', '跨站請求偽造攻擊', 'A01:2021', 'CWE-352', 'medium', '實施 CSRF 令牌驗證'),
('Insecure Direct Object References', '不安全的直接物件引用', 'A01:2021', 'CWE-639', 'medium', '實施存取控制和授權檢查'),
('Security Misconfiguration', '安全配置錯誤', 'A05:2021', 'CWE-16', 'medium', '檢視和強化安全配置'),
('Sensitive Data Exposure', '敏感資料暴露', 'A02:2021', 'CWE-200', 'high', '實施資料加密和存取控制'),
('SSL/TLS Issues', 'SSL/TLS 配置問題', 'A02:2021', 'CWE-295', 'medium', '更新 SSL 配置和證書');

-- 插入預設系統配置
INSERT INTO system_config (category, key, value, description) VALUES
('security', 'password_min_length', '8', '密碼最小長度'),
('security', 'password_require_special_chars', 'true', '密碼是否需要特殊字符'),
('security', 'max_login_attempts', '5', '最大登入嘗試次數'),
('security', 'session_timeout_hours', '24', '會話超時時間（小時）'),
('scanning', 'max_concurrent_scans', '10', '最大並發掃描數'),
('scanning', 'default_scan_timeout', '3600', '預設掃描超時時間（秒）'),
('reports', 'report_retention_days', '90', '報告保留天數'),
('notifications', 'enable_email_notifications', 'true', '是否啟用郵件通知');

-- 插入預設通知模板
INSERT INTO notification_templates (name, type, subject, content) VALUES
('Scan Completed', 'email', '掃描完成通知', '您的掃描任務已完成，發現 {{vulnerabilities_count}} 個安全問題。'),
('Critical Vulnerability Found', 'email', '發現嚴重安全漏洞', '在目標 {{target_name}} 中發現嚴重安全漏洞，請立即處理。'),
('Scan Failed', 'email', '掃描失敗通知', '掃描任務 {{job_name}} 執行失敗：{{error_message}}');

-- 創建預設管理員用戶（實際部署時應該更改）
INSERT INTO users (username, email, password_hash, salt, first_name, last_name, role, is_active, is_verified) VALUES
('admin', 'admin@websec-platform.com',
 crypt('SecurePassword123!', gen_salt('bf', 12)),
 gen_salt('bf', 12),
 'System', 'Administrator', 'admin', true, true);

-- ====================================================================
-- 資料庫維護
-- ====================================================================

-- 清理過期會話的函數
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- 清理舊審計日誌的函數
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(days_to_keep INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '1 day' * days_to_keep);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;