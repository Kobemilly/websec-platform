import React from 'react';
import ReactDOM from 'react-dom/client';

// 簡單的應用程式組件
const App = () => {
  return (
    <div style={{
      padding: '40px',
      fontFamily: 'Arial, sans-serif',
      maxWidth: '1200px',
      margin: '0 auto'
    }}>
      <header style={{
        textAlign: 'center',
        marginBottom: '40px',
        padding: '20px',
        backgroundColor: '#f5f5f5',
        borderRadius: '8px'
      }}>
        <h1 style={{ color: '#1976d2', marginBottom: '10px' }}>
          🛡️ WebSecScan Platform
        </h1>
        <p style={{ color: '#666', fontSize: '18px' }}>
          專業網站安全掃描平台
        </p>
      </header>

      <main>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: '20px',
          marginBottom: '40px'
        }}>
          <div style={{
            padding: '20px',
            border: '1px solid #ddd',
            borderRadius: '8px',
            backgroundColor: '#fff'
          }}>
            <h3 style={{ color: '#1976d2', marginBottom: '15px' }}>
              🔍 安全掃描引擎
            </h3>
            <ul style={{ color: '#666', lineHeight: '1.6' }}>
              <li>SQL 注入檢測</li>
              <li>XSS 漏洞掃描</li>
              <li>SSL/TLS 安全檢查</li>
              <li>OWASP Top 10 覆蓋</li>
            </ul>
          </div>

          <div style={{
            padding: '20px',
            border: '1px solid #ddd',
            borderRadius: '8px',
            backgroundColor: '#fff'
          }}>
            <h3 style={{ color: '#1976d2', marginBottom: '15px' }}>
              📊 專業報告系統
            </h3>
            <ul style={{ color: '#666', lineHeight: '1.6' }}>
              <li>執行摘要報告</li>
              <li>技術詳細報告</li>
              <li>合規性報告</li>
              <li>多格式匯出</li>
            </ul>
          </div>

          <div style={{
            padding: '20px',
            border: '1px solid #ddd',
            borderRadius: '8px',
            backgroundColor: '#fff'
          }}>
            <h3 style={{ color: '#1976d2', marginBottom: '15px' }}>
              👥 企業級管理
            </h3>
            <ul style={{ color: '#666', lineHeight: '1.6' }}>
              <li>用戶權限管理</li>
              <li>多因素驗證</li>
              <li>審計日誌</li>
              <li>API 整合</li>
            </ul>
          </div>
        </div>

        <div style={{
          textAlign: 'center',
          padding: '30px',
          backgroundColor: '#e3f2fd',
          borderRadius: '8px',
          marginBottom: '40px'
        }}>
          <h2 style={{ color: '#1565c0', marginBottom: '15px' }}>
            🚀 系統狀態
          </h2>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '30px', flexWrap: 'wrap' }}>
            <div>
              <strong style={{ color: '#2e7d32' }}>前端服務:</strong>
              <span style={{ color: '#4caf50', marginLeft: '8px' }}>✅ 運行中</span>
            </div>
            <div>
              <strong style={{ color: '#1565c0' }}>後端 API:</strong>
              <span style={{ color: '#4caf50', marginLeft: '8px' }}>
                <a href="http://localhost:8080/health" target="_blank" rel="noopener noreferrer"
                   style={{ color: '#1976d2', textDecoration: 'none' }}>
                  檢查狀態
                </a>
              </span>
            </div>
            <div>
              <strong style={{ color: '#f57c00' }}>掃描引擎:</strong>
              <span style={{ color: '#ff9800', marginLeft: '8px' }}>⚙️ 準備中</span>
            </div>
          </div>
        </div>

        <div style={{
          backgroundColor: '#f9f9f9',
          padding: '20px',
          borderRadius: '8px',
          border: '1px solid #ddd'
        }}>
          <h3 style={{ color: '#1976d2', marginBottom: '15px' }}>
            📚 快速開始
          </h3>
          <div style={{ color: '#666', lineHeight: '1.8' }}>
            <p><strong>1. 檢查服務狀態:</strong></p>
            <ul>
              <li>前端: <code>http://localhost:3000</code></li>
              <li>後端 API: <code>http://localhost:8080/health</code></li>
              <li>API 文檔: <code>http://localhost:8080/api-docs</code></li>
            </ul>

            <p style={{ marginTop: '20px' }}><strong>2. 開發模式運行:</strong></p>
            <pre style={{ backgroundColor: '#f5f5f5', padding: '10px', borderRadius: '4px', overflow: 'auto' }}>
{`npm run dev           # 全部服務
npm run dev:backend    # 後端 API
npm run dev:frontend   # 前端服務
npm run dev:scanner    # 掃描引擎`}
            </pre>

            <p style={{ marginTop: '20px' }}><strong>3. 生產模式部署:</strong></p>
            <pre style={{ backgroundColor: '#f5f5f5', padding: '10px', borderRadius: '4px', overflow: 'auto' }}>
{`npm run build         # 建立專案
npm run start          # 啟動服務
docker-compose up -d   # Docker 部署`}
            </pre>
          </div>
        </div>
      </main>

      <footer style={{
        textAlign: 'center',
        marginTop: '40px',
        padding: '20px',
        color: '#666',
        borderTop: '1px solid #ddd'
      }}>
        <p>© 2024 WebSecScan Platform - 專業網站安全掃描解決方案</p>
        <p style={{ fontSize: '14px', marginTop: '10px' }}>
          Version 1.0.0 | Built with ❤️ for Security Professionals
        </p>
      </footer>
    </div>
  );
};

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);