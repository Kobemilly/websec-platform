const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const compression = require('compression');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
const uuid = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || 'localhost';

// 掃描會話存儲
const scanSessions = new Map();

// 掃描狀態枚舉
const SCAN_STATUS = {
  PENDING: 'pending',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed'
};

// 掃描器路徑
const SCANNER_PATH = path.join(__dirname, '../../scanner');
const PYTHON_VENV = path.join(SCANNER_PATH, 'venv', 'bin', 'python3');
const SCANNER_MAIN = path.join(SCANNER_PATH, 'main_cli.py');

// 安全中間件
app.use(helmet());

// 速率限制
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 分鐘
  max: 1000, // 每個 IP 最多 1000 個請求
  message: {
    error: 'Too many requests from this IP, please try again later.'
  }
});
app.use(limiter);

// CORS 配置
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'http://localhost:3005',
    'http://localhost:3000',
    'http://localhost:3005',
    'http://10.64.11.49:3005'
  ],
  credentials: true
}));

// 中間件
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// 健康檢查端點
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: '1.0.0'
  });
});

// API 文檔端點
app.get('/api-docs', (req, res) => {
  res.json({
    title: 'WebSecScan API',
    version: '1.0.0',
    description: 'Professional Web Security Scanning Platform API',
    endpoints: {
      health: '/health',
      api_docs: '/api-docs',
      status: '/api/v1/status',
      scan_management: {
        start_scan: 'POST /api/v1/scan',
        get_status: 'GET /api/v1/scan/:scanId/status',
        get_results: 'GET /api/v1/scan/:scanId/results',
        export_results: 'GET /api/v1/scan/:scanId/export/:format',
        list_scans: 'GET /api/v1/scans'
      }
    },
    supported_formats: ['json', 'pdf'],
    supported_modules: ['sql_injection', 'xss_scanner', 'csrf_scanner', 'auth_bypass_scanner', 'directory_traversal_scanner', 'info_disclosure', 'ssl_tls'],
    status: 'Production Ready - All APIs Available'
  });
});

// 基本 API 路由
app.get('/api/v1/status', (req, res) => {
  res.json({
    success: true,
    message: 'WebSecScan API is running',
    timestamp: new Date().toISOString()
  });
});

// 掃描管理 API 端點

// 啟動新掃描
app.post('/api/v1/scan', async (req, res) => {
  try {
    const { url, scan_type, modules, max_concurrency, timeout } = req.body;

    // 驗證輸入
    if (!url) {
      return res.status(400).json({
        success: false,
        message: '掃描目標 URL 是必需的'
      });
    }

    // 生成掃描 ID
    const scanId = `scan_${Date.now()}_${uuid.v4().slice(0, 8)}`;

    // 建立掃描會話
    const scanSession = {
      id: scanId,
      url: url,
      scan_type: scan_type || 'basic',
      modules: modules || [],
      max_concurrency: max_concurrency || 2,
      timeout: timeout || 30,
      status: SCAN_STATUS.PENDING,
      progress: 0,
      message: '準備中...',
      start_time: new Date(),
      end_time: null,
      results: null,
      statistics: {
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        vulnerabilities_found: 0
      },
      risk_score: 0.0
    };

    // 儲存會話
    scanSessions.set(scanId, scanSession);

    // 異步啟動掃描
    startPythonScan(scanSession);

    res.json({
      success: true,
      message: '掃描已啟動',
      scan_id: scanId,
      status: scanSession.status
    });
  } catch (error) {
    console.error('啟動掃描錯誤:', error);
    res.status(500).json({
      success: false,
      message: '啟動掃描失敗: ' + error.message
    });
  }
});

// 獲取掃描狀態
app.get('/api/v1/scan/:scanId/status', (req, res) => {
  const { scanId } = req.params;
  const session = scanSessions.get(scanId);

  if (!session) {
    return res.status(404).json({
      success: false,
      message: '找不到指定的掃描會話'
    });
  }

  res.json({
    success: true,
    scan_id: scanId,
    status: session.status,
    progress: session.progress,
    message: session.message,
    statistics: session.statistics,
    risk_score: session.risk_score,
    start_time: session.start_time,
    end_time: session.end_time
  });
});

// 獲取掃描結果
app.get('/api/v1/scan/:scanId/results', (req, res) => {
  const { scanId } = req.params;
  const session = scanSessions.get(scanId);

  if (!session) {
    return res.status(404).json({
      success: false,
      message: '找不到指定的掃描會話'
    });
  }

  if (session.status !== SCAN_STATUS.COMPLETED) {
    return res.status(400).json({
      success: false,
      message: '掃描尚未完成'
    });
  }

  res.json({
    success: true,
    scan_id: scanId,
    target_url: session.url,
    scan_type: session.scan_type,
    start_time: session.start_time,
    end_time: session.end_time,
    duration: session.end_time - session.start_time,
    status: session.status,
    vulnerabilities: session.results?.vulnerabilities || [],
    statistics: session.statistics,
    risk_score: session.risk_score
  });
});

// 匯出掃描結果
app.get('/api/v1/scan/:scanId/export/:format', (req, res) => {
  const { scanId, format } = req.params;
  const session = scanSessions.get(scanId);

  if (!session) {
    return res.status(404).json({
      success: false,
      message: '找不到指定的掃描會話'
    });
  }

  if (session.status !== SCAN_STATUS.COMPLETED) {
    return res.status(400).json({
      success: false,
      message: '掃描尚未完成'
    });
  }

  const exportData = {
    scan_id: scanId,
    target_url: session.url,
    scan_type: session.scan_type,
    scan_time: session.start_time,
    duration: session.end_time - session.start_time,
    vulnerabilities: session.results?.vulnerabilities || [],
    statistics: session.statistics,
    risk_score: session.risk_score,
    generated_at: new Date().toISOString(),
    generated_by: 'WebSecScan Enterprise v1.0.0'
  };

  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="scan_report_${scanId}.json"`);
    res.send(JSON.stringify(exportData, null, 2));
  } else if (format === 'pdf') {
    // 簡化的 PDF 導出（實際應該生成真正的 PDF）
    res.setHeader('Content-Type', 'application/json'); // 暫時還是 JSON
    res.setHeader('Content-Disposition', `attachment; filename="scan_report_${scanId}.pdf"`);
    res.json({
      ...exportData,
      format: 'PDF (簡化版本)',
      note: '完整 PDF 報告功能即將推出'
    });
  } else {
    res.status(400).json({
      success: false,
      message: '不支援的匯出格式。支援的格式: json, pdf'
    });
  }
});

// 獲取所有掃描會話
app.get('/api/v1/scans', (req, res) => {
  const sessions = Array.from(scanSessions.values()).map(session => ({
    id: session.id,
    url: session.url,
    scan_type: session.scan_type,
    status: session.status,
    progress: session.progress,
    start_time: session.start_time,
    end_time: session.end_time,
    risk_score: session.risk_score
  }));

  res.json({
    success: true,
    scans: sessions,
    total: sessions.length
  });
});

// Python 掃描啟動函數
async function startPythonScan(scanSession) {
  try {
    console.log(`🚀 啟動 Python 掃描器: ${scanSession.id}`);

    // 更新狀態為運行中
    scanSession.status = SCAN_STATUS.RUNNING;
    scanSession.progress = 5;
    scanSession.message = '初始化掃描引擎...';

    // 準備 Python 掃描器命令
    const pythonArgs = [
      SCANNER_MAIN,
      '--target', scanSession.url,
      '--scan-type', scanSession.scan_type,
      '--scan-id', scanSession.id,
      '--output-dir', path.join(SCANNER_PATH, 'results'),
      '--output-format', 'json'
    ];

    // 如果指定了特定模組
    if (scanSession.modules && scanSession.modules.length > 0) {
      pythonArgs.push('--modules', scanSession.modules.join(','));
    }

    console.log(`執行命令: python3 ${pythonArgs.join(' ')}`);

    // 啟動 Python 掃描器進程
    const scanProcess = spawn('python3', pythonArgs, {
      cwd: SCANNER_PATH,
      env: { ...process.env }
    });

    let scanOutput = '';
    let scanError = '';

    // 收集標準輸出
    scanProcess.stdout.on('data', (data) => {
      const output = data.toString();
      scanOutput += output;
      console.log('[Scanner stdout]:', output);

      // 解析進度信息 (如果 scanner 輸出進度)
      const progressMatch = output.match(/Progress: (\d+)%/);
      if (progressMatch) {
        scanSession.progress = parseInt(progressMatch[1]);
      }

      // 解析狀態消息
      const messageMatch = output.match(/Status: (.+)/);
      if (messageMatch) {
        scanSession.message = messageMatch[1].trim();
      }
    });

    // 收集錯誤輸出(Python scanner 的進度信息輸出到 stderr)
    scanProcess.stderr.on('data', (data) => {
      const error = data.toString();
      scanError += error;
      
      // 解析進度信息
      const progressMatch = error.match(/Progress: (\d+)%/);
      if (progressMatch) {
        scanSession.progress = parseInt(progressMatch[1]);
      }

      // 解析狀態消息
      const messageMatch = error.match(/Status: (.+)/);
      if (messageMatch) {
        scanSession.message = messageMatch[1].trim();
      }
      
      // 只在有錯誤時才記錄到控制台
      if (error.includes('ERROR:') || error.includes('WARNING:')) {
        console.error('[Scanner stderr]:', error);
      }
    });

    // 等待掃描完成
    await new Promise((resolve, reject) => {
      scanProcess.on('close', async (code) => {
        if (code === 0) {
          console.log(`✅ Python 掃描器完成: ${scanSession.id}`);
          
          // 讀取掃描結果 JSON 檔案
          const resultFile = path.join(
            SCANNER_PATH,
            'results',
            `scan_result_${scanSession.id}.json`
          );

          try {
            const resultData = await fs.readFile(resultFile, 'utf8');
            const scanResults = JSON.parse(resultData);

            // **關鍵:直接使用 Python scanner 的完整結果,保留所有模板字段**
            scanSession.results = scanResults;
            scanSession.status = scanResults.status === 'completed' ? SCAN_STATUS.COMPLETED : SCAN_STATUS.FAILED;
            scanSession.end_time = new Date();
            
            // 合併並完善統計數據
            scanSession.statistics = {
              total_requests: scanResults.statistics?.total_requests || 0,
              successful_requests: scanResults.statistics?.successful_requests || 0,
              failed_requests: scanResults.statistics?.failed_requests || 0,
              modules_executed: scanResults.statistics?.modules_executed || 0,
              pages_scanned: scanResults.statistics?.pages_scanned || 0,
              vulnerabilities_found: scanResults.vulnerabilities?.length || 0
            };
            
            scanSession.risk_score = scanResults.risk_score || 0.0;
            scanSession.progress = 100;
            scanSession.message = '掃描完成';

            console.log(`📊 掃描結果已載入: ${scanResults.vulnerabilities?.length || 0} 個漏洞, 掃描 ${scanSession.statistics.pages_scanned} 個頁面`);
            
          } catch (readError) {
            console.error('讀取掃描結果失敗:', readError);
            scanSession.status = SCAN_STATUS.FAILED;
            scanSession.message = '無法讀取掃描結果';
          }

          resolve();
        } else {
          console.error(`❌ Python 掃描器異常退出 (code ${code})`);
          scanSession.status = SCAN_STATUS.FAILED;
          scanSession.message = `掃描失敗 (exit code ${code})`;
          scanSession.end_time = new Date();
          reject(new Error(`Scanner exited with code ${code}: ${scanError}`));
        }
      });

      scanProcess.on('error', (error) => {
        console.error('無法啟動 Python 掃描器:', error);
        scanSession.status = SCAN_STATUS.FAILED;
        scanSession.message = '無法啟動掃描器: ' + error.message;
        scanSession.end_time = new Date();
        reject(error);
      });
    });

  } catch (error) {
    console.error('Python 掃描錯誤:', error);
    scanSession.status = SCAN_STATUS.FAILED;
    scanSession.message = '掃描失敗: ' + error.message;
    scanSession.end_time = new Date();
  }
}

// 404 處理
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found'
  });
});

// 錯誤處理中間件
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// 啟動伺服器
app.listen(PORT, HOST, () => {
  console.log(`🚀 WebSecScan Backend API Server is running on ${HOST}:${PORT}`);
  console.log(`📊 Health check: http://${HOST === '0.0.0.0' ? '10.64.11.49' : HOST}:${PORT}/health`);
  console.log(`📚 API docs: http://${HOST === '0.0.0.0' ? '10.64.11.49' : HOST}:${PORT}/api-docs`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// 優雅關閉
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;