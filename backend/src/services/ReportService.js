const fs = require('fs').promises;
const path = require('path');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const { createObjectCsvWriter } = require('csv-writer');
const Handlebars = require('handlebars');
const puppeteer = require('puppeteer');
const moment = require('moment');
const logger = require('../utils/logger');

class ReportService {
  constructor() {
    this.templatePath = path.join(__dirname, '../../templates');
    this.outputPath = path.join(__dirname, '../../reports');
    this.initializeHandlebars();
  }

  /**
   * 初始化 Handlebars 助手函數
   */
  initializeHandlebars() {
    // 註冊助手函數
    Handlebars.registerHelper('formatDate', (date) => {
      return moment(date).format('YYYY-MM-DD HH:mm:ss');
    });

    Handlebars.registerHelper('formatSeverity', (severity) => {
      const severityMap = {
        'critical': '嚴重',
        'high': '高危',
        'medium': '中危',
        'low': '低危'
      };
      return severityMap[severity] || severity;
    });

    Handlebars.registerHelper('getSeverityColor', (severity) => {
      const colorMap = {
        'critical': '#d32f2f',
        'high': '#f57c00',
        'medium': '#fbc02d',
        'low': '#388e3c'
      };
      return colorMap[severity] || '#666666';
    });

    Handlebars.registerHelper('calculatePercentage', (value, total) => {
      if (total === 0) return 0;
      return Math.round((value / total) * 100);
    });

    Handlebars.registerHelper('eq', (a, b) => a === b);
    Handlebars.registerHelper('gt', (a, b) => a > b);
    Handlebars.registerHelper('add', (a, b) => a + b);
  }

  /**
   * 生成執行摘要報告（適合 CISO）
   */
  async generateExecutiveSummary(scanResults, options = {}) {
    try {
      logger.info(`生成執行摘要報告: ${scanResults.length} 個掃描結果`);

      const reportData = this.prepareExecutiveSummaryData(scanResults);

      switch (options.format || 'pdf') {
        case 'pdf':
          return await this.generateExecutivePDF(reportData, options);
        case 'html':
          return await this.generateExecutiveHTML(reportData, options);
        case 'json':
          return this.generateExecutiveJSON(reportData, options);
        default:
          throw new Error(`不支援的報告格式: ${options.format}`);
      }
    } catch (error) {
      logger.error('生成執行摘要報告時發生錯誤:', error);
      throw error;
    }
  }

  /**
   * 生成技術詳細報告
   */
  async generateTechnicalReport(scanResults, options = {}) {
    try {
      logger.info(`生成技術詳細報告: ${scanResults.length} 個掃描結果`);

      const reportData = this.prepareTechnicalReportData(scanResults);

      switch (options.format || 'pdf') {
        case 'pdf':
          return await this.generateTechnicalPDF(reportData, options);
        case 'html':
          return await this.generateTechnicalHTML(reportData, options);
        case 'excel':
          return await this.generateTechnicalExcel(reportData, options);
        case 'csv':
          return await this.generateTechnicalCSV(reportData, options);
        default:
          throw new Error(`不支援的報告格式: ${options.format}`);
      }
    } catch (error) {
      logger.error('生成技術詳細報告時發生錯誤:', error);
      throw error;
    }
  }

  /**
   * 生成合規性報告
   */
  async generateComplianceReport(scanResults, complianceStandard, options = {}) {
    try {
      logger.info(`生成合規性報告: ${complianceStandard}`);

      const reportData = this.prepareComplianceReportData(scanResults, complianceStandard);

      switch (options.format || 'pdf') {
        case 'pdf':
          return await this.generateCompliancePDF(reportData, options);
        case 'html':
          return await this.generateComplianceHTML(reportData, options);
        case 'excel':
          return await this.generateComplianceExcel(reportData, options);
        default:
          throw new Error(`不支援的報告格式: ${options.format}`);
      }
    } catch (error) {
      logger.error('生成合規性報告時發生錯誤:', error);
      throw error;
    }
  }

  /**
   * 準備執行摘要數據
   */
  prepareExecutiveSummaryData(scanResults) {
    const summary = {
      reportDate: new Date(),
      totalScans: scanResults.length,
      totalVulnerabilities: 0,
      severityBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      riskScore: 0,
      trends: [],
      topVulnerabilities: [],
      riskByAsset: [],
      recommendations: []
    };

    // 計算漏洞統計
    scanResults.forEach(scan => {
      if (scan.vulnerabilities) {
        summary.totalVulnerabilities += scan.vulnerabilities.length;

        scan.vulnerabilities.forEach(vuln => {
          if (summary.severityBreakdown[vuln.severity]) {
            summary.severityBreakdown[vuln.severity]++;
          }
        });
      }
    });

    // 計算平均風險評分
    const totalRiskScore = scanResults.reduce((sum, scan) => sum + (scan.riskScore || 0), 0);
    summary.riskScore = scanResults.length > 0 ? (totalRiskScore / scanResults.length) : 0;

    // 找出前 10 個最常見的漏洞類型
    summary.topVulnerabilities = this.getTopVulnerabilityTypes(scanResults);

    // 按資產分類風險
    summary.riskByAsset = this.categorizeRiskByAsset(scanResults);

    // 生成建議
    summary.recommendations = this.generateRecommendations(summary);

    return summary;
  }

  /**
   * 準備技術詳細報告數據
   */
  prepareTechnicalReportData(scanResults) {
    const technicalData = {
      reportDate: new Date(),
      scanResults: scanResults.map(scan => ({
        ...scan,
        vulnerabilities: scan.vulnerabilities?.map(vuln => ({
          ...vuln,
          remediation: this.getDetailedRemediation(vuln),
          references: this.getVulnerabilityReferences(vuln)
        })) || []
      })),
      statistics: this.calculateTechnicalStatistics(scanResults),
      scanConfiguration: this.extractScanConfigurations(scanResults)
    };

    return technicalData;
  }

  /**
   * 準備合規性報告數據
   */
  prepareComplianceReportData(scanResults, standard) {
    const complianceFramework = this.getComplianceFramework(standard);

    return {
      reportDate: new Date(),
      standard: standard,
      framework: complianceFramework,
      complianceScore: this.calculateComplianceScore(scanResults, complianceFramework),
      controlResults: this.mapVulnerabilitiesToControls(scanResults, complianceFramework),
      gaps: this.identifyComplianceGaps(scanResults, complianceFramework),
      actionPlan: this.generateComplianceActionPlan(scanResults, complianceFramework)
    };
  }

  /**
   * 生成執行摘要 PDF
   */
  async generateExecutivePDF(reportData, options) {
    return new Promise(async (resolve, reject) => {
      try {
        const fileName = `executive_summary_${Date.now()}.pdf`;
        const filePath = path.join(this.outputPath, fileName);

        // 確保輸出目錄存在
        await fs.mkdir(this.outputPath, { recursive: true });

        const doc = new PDFDocument({
          size: 'A4',
          margins: { top: 50, left: 50, right: 50, bottom: 50 }
        });

        const stream = require('fs').createWriteStream(filePath);
        doc.pipe(stream);

        // 添加封面
        this.addExecutiveCoverPage(doc, reportData);
        doc.addPage();

        // 添加執行摘要
        this.addExecutiveSummarySection(doc, reportData);
        doc.addPage();

        // 添加風險評估
        this.addRiskAssessmentSection(doc, reportData);
        doc.addPage();

        // 添加建議
        this.addRecommendationsSection(doc, reportData);

        doc.end();

        stream.on('finish', () => {
          resolve({
            fileName,
            filePath,
            size: require('fs').statSync(filePath).size
          });
        });

        stream.on('error', reject);

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * 生成技術詳細 Excel 報告
   */
  async generateTechnicalExcel(reportData, options) {
    try {
      const fileName = `technical_report_${Date.now()}.xlsx`;
      const filePath = path.join(this.outputPath, fileName);

      await fs.mkdir(this.outputPath, { recursive: true });

      const workbook = new ExcelJS.Workbook();

      // 添加概覽工作表
      const overviewSheet = workbook.addWorksheet('概覽');
      this.addOverviewToExcel(overviewSheet, reportData);

      // 添加漏洞詳情工作表
      const vulnerabilitiesSheet = workbook.addWorksheet('漏洞詳情');
      this.addVulnerabilitiesToExcel(vulnerabilitiesSheet, reportData);

      // 添加統計工作表
      const statisticsSheet = workbook.addWorksheet('統計分析');
      this.addStatisticsToExcel(statisticsSheet, reportData);

      await workbook.xlsx.writeFile(filePath);

      return {
        fileName,
        filePath,
        size: (await fs.stat(filePath)).size
      };

    } catch (error) {
      logger.error('生成 Excel 報告時發生錯誤:', error);
      throw error;
    }
  }

  /**
   * 生成 CSV 報告
   */
  async generateTechnicalCSV(reportData, options) {
    try {
      const fileName = `vulnerabilities_${Date.now()}.csv`;
      const filePath = path.join(this.outputPath, fileName);

      await fs.mkdir(this.outputPath, { recursive: true });

      // 準備 CSV 數據
      const csvData = [];

      reportData.scanResults.forEach(scan => {
        scan.vulnerabilities.forEach(vuln => {
          csvData.push({
            scan_id: scan.scanId,
            target_url: scan.targetUrl,
            vulnerability_id: vuln.id,
            title: vuln.title,
            description: vuln.description,
            severity: vuln.severity,
            cwe_id: vuln.cweId,
            owasp_category: vuln.owaspCategory,
            affected_url: vuln.affectedUrl,
            confidence: vuln.confidence,
            risk_score: vuln.riskScore,
            timestamp: vuln.timestamp
          });
        });
      });

      const csvWriter = createObjectCsvWriter({
        path: filePath,
        header: [
          { id: 'scan_id', title: '掃描ID' },
          { id: 'target_url', title: '目標URL' },
          { id: 'vulnerability_id', title: '漏洞ID' },
          { id: 'title', title: '標題' },
          { id: 'description', title: '描述' },
          { id: 'severity', title: '嚴重程度' },
          { id: 'cwe_id', title: 'CWE ID' },
          { id: 'owasp_category', title: 'OWASP 分類' },
          { id: 'affected_url', title: '受影響URL' },
          { id: 'confidence', title: '置信度' },
          { id: 'risk_score', title: '風險評分' },
          { id: 'timestamp', title: '時間戳' }
        ]
      });

      await csvWriter.writeRecords(csvData);

      return {
        fileName,
        filePath,
        size: (await fs.stat(filePath)).size
      };

    } catch (error) {
      logger.error('生成 CSV 報告時發生錯誤:', error);
      throw error;
    }
  }

  /**
   * 添加執行摘要封面頁
   */
  addExecutiveCoverPage(doc, reportData) {
    // 標題
    doc.fontSize(24)
       .fillColor('#2c3e50')
       .text('網站安全掃描', 50, 100, { align: 'center' })
       .fontSize(20)
       .text('執行摘要報告', 50, 140, { align: 'center' });

    // 報告信息
    doc.fontSize(12)
       .fillColor('#34495e')
       .text(`報告生成時間: ${moment(reportData.reportDate).format('YYYY年MM月DD日')}`, 50, 200)
       .text(`掃描目標數量: ${reportData.totalScans} 個`, 50, 220)
       .text(`發現漏洞總數: ${reportData.totalVulnerabilities} 個`, 50, 240)
       .text(`整體風險評分: ${reportData.riskScore.toFixed(1)}/10.0`, 50, 260);

    // 風險級別摘要
    doc.fontSize(14)
       .fillColor('#2c3e50')
       .text('漏洞嚴重程度分佈', 50, 320);

    const severityColors = {
      critical: '#d32f2f',
      high: '#f57c00',
      medium: '#fbc02d',
      low: '#388e3c'
    };

    let yPos = 350;
    Object.keys(reportData.severityBreakdown).forEach(severity => {
      const count = reportData.severityBreakdown[severity];
      doc.fontSize(11)
         .fillColor(severityColors[severity])
         .text(`${this.formatSeverityText(severity)}: ${count} 個`, 70, yPos);
      yPos += 25;
    });

    // 添加公司 Logo 位置（如果有的話）
    doc.fontSize(10)
       .fillColor('#7f8c8d')
       .text('WebSecScan - 專業網站安全掃描平台', 50, 750, { align: 'center' });
  }

  /**
   * 添加執行摘要章節
   */
  addExecutiveSummarySection(doc, reportData) {
    doc.fontSize(18)
       .fillColor('#2c3e50')
       .text('執行摘要', 50, 50);

    doc.fontSize(11)
       .fillColor('#34495e')
       .text('本次安全掃描評估了組織的 Web 應用程式安全狀況。以下是主要發現:', 50, 90, {
         width: 500,
         lineGap: 5
       });

    // 關鍵發現
    let yPos = 150;
    const keyFindings = this.generateKeyFindings(reportData);

    keyFindings.forEach(finding => {
      doc.fontSize(11)
         .fillColor('#e74c3c')
         .text('• ', 50, yPos)
         .fillColor('#34495e')
         .text(finding, 65, yPos, { width: 485, lineGap: 3 });
      yPos += 30;
    });
  }

  /**
   * 獲取前 10 個最常見的漏洞類型
   */
  getTopVulnerabilityTypes(scanResults) {
    const vulnTypes = {};

    scanResults.forEach(scan => {
      scan.vulnerabilities?.forEach(vuln => {
        const key = `${vuln.title}-${vuln.cweId}`;
        if (!vulnTypes[key]) {
          vulnTypes[key] = {
            title: vuln.title,
            cweId: vuln.cweId,
            count: 0,
            severity: vuln.severity
          };
        }
        vulnTypes[key].count++;
      });
    });

    return Object.values(vulnTypes)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  /**
   * 生成建議
   */
  generateRecommendations(summary) {
    const recommendations = [];

    // 基於嚴重漏洞數量的建議
    if (summary.severityBreakdown.critical > 0) {
      recommendations.push({
        priority: 'critical',
        title: '立即處理嚴重漏洞',
        description: `發現 ${summary.severityBreakdown.critical} 個嚴重漏洞，建議立即修復以避免安全風險。`,
        timeline: '24 小時內'
      });
    }

    if (summary.severityBreakdown.high > 5) {
      recommendations.push({
        priority: 'high',
        title: '加強安全開發流程',
        description: '高危漏洞數量較多，建議檢視和改善安全開發流程。',
        timeline: '1 週內'
      });
    }

    // 基於風險評分的建議
    if (summary.riskScore > 7) {
      recommendations.push({
        priority: 'high',
        title: '實施緊急安全措施',
        description: '整體風險評分較高，建議實施 WAF、限制存取等緊急安全措施。',
        timeline: '3 天內'
      });
    }

    return recommendations;
  }

  /**
   * 格式化嚴重程度文字
   */
  formatSeverityText(severity) {
    const severityMap = {
      'critical': '嚴重',
      'high': '高危',
      'medium': '中危',
      'low': '低危'
    };
    return severityMap[severity] || severity;
  }

  /**
   * 生成關鍵發現
   */
  generateKeyFindings(reportData) {
    const findings = [];

    if (reportData.severityBreakdown.critical > 0) {
      findings.push(`發現 ${reportData.severityBreakdown.critical} 個嚴重安全漏洞，需要立即修復`);
    }

    if (reportData.riskScore > 7) {
      findings.push(`整體安全風險評分為 ${reportData.riskScore.toFixed(1)}/10.0，屬於高風險等級`);
    }

    if (reportData.totalVulnerabilities > 50) {
      findings.push(`總計發現 ${reportData.totalVulnerabilities} 個安全問題，建議加強安全管控`);
    }

    return findings;
  }

  /**
   * 獲取合規性框架
   */
  getComplianceFramework(standard) {
    const frameworks = {
      'pci-dss': {
        name: 'PCI DSS 3.2.1',
        description: '支付卡行業數據安全標準',
        requirements: [
          '建立和維護安全的網路和系統',
          '保護帳戶持有人數據',
          '維護漏洞管理計劃',
          '實施強大的存取控制措施',
          '定期監控和測試網路',
          '維護資訊安全政策'
        ]
      },
      'gdpr': {
        name: 'GDPR',
        description: '一般資料保護規範',
        requirements: [
          '資料保護原則',
          '個人資料處理的合法基礎',
          '資料主體權利',
          '技術和組織措施',
          '個資外洩通報',
          '資料保護影響評估'
        ]
      }
    };

    return frameworks[standard] || {
      name: standard.toUpperCase(),
      description: '自定義合規標準',
      requirements: []
    };
  }

  /**
   * 計算合規性評分
   */
  calculateComplianceScore(scanResults, framework) {
    // 這裡實現具體的合規性評分邏輯
    // 基於漏洞類型和嚴重程度計算合規性得分

    let totalScore = 100;
    let penaltyPoints = 0;

    scanResults.forEach(scan => {
      scan.vulnerabilities?.forEach(vuln => {
        switch (vuln.severity) {
          case 'critical':
            penaltyPoints += 15;
            break;
          case 'high':
            penaltyPoints += 10;
            break;
          case 'medium':
            penaltyPoints += 5;
            break;
          case 'low':
            penaltyPoints += 1;
            break;
        }
      });
    });

    return Math.max(0, totalScore - penaltyPoints);
  }
}

module.exports = ReportService;