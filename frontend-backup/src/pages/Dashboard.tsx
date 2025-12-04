import React, { useState, useEffect } from 'react';
import {
  Grid,
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Alert,
  Divider
} from '@mui/material';
import {
  Security,
  BugReport,
  Assessment,
  Warning,
  CheckCircle,
  Error,
  TrendingUp,
  Schedule,
  Domain
} from '@mui/icons-material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  ResponsiveContainer
} from 'recharts';

interface SecurityMetrics {
  totalAssets: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  activeScanners: number;
  complianceScore: number;
  lastScanDate: string;
}

interface RecentScan {
  id: string;
  target: string;
  status: 'completed' | 'running' | 'failed';
  vulnerabilities: number;
  riskScore: number;
  scanDate: string;
}

const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetrics>({
    totalAssets: 0,
    criticalVulns: 0,
    highVulns: 0,
    mediumVulns: 0,
    lowVulns: 0,
    activeScanners: 0,
    complianceScore: 0,
    lastScanDate: ''
  });

  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);

  // 模擬數據載入
  useEffect(() => {
    setTimeout(() => {
      setMetrics({
        totalAssets: 247,
        criticalVulns: 12,
        highVulns: 34,
        mediumVulns: 89,
        lowVulns: 156,
        activeScanners: 3,
        complianceScore: 87,
        lastScanDate: '2024-01-15 14:30:00'
      });

      setRecentScans([
        { id: '1', target: 'app.company.com', status: 'completed', vulnerabilities: 23, riskScore: 7.8, scanDate: '2024-01-15 10:00' },
        { id: '2', target: 'api.company.com', status: 'running', vulnerabilities: 0, riskScore: 0, scanDate: '2024-01-15 14:30' },
        { id: '3', target: 'admin.company.com', status: 'completed', vulnerabilities: 5, riskScore: 4.2, scanDate: '2024-01-15 08:15' },
        { id: '4', target: 'staging.company.com', status: 'failed', vulnerabilities: 0, riskScore: 0, scanDate: '2024-01-15 06:45' }
      ]);
      setLoading(false);
    }, 1000);
  }, []);

  const vulnerabilityData = [
    { name: '嚴重', count: metrics.criticalVulns, color: '#f44336' },
    { name: '高危', count: metrics.highVulns, color: '#ff9800' },
    { name: '中危', count: metrics.mediumVulns, color: '#ffeb3b' },
    { name: '低危', count: metrics.lowVulns, color: '#4caf50' }
  ];

  const trendData = [
    { month: '10月', critical: 15, high: 42, medium: 78, low: 134 },
    { month: '11月', critical: 18, high: 39, medium: 85, low: 142 },
    { month: '12月', critical: 14, high: 36, medium: 91, low: 151 },
    { month: '1月', critical: 12, high: 34, medium: 89, low: 156 }
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'info';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 8) return { label: '高風險', color: 'error' };
    if (score >= 5) return { label: '中風險', color: 'warning' };
    return { label: '低風險', color: 'success' };
  };

  if (loading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          載入安全儀表板...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      {/* 頁面標題 */}
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600 }}>
        🛡️ 安全儀表板
      </Typography>

      {/* 關鍵指標卡片 */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'primary.main', color: 'primary.contrastText' }}>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Domain sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {metrics.totalAssets}
                  </Typography>
                  <Typography variant="body2">
                    總資產數量
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'error.main', color: 'error.contrastText' }}>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Error sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {metrics.criticalVulns}
                  </Typography>
                  <Typography variant="body2">
                    嚴重漏洞
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'warning.main', color: 'warning.contrastText' }}>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Warning sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {metrics.highVulns}
                  </Typography>
                  <Typography variant="body2">
                    高危漏洞
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ bgcolor: 'success.main', color: 'success.contrastText' }}>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Assessment sx={{ fontSize: 40, mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {metrics.complianceScore}%
                  </Typography>
                  <Typography variant="body2">
                    合規評分
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* 漏洞分佈和趨勢圖表 */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              漏洞分佈
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={vulnerabilityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {vulnerabilityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              漏洞趨勢（過去4個月）
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="critical" fill="#f44336" name="嚴重" />
                <Bar dataKey="high" fill="#ff9800" name="高危" />
                <Bar dataKey="medium" fill="#ffeb3b" name="中危" />
                <Bar dataKey="low" fill="#4caf50" name="低危" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>

      {/* 最近掃描結果 */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">
            最近掃描結果
          </Typography>
          <Button variant="contained" startIcon={<Security />}>
            新增掃描
          </Button>
        </Box>

        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>目標網站</TableCell>
                <TableCell>狀態</TableCell>
                <TableCell>漏洞數量</TableCell>
                <TableCell>風險評分</TableCell>
                <TableCell>掃描時間</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {recentScans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell>{scan.target}</TableCell>
                  <TableCell>
                    <Chip
                      label={scan.status}
                      color={getStatusColor(scan.status) as any}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{scan.vulnerabilities || '-'}</TableCell>
                  <TableCell>
                    {scan.riskScore > 0 ? (
                      <Chip
                        label={`${scan.riskScore} - ${getRiskLevel(scan.riskScore).label}`}
                        color={getRiskLevel(scan.riskScore).color as any}
                        size="small"
                      />
                    ) : '-'}
                  </TableCell>
                  <TableCell>{scan.scanDate}</TableCell>
                  <TableCell>
                    <Button size="small" variant="outlined">
                      查看報告
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* 系統狀態和快速操作 */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              系統狀態
            </Typography>
            <Box mb={2}>
              <Box display="flex" justifyContent="space-between" mb={1}>
                <Typography variant="body2">掃描引擎</Typography>
                <Chip label="運行中" color="success" size="small" />
              </Box>
              <Box display="flex" justifyContent="space-between" mb={1}>
                <Typography variant="body2">活躍掃描器</Typography>
                <Typography variant="body2">{metrics.activeScanners} 個</Typography>
              </Box>
              <Box display="flex" justifyContent="space-between" mb={1}>
                <Typography variant="body2">最後更新</Typography>
                <Typography variant="body2">{metrics.lastScanDate}</Typography>
              </Box>
            </Box>
            <Divider sx={{ my: 2 }} />
            <Typography variant="h6" gutterBottom>
              快速操作
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <Button
                  fullWidth
                  variant="outlined"
                  startIcon={<BugReport />}
                  color="primary"
                >
                  漏洞掃描
                </Button>
              </Grid>
              <Grid item xs={6}>
                <Button
                  fullWidth
                  variant="outlined"
                  startIcon={<Assessment />}
                  color="secondary"
                >
                  生成報告
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              安全建議
            </Typography>
            <Alert severity="error" sx={{ mb: 2 }}>
              發現 12 個嚴重漏洞需要立即處理
            </Alert>
            <Alert severity="warning" sx={{ mb: 2 }}>
              3 個網站的 SSL 憑證即將過期
            </Alert>
            <Alert severity="info">
              建議對新上線的應用程式進行安全掃描
            </Alert>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;