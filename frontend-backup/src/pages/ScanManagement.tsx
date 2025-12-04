import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Grid,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Checkbox,
  FormControlLabel,
  FormGroup,
  LinearProgress,
  Menu,
  Card,
  CardContent,
  Fab
} from '@mui/material';
import {
  Add,
  PlayArrow,
  Pause,
  Stop,
  Delete,
  Edit,
  MoreVert,
  Security,
  Schedule,
  Assessment,
  Warning,
  CheckCircle,
  Error
} from '@mui/icons-material';

interface ScanTarget {
  id: string;
  name: string;
  url: string;
  scanType: 'basic' | 'comprehensive' | 'owasp' | 'api';
  status: 'idle' | 'running' | 'completed' | 'failed' | 'scheduled';
  lastScan?: string;
  progress?: number;
  vulnerabilities?: number;
  riskScore?: number;
  schedule?: string;
}

interface ScanTemplate {
  id: string;
  name: string;
  description: string;
  scanModules: string[];
  estimatedTime: string;
}

const ScanManagement: React.FC = () => {
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<ScanTarget | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [menuTargetId, setMenuTargetId] = useState<string>('');

  // 表單狀態
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    scanType: 'basic' as const,
    schedule: '',
    modules: [] as string[]
  });

  const scanModules = [
    { id: 'sql_injection', name: 'SQL 注入檢測' },
    { id: 'xss', name: 'XSS 漏洞掃描' },
    { id: 'csrf', name: 'CSRF 保護檢查' },
    { id: 'auth_bypass', name: '身份驗證繞過' },
    { id: 'ssl_tls', name: 'SSL/TLS 配置' },
    { id: 'directory_traversal', name: '目錄遍歷' },
    { id: 'info_disclosure', name: '資訊洩露' },
    { id: 'weak_crypto', name: '弱加密檢查' }
  ];

  // 初始化數據
  useEffect(() => {
    // 模擬載入掃描目標
    setTargets([
      {
        id: '1',
        name: '主要應用程式',
        url: 'https://app.company.com',
        scanType: 'comprehensive',
        status: 'running',
        progress: 65,
        lastScan: '2024-01-15 14:30',
        vulnerabilities: 12,
        riskScore: 7.8,
        schedule: '每日 02:00'
      },
      {
        id: '2',
        name: 'API 伺服器',
        url: 'https://api.company.com',
        scanType: 'api',
        status: 'completed',
        lastScan: '2024-01-15 10:15',
        vulnerabilities: 5,
        riskScore: 4.2,
        schedule: '每週一 01:00'
      },
      {
        id: '3',
        name: '管理後台',
        url: 'https://admin.company.com',
        scanType: 'owasp',
        status: 'scheduled',
        lastScan: '2024-01-14 22:00',
        vulnerabilities: 23,
        riskScore: 8.9,
        schedule: '每日 03:00'
      }
    ]);

    // 模擬掃描模板
    setTemplates([
      {
        id: '1',
        name: 'OWASP Top 10 掃描',
        description: '基於 OWASP Top 10 的全面安全掃描',
        scanModules: ['sql_injection', 'xss', 'csrf', 'auth_bypass'],
        estimatedTime: '45 分鐘'
      },
      {
        id: '2',
        name: '快速安全檢查',
        description: '基礎安全漏洞快速掃描',
        scanModules: ['sql_injection', 'xss'],
        estimatedTime: '15 分鐘'
      },
      {
        id: '3',
        name: 'SSL/TLS 專項檢查',
        description: '專注於傳輸層安全配置檢查',
        scanModules: ['ssl_tls', 'weak_crypto'],
        estimatedTime: '10 分鐘'
      }
    ]);
  }, []);

  const handleOpenDialog = (target?: ScanTarget) => {
    if (target) {
      setSelectedTarget(target);
      setFormData({
        name: target.name,
        url: target.url,
        scanType: target.scanType,
        schedule: target.schedule || '',
        modules: []
      });
    } else {
      setSelectedTarget(null);
      setFormData({
        name: '',
        url: '',
        scanType: 'basic',
        schedule: '',
        modules: []
      });
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setSelectedTarget(null);
  };

  const handleSaveTarget = () => {
    const newTarget: ScanTarget = {
      id: selectedTarget?.id || Date.now().toString(),
      name: formData.name,
      url: formData.url,
      scanType: formData.scanType,
      status: 'idle',
      schedule: formData.schedule
    };

    if (selectedTarget) {
      setTargets(prev => prev.map(t => t.id === selectedTarget.id ? { ...t, ...newTarget } : t));
    } else {
      setTargets(prev => [...prev, newTarget]);
    }

    handleCloseDialog();
  };

  const handleStartScan = (targetId: string) => {
    setTargets(prev => prev.map(t =>
      t.id === targetId ? { ...t, status: 'running', progress: 0 } : t
    ));
  };

  const handleStopScan = (targetId: string) => {
    setTargets(prev => prev.map(t =>
      t.id === targetId ? { ...t, status: 'idle', progress: 0 } : t
    ));
  };

  const handleDeleteTarget = (targetId: string) => {
    setTargets(prev => prev.filter(t => t.id !== targetId));
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running': return <PlayArrow color="primary" />;
      case 'completed': return <CheckCircle color="success" />;
      case 'failed': return <Error color="error" />;
      case 'scheduled': return <Schedule color="warning" />;
      default: return <Pause color="disabled" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'info';
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'scheduled': return 'warning';
      default: return 'default';
    }
  };

  const getRiskLevel = (score?: number) => {
    if (!score) return { label: '-', color: 'default' };
    if (score >= 8) return { label: '高風險', color: 'error' };
    if (score >= 5) return { label: '中風險', color: 'warning' };
    return { label: '低風險', color: 'success' };
  };

  return (
    <Box sx={{ flexGrow: 1 }}>
      {/* 頁面標題和操作 */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" fontWeight={600}>
          🔍 掃描管理
        </Typography>
        <Button
          variant="contained"
          startIcon={<Add />}
          onClick={() => handleOpenDialog()}
          size="large"
        >
          新增掃描目標
        </Button>
      </Box>

      {/* 掃描統計卡片 */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Security sx={{ fontSize: 40, color: 'primary.main', mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {targets.length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    掃描目標總數
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <PlayArrow sx={{ fontSize: 40, color: 'info.main', mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {targets.filter(t => t.status === 'running').length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    運行中掃描
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Schedule sx={{ fontSize: 40, color: 'warning.main', mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {targets.filter(t => t.schedule).length}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    排程掃描
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Warning sx={{ fontSize: 40, color: 'error.main', mr: 2 }} />
                <Box>
                  <Typography variant="h4" fontWeight="bold">
                    {targets.reduce((sum, t) => sum + (t.vulnerabilities || 0), 0)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    總漏洞數量
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* 掃描目標列表 */}
      <Paper sx={{ mb: 3 }}>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>
            掃描目標
          </Typography>
        </Box>

        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>狀態</TableCell>
                <TableCell>目標名稱</TableCell>
                <TableCell>URL</TableCell>
                <TableCell>掃描類型</TableCell>
                <TableCell>進度</TableCell>
                <TableCell>漏洞數</TableCell>
                <TableCell>風險評分</TableCell>
                <TableCell>最後掃描</TableCell>
                <TableCell>排程</TableCell>
                <TableCell>操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {targets.map((target) => (
                <TableRow key={target.id}>
                  <TableCell>
                    <Box display="flex" alignItems="center">
                      {getStatusIcon(target.status)}
                      <Chip
                        label={target.status}
                        color={getStatusColor(target.status) as any}
                        size="small"
                        sx={{ ml: 1 }}
                      />
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight="medium">
                      {target.name}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {target.url}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={target.scanType}
                      variant="outlined"
                      size="small"
                    />
                  </TableCell>
                  <TableCell sx={{ width: 150 }}>
                    {target.status === 'running' && target.progress !== undefined ? (
                      <Box>
                        <LinearProgress
                          variant="determinate"
                          value={target.progress}
                          sx={{ mb: 0.5 }}
                        />
                        <Typography variant="caption">
                          {target.progress}%
                        </Typography>
                      </Box>
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell>
                    {target.vulnerabilities || '-'}
                  </TableCell>
                  <TableCell>
                    {target.riskScore ? (
                      <Chip
                        label={`${target.riskScore} - ${getRiskLevel(target.riskScore).label}`}
                        color={getRiskLevel(target.riskScore).color as any}
                        size="small"
                      />
                    ) : '-'}
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {target.lastScan || '-'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {target.schedule || '-'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" gap={1}>
                      {target.status === 'idle' || target.status === 'completed' || target.status === 'failed' ? (
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => handleStartScan(target.id)}
                          title="開始掃描"
                        >
                          <PlayArrow />
                        </IconButton>
                      ) : (
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => handleStopScan(target.id)}
                          title="停止掃描"
                        >
                          <Stop />
                        </IconButton>
                      )}
                      <IconButton
                        size="small"
                        onClick={() => handleOpenDialog(target)}
                        title="編輯"
                      >
                        <Edit />
                      </IconButton>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeleteTarget(target.id)}
                        title="刪除"
                      >
                        <Delete />
                      </IconButton>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* 掃描模板 */}
      <Paper>
        <Box p={2}>
          <Typography variant="h6" gutterBottom>
            掃描模板
          </Typography>
          <Grid container spacing={2}>
            {templates.map((template) => (
              <Grid item xs={12} md={4} key={template.id}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      {template.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {template.description}
                    </Typography>
                    <Box display="flex" justifyContent="space-between" alignItems="center">
                      <Chip
                        label={`預計時間: ${template.estimatedTime}`}
                        size="small"
                        color="info"
                      />
                      <Button size="small" variant="outlined">
                        使用模板
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      </Paper>

      {/* 新增/編輯目標對話框 */}
      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedTarget ? '編輯掃描目標' : '新增掃描目標'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="目標名稱"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="目標 URL"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                placeholder="https://example.com"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>掃描類型</InputLabel>
                <Select
                  value={formData.scanType}
                  onChange={(e) => setFormData({ ...formData, scanType: e.target.value as any })}
                >
                  <MenuItem value="basic">基礎掃描</MenuItem>
                  <MenuItem value="comprehensive">全面掃描</MenuItem>
                  <MenuItem value="owasp">OWASP 掃描</MenuItem>
                  <MenuItem value="api">API 掃描</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="排程設定"
                value={formData.schedule}
                onChange={(e) => setFormData({ ...formData, schedule: e.target.value })}
                placeholder="每日 02:00"
              />
            </Grid>
            <Grid item xs={12}>
              <Typography variant="subtitle1" gutterBottom>
                掃描模組
              </Typography>
              <FormGroup row>
                {scanModules.map((module) => (
                  <FormControlLabel
                    key={module.id}
                    control={
                      <Checkbox
                        checked={formData.modules.includes(module.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setFormData({
                              ...formData,
                              modules: [...formData.modules, module.id]
                            });
                          } else {
                            setFormData({
                              ...formData,
                              modules: formData.modules.filter(m => m !== module.id)
                            });
                          }
                        }}
                      />
                    }
                    label={module.name}
                  />
                ))}
              </FormGroup>
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>取消</Button>
          <Button onClick={handleSaveTarget} variant="contained">
            {selectedTarget ? '更新' : '新增'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScanManagement;