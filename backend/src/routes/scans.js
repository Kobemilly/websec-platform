const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const ScanService = require('../services/ScanService');
const { authorize } = require('../middleware/authMiddleware');
const { validateRequest } = require('../middleware/validationMiddleware');
const { asyncHandler } = require('../utils/asyncHandler');

const router = express.Router();

/**
 * @route   GET /api/v1/scans
 * @desc    Get all scan targets for the authenticated user
 * @access  Private
 */
router.get('/',
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('status').optional().isIn(['idle', 'running', 'completed', 'failed', 'scheduled']).withMessage('Invalid status'),
    query('scanType').optional().isIn(['basic', 'comprehensive', 'owasp', 'api']).withMessage('Invalid scan type'),
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, status, scanType, search } = req.query;

    const filters = {
      userId: req.user.id,
      ...(status && { status }),
      ...(scanType && { scanType }),
      ...(search && { search })
    };

    const result = await ScanService.getScanTargets(filters, {
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.json({
      success: true,
      data: result.targets,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: result.total,
        pages: Math.ceil(result.total / limit)
      }
    });
  })
);

/**
 * @route   GET /api/v1/scans/:id
 * @desc    Get scan target by ID
 * @access  Private
 */
router.get('/:id',
  [
    param('id').isUUID().withMessage('Invalid scan ID format')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const scanTarget = await ScanService.getScanTargetById(req.params.id, req.user.id);

    if (!scanTarget) {
      return res.status(404).json({
        success: false,
        message: 'Scan target not found'
      });
    }

    res.json({
      success: true,
      data: scanTarget
    });
  })
);

/**
 * @route   POST /api/v1/scans
 * @desc    Create new scan target
 * @access  Private
 */
router.post('/',
  [
    body('name').trim().isLength({ min: 1, max: 100 }).withMessage('Name must be 1-100 characters'),
    body('url').isURL({ protocols: ['http', 'https'] }).withMessage('Valid URL required'),
    body('scanType').isIn(['basic', 'comprehensive', 'owasp', 'api']).withMessage('Invalid scan type'),
    body('schedule').optional().matches(/^(daily|weekly|monthly) \d{2}:\d{2}$/).withMessage('Invalid schedule format'),
    body('modules').optional().isArray().withMessage('Modules must be an array'),
    body('modules.*').optional().isString().withMessage('Each module must be a string'),
    body('description').optional().isLength({ max: 500 }).withMessage('Description must be max 500 characters')
  ],
  validateRequest,
  authorize(['user', 'admin']),
  asyncHandler(async (req, res) => {
    const scanData = {
      ...req.body,
      userId: req.user.id,
      createdBy: req.user.id
    };

    const scanTarget = await ScanService.createScanTarget(scanData);

    res.status(201).json({
      success: true,
      message: 'Scan target created successfully',
      data: scanTarget
    });
  })
);

/**
 * @route   PUT /api/v1/scans/:id
 * @desc    Update scan target
 * @access  Private
 */
router.put('/:id',
  [
    param('id').isUUID().withMessage('Invalid scan ID format'),
    body('name').optional().trim().isLength({ min: 1, max: 100 }).withMessage('Name must be 1-100 characters'),
    body('url').optional().isURL({ protocols: ['http', 'https'] }).withMessage('Valid URL required'),
    body('scanType').optional().isIn(['basic', 'comprehensive', 'owasp', 'api']).withMessage('Invalid scan type'),
    body('schedule').optional().matches(/^(daily|weekly|monthly) \d{2}:\d{2}$/).withMessage('Invalid schedule format'),
    body('modules').optional().isArray().withMessage('Modules must be an array'),
    body('description').optional().isLength({ max: 500 }).withMessage('Description must be max 500 characters')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const updatedTarget = await ScanService.updateScanTarget(req.params.id, req.body, req.user.id);

    if (!updatedTarget) {
      return res.status(404).json({
        success: false,
        message: 'Scan target not found'
      });
    }

    res.json({
      success: true,
      message: 'Scan target updated successfully',
      data: updatedTarget
    });
  })
);

/**
 * @route   DELETE /api/v1/scans/:id
 * @desc    Delete scan target
 * @access  Private
 */
router.delete('/:id',
  [
    param('id').isUUID().withMessage('Invalid scan ID format')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const deleted = await ScanService.deleteScanTarget(req.params.id, req.user.id);

    if (!deleted) {
      return res.status(404).json({
        success: false,
        message: 'Scan target not found'
      });
    }

    res.json({
      success: true,
      message: 'Scan target deleted successfully'
    });
  })
);

/**
 * @route   POST /api/v1/scans/:id/start
 * @desc    Start a scan
 * @access  Private
 */
router.post('/:id/start',
  [
    param('id').isUUID().withMessage('Invalid scan ID format'),
    body('priority').optional().isIn(['low', 'normal', 'high', 'critical']).withMessage('Invalid priority level')
  ],
  validateRequest,
  authorize(['user', 'admin']),
  asyncHandler(async (req, res) => {
    const { priority = 'normal' } = req.body;

    const scanJob = await ScanService.startScan(req.params.id, {
      userId: req.user.id,
      priority
    });

    if (!scanJob) {
      return res.status(404).json({
        success: false,
        message: 'Scan target not found or already running'
      });
    }

    res.json({
      success: true,
      message: 'Scan started successfully',
      data: {
        jobId: scanJob.id,
        estimatedDuration: scanJob.estimatedDuration,
        status: 'queued'
      }
    });
  })
);

/**
 * @route   POST /api/v1/scans/:id/stop
 * @desc    Stop a running scan
 * @access  Private
 */
router.post('/:id/stop',
  [
    param('id').isUUID().withMessage('Invalid scan ID format')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const stopped = await ScanService.stopScan(req.params.id, req.user.id);

    if (!stopped) {
      return res.status(404).json({
        success: false,
        message: 'Scan not found or not running'
      });
    }

    res.json({
      success: true,
      message: 'Scan stopped successfully'
    });
  })
);

/**
 * @route   GET /api/v1/scans/:id/status
 * @desc    Get scan status and progress
 * @access  Private
 */
router.get('/:id/status',
  [
    param('id').isUUID().withMessage('Invalid scan ID format')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const status = await ScanService.getScanStatus(req.params.id, req.user.id);

    if (!status) {
      return res.status(404).json({
        success: false,
        message: 'Scan not found'
      });
    }

    res.json({
      success: true,
      data: status
    });
  })
);

/**
 * @route   GET /api/v1/scans/:id/results
 * @desc    Get scan results
 * @access  Private
 */
router.get('/:id/results',
  [
    param('id').isUUID().withMessage('Invalid scan ID format'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('severity').optional().isIn(['low', 'medium', 'high', 'critical']).withMessage('Invalid severity level')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, severity } = req.query;

    const results = await ScanService.getScanResults(req.params.id, {
      userId: req.user.id,
      page: parseInt(page),
      limit: parseInt(limit),
      severity
    });

    if (!results) {
      return res.status(404).json({
        success: false,
        message: 'Scan results not found'
      });
    }

    res.json({
      success: true,
      data: results
    });
  })
);

/**
 * @route   POST /api/v1/scans/bulk-start
 * @desc    Start multiple scans
 * @access  Private - Admin only
 */
router.post('/bulk-start',
  [
    body('scanIds').isArray({ min: 1, max: 10 }).withMessage('Scan IDs must be an array of 1-10 items'),
    body('scanIds.*').isUUID().withMessage('Each scan ID must be valid UUID'),
    body('priority').optional().isIn(['low', 'normal', 'high', 'critical']).withMessage('Invalid priority level')
  ],
  validateRequest,
  authorize(['admin']),
  asyncHandler(async (req, res) => {
    const { scanIds, priority = 'normal' } = req.body;

    const results = await ScanService.bulkStartScans(scanIds, {
      userId: req.user.id,
      priority
    });

    res.json({
      success: true,
      message: `Started ${results.successful.length} scans, ${results.failed.length} failed`,
      data: results
    });
  })
);

/**
 * @route   GET /api/v1/scans/templates
 * @desc    Get available scan templates
 * @access  Private
 */
router.get('/templates',
  asyncHandler(async (req, res) => {
    const templates = await ScanService.getScanTemplates();

    res.json({
      success: true,
      data: templates
    });
  })
);

/**
 * @route   POST /api/v1/scans/validate-target
 * @desc    Validate a target URL before creating scan
 * @access  Private
 */
router.post('/validate-target',
  [
    body('url').isURL({ protocols: ['http', 'https'] }).withMessage('Valid URL required')
  ],
  validateRequest,
  asyncHandler(async (req, res) => {
    const validation = await ScanService.validateTarget(req.body.url);

    res.json({
      success: true,
      data: validation
    });
  })
);

module.exports = router;