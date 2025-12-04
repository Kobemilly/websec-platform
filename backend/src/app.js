const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const compression = require('compression');
const { errorHandler, notFound } = require('./middleware/errorMiddleware');
const { authenticate, authorize } = require('./middleware/authMiddleware');
const { requestLogger } = require('./middleware/loggingMiddleware');

// Route imports
const authRoutes = require('./routes/auth');
const scanRoutes = require('./routes/scans');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const reportRoutes = require('./routes/reports');
const assetRoutes = require('./routes/assets');
const userRoutes = require('./routes/users');
const complianceRoutes = require('./routes/compliance');
const systemRoutes = require('./routes/system');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Strict API rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many API requests, please try again later.'
  }
});

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression and logging
app.use(compression());
app.use(morgan('combined'));
app.use(requestLogger);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.API_VERSION || '1.0.0'
  });
});

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/scans', apiLimiter, authenticate, scanRoutes);
app.use('/api/v1/vulnerabilities', apiLimiter, authenticate, vulnerabilityRoutes);
app.use('/api/v1/reports', apiLimiter, authenticate, reportRoutes);
app.use('/api/v1/assets', apiLimiter, authenticate, assetRoutes);
app.use('/api/v1/users', apiLimiter, authenticate, authorize(['admin']), userRoutes);
app.use('/api/v1/compliance', apiLimiter, authenticate, complianceRoutes);
app.use('/api/v1/system', apiLimiter, authenticate, authorize(['admin']), systemRoutes);

// API Documentation
app.get('/api-docs', (req, res) => {
  res.json({
    title: 'WebSecScan API',
    version: '1.0.0',
    description: 'Professional Web Security Scanning Platform API',
    endpoints: {
      authentication: '/api/v1/auth',
      scans: '/api/v1/scans',
      vulnerabilities: '/api/v1/vulnerabilities',
      reports: '/api/v1/reports',
      assets: '/api/v1/assets',
      users: '/api/v1/users',
      compliance: '/api/v1/compliance',
      system: '/api/v1/system'
    },
    documentation: 'https://docs.websec-platform.com'
  });
});

// Error handling middleware
app.use(notFound);
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;