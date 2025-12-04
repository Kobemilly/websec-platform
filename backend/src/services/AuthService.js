const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const UserSession = require('../models/UserSession');
const UserPermission = require('../models/UserPermission');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');
const { sendEmail } = require('../utils/emailService');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET;
    this.jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
    this.tokenExpiryTime = process.env.JWT_EXPIRY || '24h';
    this.refreshTokenExpiryTime = process.env.JWT_REFRESH_EXPIRY || '7d';
    this.maxFailedAttempts = 5;
    this.lockoutDuration = 30 * 60 * 1000; // 30 分鐘
  }

  /**
   * 用戶註冊
   */
  async register(userData, requestInfo = {}) {
    try {
      const { username, email, password, firstName, lastName, organization, role = 'user' } = userData;

      // 檢查用戶是否已存在
      const existingUser = await User.findOne({
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        throw new Error('用戶名或電子郵件已存在');
      }

      // 驗證密碼強度
      this.validatePasswordStrength(password);

      // 生成鹽值和雜湊密碼
      const salt = await bcrypt.genSalt(12);
      const passwordHash = await bcrypt.hash(password, salt);

      // 創建新用戶
      const newUser = new User({
        username,
        email: email.toLowerCase(),
        passwordHash,
        salt,
        firstName,
        lastName,
        organization,
        role,
        isActive: true,
        isVerified: false,
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await newUser.save();

      // 生成驗證令牌
      const verificationToken = crypto.randomBytes(32).toString('hex');
      await this.storeVerificationToken(newUser.id, verificationToken);

      // 發送驗證郵件
      await this.sendVerificationEmail(newUser, verificationToken);

      // 記錄審計日誌
      await this.logAuditEvent('USER_REGISTERED', newUser.id, {
        email: newUser.email,
        role: newUser.role
      }, requestInfo);

      logger.info(`新用戶註冊: ${email} (ID: ${newUser.id})`);

      return {
        success: true,
        message: '註冊成功，請檢查您的電子郵件以完成帳戶驗證',
        userId: newUser.id
      };

    } catch (error) {
      logger.error('用戶註冊錯誤:', error);
      throw error;
    }
  }

  /**
   * 用戶登入
   */
  async login(credentials, requestInfo = {}) {
    try {
      const { email, password, totpCode } = credentials;
      const { ipAddress, userAgent } = requestInfo;

      // 查找用戶
      const user = await User.findOne({
        email: email.toLowerCase(),
        isActive: true
      });

      if (!user) {
        await this.logFailedLogin(email, 'USER_NOT_FOUND', requestInfo);
        throw new Error('用戶名或密碼錯誤');
      }

      // 檢查帳戶鎖定
      if (await this.isAccountLocked(user)) {
        await this.logFailedLogin(email, 'ACCOUNT_LOCKED', requestInfo);
        throw new Error('帳戶已被鎖定，請稍後再試');
      }

      // 驗證密碼
      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
      if (!isPasswordValid) {
        await this.handleFailedLogin(user, 'INVALID_PASSWORD', requestInfo);
        throw new Error('用戶名或密碼錯誤');
      }

      // 檢查帳戶驗證狀態
      if (!user.isVerified) {
        throw new Error('請先驗證您的電子郵件地址');
      }

      // 檢查 MFA（如果已啟用）
      if (user.mfaEnabled) {
        if (!totpCode) {
          throw new Error('需要雙因素驗證碼');
        }

        const isMfaValid = await this.verifyMFA(user, totpCode);
        if (!isMfaValid) {
          await this.handleFailedLogin(user, 'INVALID_MFA', requestInfo);
          throw new Error('雙因素驗證碼錯誤');
        }
      }

      // 生成 JWT 令牌
      const tokens = await this.generateTokens(user);

      // 創建用戶會話
      const session = await this.createSession(user.id, tokens.refreshToken, {
        ipAddress,
        userAgent
      });

      // 更新登入資訊
      await User.updateOne(
        { _id: user.id },
        {
          lastLoginAt: new Date(),
          failedLoginAttempts: 0,
          lockedUntil: null,
          updatedAt: new Date()
        }
      );

      // 記錄審計日誌
      await this.logAuditEvent('USER_LOGIN', user.id, {
        email: user.email,
        sessionId: session.id
      }, requestInfo);

      logger.info(`用戶登入成功: ${email} (ID: ${user.id})`);

      return {
        success: true,
        message: '登入成功',
        user: this.sanitizeUser(user),
        tokens: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: this.tokenExpiryTime
        }
      };

    } catch (error) {
      logger.error('用戶登入錯誤:', error);
      throw error;
    }
  }

  /**
   * 刷新令牌
   */
  async refreshToken(refreshToken, requestInfo = {}) {
    try {
      // 驗證刷新令牌
      const decoded = jwt.verify(refreshToken, this.jwtRefreshSecret);

      // 檢查會話是否存在且有效
      const session = await UserSession.findOne({
        refreshToken: this.hashToken(refreshToken),
        isActive: true,
        expiresAt: { $gt: new Date() }
      });

      if (!session) {
        throw new Error('無效的刷新令牌');
      }

      // 獲取用戶資訊
      const user = await User.findOne({
        _id: decoded.userId,
        isActive: true
      });

      if (!user) {
        throw new Error('用戶不存在或已停用');
      }

      // 生成新的訪問令牌
      const newTokens = await this.generateTokens(user);

      // 更新會話
      await UserSession.updateOne(
        { _id: session.id },
        {
          refreshToken: this.hashToken(newTokens.refreshToken),
          updatedAt: new Date()
        }
      );

      logger.info(`令牌刷新成功: ${user.email}`);

      return {
        success: true,
        tokens: {
          accessToken: newTokens.accessToken,
          refreshToken: newTokens.refreshToken,
          expiresIn: this.tokenExpiryTime
        }
      };

    } catch (error) {
      logger.error('令牌刷新錯誤:', error);
      throw error;
    }
  }

  /**
   * 用戶登出
   */
  async logout(accessToken, requestInfo = {}) {
    try {
      const decoded = jwt.decode(accessToken);

      if (decoded && decoded.sessionId) {
        // 停用會話
        await UserSession.updateOne(
          { _id: decoded.sessionId },
          { isActive: false, updatedAt: new Date() }
        );

        // 記錄審計日誌
        await this.logAuditEvent('USER_LOGOUT', decoded.userId, {
          sessionId: decoded.sessionId
        }, requestInfo);
      }

      return {
        success: true,
        message: '登出成功'
      };

    } catch (error) {
      logger.error('用戶登出錯誤:', error);
      throw error;
    }
  }

  /**
   * 啟用 MFA
   */
  async enableMFA(userId, requestInfo = {}) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('用戶不存在');
      }

      if (user.mfaEnabled) {
        throw new Error('雙因素驗證已啟用');
      }

      // 生成 MFA 密鑰
      const secret = speakeasy.generateSecret({
        name: `WebSecScan:${user.email}`,
        issuer: 'WebSecScan Security Platform'
      });

      // 生成 QR 碼
      const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

      // 暫存密鑰（用戶確認後才正式啟用）
      await this.storeTempMfaSecret(userId, secret.base32);

      return {
        success: true,
        secret: secret.base32,
        qrCode: qrCodeUrl,
        backupCodes: await this.generateBackupCodes(userId)
      };

    } catch (error) {
      logger.error('啟用 MFA 錯誤:', error);
      throw error;
    }
  }

  /**
   * 驗證並確認 MFA 設定
   */
  async confirmMFA(userId, totpCode, requestInfo = {}) {
    try {
      const tempSecret = await this.getTempMfaSecret(userId);
      if (!tempSecret) {
        throw new Error('未找到 MFA 設定');
      }

      // 驗證 TOTP 碼
      const isValid = speakeasy.totp.verify({
        secret: tempSecret,
        encoding: 'base32',
        token: totpCode,
        window: 1
      });

      if (!isValid) {
        throw new Error('驗證碼錯誤');
      }

      // 正式啟用 MFA
      await User.updateOne(
        { _id: userId },
        {
          mfaEnabled: true,
          mfaSecret: this.encrypt(tempSecret),
          updatedAt: new Date()
        }
      );

      // 清除暫存密鑰
      await this.clearTempMfaSecret(userId);

      // 記錄審計日誌
      await this.logAuditEvent('MFA_ENABLED', userId, {}, requestInfo);

      logger.info(`用戶啟用 MFA: ${userId}`);

      return {
        success: true,
        message: '雙因素驗證已成功啟用'
      };

    } catch (error) {
      logger.error('確認 MFA 錯誤:', error);
      throw error;
    }
  }

  /**
   * 密碼重設
   */
  async resetPassword(email, requestInfo = {}) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        // 為了安全考量，即使用戶不存在也返回成功訊息
        return {
          success: true,
          message: '如果該電子郵件地址存在，您將收到重設密碼的指示'
        };
      }

      // 生成重設令牌
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

      // 儲存重設令牌（24小時有效）
      await User.updateOne(
        { _id: user.id },
        {
          passwordResetToken: resetTokenHash,
          passwordResetExpires: new Date(Date.now() + 24 * 60 * 60 * 1000),
          updatedAt: new Date()
        }
      );

      // 發送重設密碼郵件
      await this.sendPasswordResetEmail(user, resetToken);

      // 記錄審計日誌
      await this.logAuditEvent('PASSWORD_RESET_REQUESTED', user.id, {
        email: user.email
      }, requestInfo);

      return {
        success: true,
        message: '如果該電子郵件地址存在，您將收到重設密碼的指示'
      };

    } catch (error) {
      logger.error('密碼重設錯誤:', error);
      throw error;
    }
  }

  /**
   * 權限檢查
   */
  async hasPermission(userId, resource, action) {
    try {
      const user = await User.findById(userId);
      if (!user || !user.isActive) {
        return false;
      }

      // 管理員擁有所有權限
      if (user.role === 'admin') {
        return true;
      }

      // 檢查角色預設權限
      const rolePermissions = this.getRolePermissions(user.role);
      if (this.checkPermission(rolePermissions, resource, action)) {
        return true;
      }

      // 檢查用戶特殊權限
      const userPermission = await UserPermission.findOne({
        userId: userId,
        resource: resource,
        action: action
      });

      return !!userPermission;

    } catch (error) {
      logger.error('權限檢查錯誤:', error);
      return false;
    }
  }

  /**
   * 驗證密碼強度
   */
  validatePasswordStrength(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasNonalphas = /\W/.test(password);

    const errors = [];

    if (password.length < minLength) {
      errors.push(`密碼長度至少需要 ${minLength} 個字符`);
    }

    if (!hasUpperCase) {
      errors.push('密碼必須包含大寫字母');
    }

    if (!hasLowerCase) {
      errors.push('密碼必須包含小寫字母');
    }

    if (!hasNumbers) {
      errors.push('密碼必須包含數字');
    }

    if (!hasNonalphas) {
      errors.push('密碼必須包含特殊字符');
    }

    if (errors.length > 0) {
      throw new Error(`密碼不符合安全要求: ${errors.join(', ')}`);
    }

    return true;
  }

  /**
   * 生成 JWT 令牌
   */
  async generateTokens(user) {
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      iat: Math.floor(Date.now() / 1000)
    };

    const accessToken = jwt.sign(payload, this.jwtSecret, {
      expiresIn: this.tokenExpiryTime,
      issuer: 'websec-platform',
      audience: 'websec-platform-users'
    });

    const refreshToken = jwt.sign(
      { userId: user.id },
      this.jwtRefreshSecret,
      {
        expiresIn: this.refreshTokenExpiryTime,
        issuer: 'websec-platform'
      }
    );

    return { accessToken, refreshToken };
  }

  /**
   * 創建用戶會話
   */
  async createSession(userId, refreshToken, metadata = {}) {
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7天

    const session = new UserSession({
      userId,
      sessionToken: crypto.randomBytes(32).toString('hex'),
      refreshToken: this.hashToken(refreshToken),
      ipAddress: metadata.ipAddress,
      userAgent: metadata.userAgent,
      isActive: true,
      expiresAt,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    await session.save();
    return session;
  }

  /**
   * 檢查帳戶是否被鎖定
   */
  async isAccountLocked(user) {
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return true;
    }
    return false;
  }

  /**
   * 處理登入失敗
   */
  async handleFailedLogin(user, reason, requestInfo) {
    const failedAttempts = (user.failedLoginAttempts || 0) + 1;
    const updateData = {
      failedLoginAttempts: failedAttempts,
      updatedAt: new Date()
    };

    if (failedAttempts >= this.maxFailedAttempts) {
      updateData.lockedUntil = new Date(Date.now() + this.lockoutDuration);
    }

    await User.updateOne({ _id: user.id }, updateData);

    await this.logAuditEvent('LOGIN_FAILED', user.id, { reason }, requestInfo);
  }

  /**
   * 獲取角色權限
   */
  getRolePermissions(role) {
    const permissions = {
      admin: {
        scans: ['create', 'read', 'update', 'delete'],
        users: ['create', 'read', 'update', 'delete'],
        reports: ['create', 'read', 'update', 'delete'],
        system: ['read', 'update']
      },
      manager: {
        scans: ['create', 'read', 'update'],
        users: ['read'],
        reports: ['create', 'read', 'update'],
        system: ['read']
      },
      analyst: {
        scans: ['create', 'read'],
        reports: ['create', 'read'],
        vulnerabilities: ['read', 'update']
      },
      user: {
        scans: ['create', 'read'],
        reports: ['read'],
        vulnerabilities: ['read']
      }
    };

    return permissions[role] || permissions.user;
  }

  /**
   * 檢查權限
   */
  checkPermission(rolePermissions, resource, action) {
    return rolePermissions[resource] && rolePermissions[resource].includes(action);
  }

  /**
   * 記錄審計事件
   */
  async logAuditEvent(action, userId, details, requestInfo) {
    try {
      const auditLog = new AuditLog({
        userId,
        action,
        details,
        ipAddress: requestInfo.ipAddress,
        userAgent: requestInfo.userAgent,
        timestamp: new Date()
      });

      await auditLog.save();
    } catch (error) {
      logger.error('記錄審計事件錯誤:', error);
    }
  }

  /**
   * 雜湊令牌
   */
  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * 加密敏感數據
   */
  encrypt(text) {
    const algorithm = 'aes-256-gcm';
    const secretKey = process.env.ENCRYPTION_KEY;
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipher(algorithm, secretKey);
    cipher.setAAD(Buffer.from('websec-platform', 'utf8'));

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      iv: iv.toString('hex'),
      encryptedData: encrypted,
      authTag: authTag.toString('hex')
    };
  }

  /**
   * 清理用戶資料（移除敏感資訊）
   */
  sanitizeUser(user) {
    const sanitized = { ...user.toObject() };
    delete sanitized.passwordHash;
    delete sanitized.salt;
    delete sanitized.mfaSecret;
    delete sanitized.passwordResetToken;
    delete sanitized.passwordResetExpires;
    return sanitized;
  }
}

module.exports = AuthService;