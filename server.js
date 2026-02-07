require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
  jwtSecret: process.env.JWT_SECRET || 'fallback-dev-secret-key-never-use-in-production',
  jwtExpire: process.env.JWT_EXPIRE || '7d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
};

// Security validation for production
if (process.env.NODE_ENV === 'production') {
  if (!process.env.JWT_SECRET) {
    console.warn('⚠️  WARNING: JWT_SECRET not set, using fallback secret');
    console.warn('⚠️  Please set JWT_SECRET in environment variables');
  } else {
    console.log('✅ Production security checks passed');
  }
}

// ============================================
// AUTO COMPLETION MANAGER CLASS
// ============================================

class AutoCompletionManager {
  constructor(db) {
    this.db = db;
    this.lastProcessedDate = null;
    this.isProcessing = false;
  }

  async loadLastProcessedDate() {
    const lastDate = await this.db.getMetadata('lastAutoCompletionDate');
    this.lastProcessedDate = lastDate;
    console.log(`📅 Last auto-completion: ${this.lastProcessedDate || 'Never'}`);
  }

  async saveLastProcessedDate(date) {
    await this.db.setMetadata('lastAutoCompletionDate', date);
    this.lastProcessedDate = date;
  }

  getYesterdayDate() {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    return yesterday.toISOString().split('T')[0];
  }

  addDays(dateStr, days) {
    const date = new Date(dateStr);
    date.setDate(date.getDate() + days);
    return date.toISOString().split('T')[0];
  }

  async processDate(dateStr) {
    console.log(`🕛 Processing auto-completion for ${dateStr}`);

    const allGoals = await this.db.getAllActiveGoals();
    let completedCount = 0;

    for (const goal of allGoals) {
      const goalCreatedDate = goal.created_at.toISOString().split('T')[0];
      if (goalCreatedDate > dateStr) {
        continue;
      }

      const existingLog = await this.db.findGoalLog(goal.id, dateStr);

      if (!existingLog) {
        await this.db.createGoalLog({
          goal_id: goal.id,
          user_id: goal.user_id,
          status: 'completed',
          date: dateStr,
          notes: 'Auto-marked as completed'
        });

        completedCount++;
      }
    }

    console.log(`✅ Processed ${dateStr}: ${completedCount} goals auto-completed`);
    return completedCount;
  }

  async processMissedDays() {
    const today = new Date().toISOString().split('T')[0];

    if (this.lastProcessedDate === null) {
      const yesterday = this.getYesterdayDate();
      await this.processDate(yesterday);
      await this.saveLastProcessedDate(today);
      return;
    }

    const yesterday = this.getYesterdayDate();
    let currentDate = this.addDays(this.lastProcessedDate, 1);

    while (currentDate <= yesterday) {
      console.log(`📅 Catching up missed date: ${currentDate}`);
      await this.processDate(currentDate);
      currentDate = this.addDays(currentDate, 1);
    }

    await this.saveLastProcessedDate(today);
  }

  startScheduler() {
    console.log('🕛 Starting auto-completion scheduler...');

    this.loadLastProcessedDate();

    setInterval(() => {
      if (this.isProcessing) return;

      const now = new Date();
      const today = now.toISOString().split('T')[0];

      if (this.lastProcessedDate !== today && now.getHours() === 0) {
        this.isProcessing = true;
        this.processMissedDays()
          .then(() => {
            this.isProcessing = false;
          })
          .catch((error) => {
            console.error('❌ Auto-completion error:', error);
            this.isProcessing = false;
          });
      }
    }, 3600000);

    setTimeout(() => {
      if (!this.isProcessing) {
        this.isProcessing = true;
        this.processMissedDays()
          .then(() => {
            this.isProcessing = false;
          })
          .catch((error) => {
            console.error('❌ Startup auto-completion error:', error);
            this.isProcessing = false;
          });
      }
    }, 5000);

    console.log('✅ Auto-completion scheduler initialized');
  }
}

// Initialize database
const db = require('./mongodb');

const autoCompletionManager = new AutoCompletionManager(db);
autoCompletionManager.startScheduler();

// Rate limiting store
const rateLimitStore = {
  general: new Map(),
  auth: new Map(),
  register: new Map()
};

// Rate limiting middleware
const createRateLimit = (store, windowMs, max) => {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();

    for (const [key, data] of store.entries()) {
      if (data.resetTime < now) {
        store.delete(key);
      }
    }

    const current = store.get(ip) || { count: 0, resetTime: now + windowMs };

    if (current.resetTime < now) {
      current.count = 1;
      current.resetTime = now + windowMs;
    } else {
      current.count++;
    }

    store.set(ip, current);

    if (current.count > max) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests, please try again later'
      });
    }

    next();
  };
};

// Validation functions
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  const minLength = 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[@$!%*?&]/.test(password);

  return password.length >= minLength && hasUpper && hasLower && hasNumber && hasSpecial;
};

const validateUsername = (username) => {
  const usernameRegex = /^[a-zA-Z0-9_]+$/;
  return username.length >= 3 && username.length <= 30 && usernameRegex.test(username);
};

// JWT utilities
const generateToken = (userId) => {
  return jwt.sign({ userId }, config.jwtSecret, { expiresIn: config.jwtExpire });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, config.jwtSecret);
  } catch (error) {
    return null;
  }
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }

  const user = await db.findUserById(decoded.userId);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: 'User not found'
    });
  }

  req.user = user;
  next();
};

// Utility functions
const createSessionHash = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

const getUserProfile = (user) => {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name,
    created_at: user.created_at,
    last_login: user.last_login
  };
};

// Middleware
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

app.use(createRateLimit(rateLimitStore.general, 15 * 60 * 1000, 100));

// ============================================
// ROUTES
// ============================================

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Habit Harbor API with MongoDB',
    version: '2.0.0',
    endpoints: {
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      profile: 'GET /api/auth/profile',
      logout: 'POST /api/auth/logout',
      verifyToken: 'GET /api/auth/verify-token',
      health: 'GET /api/auth/health',
      goals: 'GET /api/goals',
      createGoal: 'POST /api/goals',
      goalStats: 'GET /api/goals/:goalId/stats',
      logGoal: 'POST /api/goals/:goalId/logs'
    }
  });
});

// Register endpoint
app.post('/api/auth/register',
  createRateLimit(rateLimitStore.register, 60 * 60 * 1000, 3),
  async (req, res) => {
    try {
      const { username, email, password, confirmPassword, first_name, last_name } = req.body;

      const errors = [];

      if (!username || !validateUsername(username)) {
        errors.push({ field: 'username', message: 'Username must be 3-30 characters and contain only letters, numbers, and underscores' });
      }

      if (!email || !validateEmail(email)) {
        errors.push({ field: 'email', message: 'Please provide a valid email address' });
      }

      if (!password || !validatePassword(password)) {
        errors.push({
          field: 'password',
          message: 'Password must be at least 8 characters with uppercase, lowercase, number and special character'
        });
      }

      if (password !== confirmPassword) {
        errors.push({ field: 'confirmPassword', message: 'Passwords do not match' });
      }

      if (first_name && (first_name.length < 2 || first_name.length > 50)) {
        errors.push({ field: 'first_name', message: 'First name must be 2-50 characters' });
      }

      if (last_name && (last_name.length < 2 || last_name.length > 50)) {
        errors.push({ field: 'last_name', message: 'Last name must be 2-50 characters' });
      }

      if (errors.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: errors
        });
      }

      if (await db.emailExists(email)) {
        return res.status(409).json({
          success: false,
          message: 'Email already registered'
        });
      }

      if (await db.usernameExists(username)) {
        return res.status(409).json({
          success: false,
          message: 'Username already taken'
        });
      }

      const hashedPassword = await bcrypt.hash(password, config.bcryptRounds);

      const newUser = await db.createUser({
        username,
        email,
        password_hash: hashedPassword,
        first_name,
        last_name
      });

      const token = generateToken(newUser.id);

      console.log(`New user registered: ${email}`);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: getUserProfile(newUser),
          token
        }
      });

    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  });

// Login endpoint
app.post('/api/auth/login',
  createRateLimit(rateLimitStore.auth, 15 * 60 * 1000, 5),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      if (!email || !validateEmail(email)) {
        return res.status(400).json({
          success: false,
          message: 'Please provide a valid email address'
        });
      }

      if (!password) {
        return res.status(400).json({
          success: false,
          message: 'Password is required'
        });
      }

      await db.logLoginAttempt(email, clientIp, false);

      const user = await db.findUserByEmail(email);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      if (!isValidPassword) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      await db.updateUserLastLogin(user.id);
      await db.logLoginAttempt(email, clientIp, true);

      const token = generateToken(user.id);

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await db.createSession({
        user_id: user.id,
        token_hash: createSessionHash(token),
        expires_at: expiresAt.toISOString(),
        ip_address: clientIp,
        user_agent: userAgent
      });

      console.log(`User logged in: ${email}`);

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: getUserProfile(user),
          token
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Internal server error'
      });
    }
  });

// Get profile endpoint
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: getUserProfile(req.user)
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Verify token endpoint
app.get('/api/auth/verify-token', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      message: 'Token is valid',
      data: {
        user: getUserProfile(req.user)
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const tokenHash = createSessionHash(token);
      await db.deleteSession(tokenHash);
    }

    res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get login attempts endpoint
app.get('/api/auth/login-attempts', authenticateToken, async (req, res) => {
  try {
    const { email, limit = 10 } = req.query;
    const attempts = await db.getLoginAttempts(email, parseInt(limit));

    res.json({
      success: true,
      data: attempts
    });
  } catch (error) {
    console.error('Get login attempts error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Health check endpoint
app.get('/api/auth/health', (req, res) => {
  res.json({
    success: true,
    message: 'Auth service is running',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ============================================
// GOALS ENDPOINTS
// ============================================

// Get all goals for authenticated user
app.get('/api/goals', authenticateToken, async (req, res) => {
  try {
    console.log(`📋 Getting goals for user: ${req.user.id}`);
    const userGoals = await db.getGoalsByUserId(req.user.id);

    res.json({
      success: true,
      data: userGoals
    });
  } catch (error) {
    console.error('Get goals error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Create goal
app.post('/api/goals', authenticateToken, async (req, res) => {
  try {
    console.log('🔵 Create goal request received');
    console.log('📋 Request body:', req.body);
    console.log('📋 User:', req.user.id);

    const { title, description, category, color, icon, target_frequency, target_count } = req.body;

    if (!title || title.trim().length === 0) {
      console.log('❌ Title validation failed');
      return res.status(400).json({
        success: false,
        message: 'Title is required'
      });
    }

    if (title.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Title must be less than 100 characters'
      });
    }

    const newGoal = await db.createGoal({
      user_id: req.user.id,
      title: title.trim(),
      description: description?.trim() || '',
      category: category || 'General',
      color: color || '#4CAF50',
      icon: icon || 'star',
      target_frequency: target_frequency || 'daily',
      target_count: target_count || 1
    });

    console.log('✅ Goal created successfully:', newGoal.id);

    res.status(201).json({
      success: true,
      message: 'Goal created successfully',
      data: newGoal
    });
  } catch (error) {
    console.error('❌ Create goal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get goal by ID
app.get('/api/goals/:goalId', authenticateToken, async (req, res) => {
  try {
    const { goalId } = req.params;
    const goal = await db.findGoalById(goalId);

    if (!goal || goal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    res.json({
      success: true,
      data: goal
    });
  } catch (error) {
    console.error('Get goal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update goal
app.put('/api/goals/:goalId', authenticateToken, async (req, res) => {
  try {
    const { goalId } = req.params;
    const updates = req.body;

    const existingGoal = await db.findGoalById(goalId);
    if (!existingGoal || existingGoal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    const updatedGoal = await db.updateGoal(goalId, updates);

    res.json({
      success: true,
      message: 'Goal updated successfully',
      data: updatedGoal
    });
  } catch (error) {
    console.error('Update goal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete goal
app.delete('/api/goals/:goalId', authenticateToken, async (req, res) => {
  try {
    const { goalId } = req.params;

    const deleted = await db.deleteGoal(goalId, req.user.id);

    if (!deleted) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    res.json({
      success: true,
      message: 'Goal deleted successfully'
    });
  } catch (error) {
    console.error('Delete goal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get goal stats
app.get('/api/goals/:goalId/stats', authenticateToken, async (req, res) => {
  try {
    const { goalId } = req.params;
    const { days = 30 } = req.query;

    const goal = await db.findGoalById(goalId);
    if (!goal || goal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    const logs = await db.getGoalLogsByGoalId(goalId, parseInt(days));

    const completed = logs.filter(log => log.status === 'completed').length;
    const missed = logs.filter(log => log.status === 'missed').length;
    const holiday = logs.filter(log => log.status === 'holiday').length;
    const sick = logs.filter(log => log.status === 'sick').length;
    const skipped = logs.filter(log => log.status === 'skipped').length;

    const totalDays = parseInt(days);
    const completionRate = totalDays > 0 ? Math.round((completed / totalDays) * 100) : 0;

    const stats = {
      total_days: totalDays,
      completed,
      missed,
      holiday,
      sick,
      skipped,
      completion_rate: completionRate,
      current_streak: 0,
      longest_streak: 0
    };

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('Get goal stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Log goal status
app.post('/api/goals/:goalId/logs', authenticateToken, async (req, res) => {
  try {
    const { goalId } = req.params;
    const { status, date, notes } = req.body;

    const goal = await db.findGoalById(goalId);
    if (!goal || goal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    if (!status) {
      return res.status(400).json({
        success: false,
        message: 'Status is required'
      });
    }

    const validStatuses = ['completed', 'missed', 'holiday', 'sick', 'skipped'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }

    const newLog = await db.createGoalLog({
      goal_id: goalId,
      user_id: req.user.id,
      status,
      date: date || new Date().toISOString().split('T')[0],
      notes: notes || ''
    });

    res.status(201).json({
      success: true,
      message: 'Goal logged successfully',
      data: newLog
    });
  } catch (error) {
    console.error('Log goal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Debug endpoint
app.post('/api/debug/auto-complete-yesterday', async (req, res) => {
  try {
    console.log('🔧 Manual auto-completion triggered via API');

    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];

    console.log(`📅 Processing date: ${yesterdayStr}`);

    const allGoals = await db.getAllActiveGoals();
    console.log(`📊 Total active goals in database: ${allGoals.length}`);

    let autoCompletedCount = 0;

    for (const goal of allGoals) {
      console.log(`\n🎯 Checking Goal: "${goal.title}"`);
      console.log(`   Goal ID: ${goal.id}`);
      console.log(`   User ID: ${goal.user_id}`);
      console.log(`   Created: ${goal.created_at.toISOString().split('T')[0]}`);

      const goalCreatedDate = goal.created_at.toISOString().split('T')[0];
      if (goalCreatedDate > yesterdayStr) {
        console.log(`   ⏭️  SKIPPED: Goal created AFTER ${yesterdayStr}`);
        continue;
      }

      const existingLog = await db.findGoalLog(goal.id, yesterdayStr);

      if (existingLog) {
        console.log(`   ⏭️  SKIPPED: Already logged as "${existingLog.status}"`);
        continue;
      }

      await db.createGoalLog({
        goal_id: goal.id,
        user_id: goal.user_id,
        status: 'completed',
        date: yesterdayStr,
        notes: 'Auto-marked as Completed'
      });

      autoCompletedCount++;
      console.log(`   ✅ SUCCESS: Auto-marked as COMPLETED`);
    }

    console.log(`\n🎉 SUMMARY: ${autoCompletedCount} goals auto-completed for ${yesterdayStr}`);

    res.json({
      success: true,
      message: `Auto-completed ${autoCompletedCount} goals for yesterday`,
      data: {
        date: yesterdayStr,
        completedCount: autoCompletedCount,
        totalGoals: allGoals.length,
        skipped: allGoals.length - autoCompletedCount
      }
    });

  } catch (error) {
    console.error('❌ Manual auto-completion error:', error);
    res.status(500).json({
      success: false,
      message: 'Auto-completion failed',
      error: error.message
    });
  }
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);

  res.status(error.status || 500).json({
    success: false,
    message: error.message || 'Internal server error'
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await db.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await db.close();
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start server
app.listen(PORT, async () => {
  try {
    await db.connect();
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ MongoDB Atlas connected successfully!`);
    console.log(`✅ API available at: http://localhost:${PORT}`);
    console.log('\n📊 API Endpoints:');
    console.log('  POST /api/auth/register   - Register user');
    console.log('  POST /api/auth/login      - Login user');
    console.log('  GET  /api/auth/profile    - Get profile (protected)');
    console.log('  GET  /api/auth/verify-token - Verify token (protected)');
    console.log('  POST /api/auth/logout     - Logout (protected)');
    console.log('  GET  /api/goals           - Get all goals (protected)');
    console.log('  POST /api/goals           - Create goal (protected)');
    console.log('  GET  /api/goals/:id       - Get goal by ID (protected)');
    console.log('  PUT  /api/goals/:id       - Update goal (protected)');
    console.log('  DELETE /api/goals/:id     - Delete goal (protected)');
    console.log('  GET  /api/goals/:id/stats - Get goal stats (protected)');
    console.log('  POST /api/goals/:id/logs  - Log goal status (protected)');
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
});

module.exports = app;