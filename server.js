require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
// Configuration
const config = {
  jwtSecret: process.env.JWT_SECRET || 'fallback-dev-secret-key-never-use-in-production',
  jwtExpire: process.env.JWT_EXPIRE || '7d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  dbName: process.env.DATABASE_PATH || 'login_system.db'
};

// Security warning for development
// Security validation for production
if (process.env.NODE_ENV === 'production') {
  if (!process.env.JWT_SECRET) {
    console.warn('⚠️  WARNING: JWT_SECRET not set, using fallback secret');
    console.warn('⚠️  Please set JWT_SECRET in Railway dashboard');
    // Don't exit - let server continue with fallback secret
  } else {
    console.log('✅ Production security checks passed');
  }
}

//Auto Completion Manager Class
class AutoCompletionManager {
  constructor(db) {
    this.db = db;
    this.lastProcessedDate = null;
    this.isProcessing = false;
  }

  loadLastProcessedDate() {
    const metaData = this.db.data.metadata || {};
    this.lastProcessedDate = metaData.lastAutoCompletionDate || null;
    console.log(`📅 Last auto-completion: ${this.lastProcessedDate || 'Never'}`);
  }

  saveLastProcessedDate(date) {
    if (!this.db.data.metadata) {
      this.db.data.metadata = {};
    }
    this.db.data.metadata.lastAutoCompletionDate = date;
    this.db.saveToFile();
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

  processDate(dateStr) {
    console.log(`🕛 Processing auto-completion for ${dateStr}`);

    const allGoals = this.db.data.goals.filter(goal => goal.is_active);
    let completedCount = 0;

    allGoals.forEach(goal => {
      const goalCreatedDate = goal.created_at.split('T')[0];
      if (goalCreatedDate > dateStr) {
        return;
      }

      const existingLog = this.db.data.goalLogs.find(log =>
        log.goal_id === goal.id &&
        log.date === dateStr
      );

      if (!existingLog) {
        this.db.createGoalLog({
          goal_id: goal.id,
          user_id: goal.user_id,
          status: 'completed',
          date: dateStr,
          notes: 'Auto-marked as completed'
        });

        completedCount++;
      }
    });

    console.log(`✅ Processed ${dateStr}: ${missedCount} goals auto-missed`);
    return missedCount;
  }

  processMissedDays() {
    const today = new Date().toISOString().split('T')[0];

    if (this.lastProcessedDate === null) {
      // First run - only process yesterday
      const yesterday = this.getYesterdayDate();
      this.processDate(yesterday);
      this.saveLastProcessedDate(today);
      return;
    }

    // ✅ Process all dates between lastProcessedDate and yesterday
    const yesterday = this.getYesterdayDate();
    let currentDate = this.addDays(this.lastProcessedDate, 1);

    while (currentDate <= yesterday) {
      console.log(`📅 Catching up missed date: ${currentDate}`);
      this.processDate(currentDate);
      currentDate = this.addDays(currentDate, 1);
    }

    this.saveLastProcessedDate(today);
  }

  startScheduler() {
    console.log('🕛 Starting auto-completion scheduler...');

    this.loadLastProcessedDate();

    // ✅ Check every hour (low CPU usage)
    setInterval(() => {
      if (this.isProcessing) return;

      const now = new Date();
      const today = now.toISOString().split('T')[0];

      // Run once per day between midnight and 1 AM
      if (this.lastProcessedDate !== today && now.getHours() === 0) {
        this.isProcessing = true;
        try {
          this.processMissedDays();
        } catch (error) {
          console.error('❌ Auto-completion error:', error);
        } finally {
          this.isProcessing = false;
        }
      }
    }, 3600000); // Check every hour

    // ✅ Run on startup to catch up
    setTimeout(() => {
      if (!this.isProcessing) {
        this.isProcessing = true;
        try {
          this.processMissedDays();
        } catch (error) {
          console.error('❌ Startup auto-completion error:', error);
        } finally {
          this.isProcessing = false;
        }
      }
    }, 5000);

    console.log('✅ Auto-completion scheduler initialized');
  }
}


// Enhanced SQLite implementation with goals support
class SimpleDB {
  constructor(dbPath) {
      this.dbPath = dbPath;
      this.data = {
        users: [],
        sessions: [],
        loginAttempts: [],
        goals: [],
        goalLogs: [],
        metadata: {} // ✅ Add this
      };
      this.loadFromFile();
  }


loadFromFile() {
    try {
      if (fs.existsSync(this.dbPath)) {
        const fileData = fs.readFileSync(this.dbPath, 'utf8');
        const loadedData = JSON.parse(fileData);

        this.data = {
          users: loadedData.users || [],
          sessions: loadedData.sessions || [],
          loginAttempts: loadedData.loginAttempts || [],
          goals: loadedData.goals || [],
          goalLogs: loadedData.goalLogs || [],
          metadata: loadedData.metadata || {} // ✅ Add this
        };
      }
    } catch (error) {
      console.log('Creating new database...');
      this.data = {
        users: [],
        sessions: [],
        loginAttempts: [],
        goals: [],
        goalLogs: [],
        metadata: {}
      };
    }
  }

  saveToFile() {
    try {
      fs.writeFileSync(this.dbPath, JSON.stringify(this.data, null, 2));
      console.log(`💾 Database saved with ${this.data.goals.length} goals`);
    } catch (error) {
      console.error('Error saving database:', error);
    }
  }

  generateId() {
    return Date.now() + Math.random().toString(36).substr(2, 9);
  }

  // User operations (existing code)
  createUser(userData) {
    const user = {
      id: this.generateId(),
      username: userData.username,
      email: userData.email,
      password_hash: userData.password_hash,
      first_name: userData.first_name || null,
      last_name: userData.last_name || null,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_login: null
    };

    this.data.users.push(user);
    this.saveToFile();
    return user;
  }

  findUserByEmail(email) {
    return this.data.users.find(user => user.email === email && user.is_active);
  }

  findUserByUsername(username) {
    return this.data.users.find(user => user.username === username && user.is_active);
  }

  findUserById(id) {
    return this.data.users.find(user => user.id == id && user.is_active);
  }

  updateUserLastLogin(userId) {
    const user = this.findUserById(userId);
    if (user) {
      user.last_login = new Date().toISOString();
      this.saveToFile();
    }
    return user;
  }

  emailExists(email) {
    return this.data.users.some(user => user.email === email);
  }

  usernameExists(username) {
    return this.data.users.some(user => user.username === username);
  }

  // Session operations (existing code)
  createSession(sessionData) {
    const session = {
      id: this.generateId(),
      user_id: sessionData.user_id,
      token_hash: sessionData.token_hash,
      expires_at: sessionData.expires_at,
      created_at: new Date().toISOString(),
      ip_address: sessionData.ip_address,
      user_agent: sessionData.user_agent
    };

    this.data.sessions.push(session);
    this.saveToFile();
    return session;
  }

  deleteSession(tokenHash) {
    this.data.sessions = this.data.sessions.filter(session => session.token_hash !== tokenHash);
    this.saveToFile();
  }

  // Login attempts (existing code)
  logLoginAttempt(email, ipAddress, success) {
    const attempt = {
      id: this.generateId(),
      email: email,
      ip_address: ipAddress,
      success: success,
      attempted_at: new Date().toISOString()
    };

    this.data.loginAttempts.push(attempt);
    this.saveToFile();
    return attempt;
  }

  getLoginAttempts(email = null, limit = 10) {
    let attempts = this.data.loginAttempts;

    if (email) {
      attempts = attempts.filter(attempt => attempt.email === email);
    }

    return attempts
      .sort((a, b) => new Date(b.attempted_at) - new Date(a.attempted_at))
      .slice(0, limit);
  }

  // ✅ NEW: Goal operations
  createGoal(goalData) {
    const goal = {
      id: 'goal_' + Date.now() + Math.random().toString(36).substr(2, 9),
      user_id: goalData.user_id,
      title: goalData.title,
      description: goalData.description || '',
      category: goalData.category || 'General',
      color: goalData.color || '#4CAF50',
      icon: goalData.icon || 'star',
      target_frequency: goalData.target_frequency || 'daily',
      target_count: goalData.target_count || 1,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    this.data.goals.push(goal);
    this.saveToFile();
    console.log(`✅ Goal created: ${goal.title} for user ${goal.user_id}`);
    return goal;
  }

  getGoalsByUserId(userId) {
    const userGoals = this.data.goals.filter(goal => goal.user_id === userId && goal.is_active);

    // ✅ Add today's status for each goal
    const today = new Date().toISOString().split('T')[0];
    const enrichedGoals = userGoals.map(goal => {
      const todayLog = this.data.goalLogs.find(log =>
        log.goal_id === goal.id &&
        log.date === today
      );

      return {
        ...goal,
        todayStatus: todayLog ? todayLog.status : null,
        todayLogId: todayLog ? todayLog.id : null
      };
    });

    console.log(`📋 Retrieved ${enrichedGoals.length} goals for user ${userId}`);
    return enrichedGoals;
  }

  findGoalById(goalId) {
    return this.data.goals.find(goal => goal.id === goalId && goal.is_active);
  }

  updateGoal(goalId, updates) {
    const goalIndex = this.data.goals.findIndex(goal => goal.id === goalId && goal.is_active);

    if (goalIndex === -1) {
      return null;
    }

    this.data.goals[goalIndex] = {
      ...this.data.goals[goalIndex],
      ...updates,
      updated_at: new Date().toISOString()
    };

    this.saveToFile();
    console.log(`✅ Goal updated: ${goalId}`);
    return this.data.goals[goalIndex];
  }

  deleteGoal(goalId, userId) {
    const goalIndex = this.data.goals.findIndex(goal =>
      goal.id === goalId && goal.user_id === userId && goal.is_active
    );

    if (goalIndex === -1) {
      return false;
    }

    this.data.goals[goalIndex].is_active = false;
    this.data.goals[goalIndex].updated_at = new Date().toISOString();
    this.saveToFile();
    console.log(`✅ Goal deleted: ${goalId}`);
    return true;
  }

  // ✅ NEW: Goal log operations
  createGoalLog(logData) {
    const log = {
      id: 'log_' + Date.now() + Math.random().toString(36).substr(2, 9),
      goal_id: logData.goal_id,
      user_id: logData.user_id,
      date: logData.date || new Date().toISOString().split('T')[0],
      status: logData.status,
      notes: logData.notes || '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    this.data.goalLogs.push(log);
    this.saveToFile();
    console.log(`✅ Goal log created: ${log.status} for goal ${log.goal_id}`);
    return log;
  }

  getGoalLogsByGoalId(goalId, limit = 30) {
    return this.data.goalLogs
      .filter(log => log.goal_id === goalId)
      .sort((a, b) => new Date(b.date) - new Date(a.date))
      .slice(0, limit);
  }

}

function autoCompleteYesterdayGoals() {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayStr = yesterday.toISOString().split('T')[0]; // YYYY-MM-DD format

  console.log(`🕛 Running midnight auto-completion for ${yesterdayStr}`);

  // Get all active goals
  const allGoals = db.data.goals.filter(goal => goal.is_active);
  let autoCompletedCount = 0;

  allGoals.forEach(goal => {
    // Check if there's already a log for yesterday
    const existingLog = db.data.goalLogs.find(log =>
      log.goal_id === goal.id &&
      log.date === yesterdayStr
    );

    if (!existingLog) {
      // No log exists for yesterday - auto-complete it
      const autoLog = db.createGoalLog({
        goal_id: goal.id,
        user_id: goal.user_id,
        status: 'completed',
        date: yesterdayStr,
        notes: 'Auto-completed at midnight'
      });

      autoCompletedCount++;
      console.log(`✅ Auto-completed: ${goal.title} for ${yesterdayStr}`);
    }
  });

  console.log(`🎉 Midnight auto-completion finished: ${autoCompletedCount} goals completed for ${yesterdayStr}`);
  return autoCompletedCount;
}



// Initialize database
const db = new SimpleDB(path.join(__dirname, config.dbName));

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

    // Clean old entries
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
const authenticateToken = (req, res, next) => {
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

  const user = db.findUserById(decoded.userId);
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

// Apply rate limiting
app.use(createRateLimit(rateLimitStore.general, 15 * 60 * 1000, 100));

// Routes

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Login Backend API with Goals',
    version: '1.0.0',
    endpoints: {
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      profile: 'GET /api/auth/profile',
      logout: 'POST /api/auth/logout',
      verifyToken: 'GET /api/auth/verify-token',
      loginAttempts: 'GET /api/auth/login-attempts',
      health: 'GET /api/auth/health',
      goals: 'GET /api/goals',
      createGoal: 'POST /api/goals',
      goalStats: 'GET /api/goals/:goalId/stats',
      logGoal: 'POST /api/goals/:goalId/logs'
    }
  });
});

// Register endpoint (existing code)
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

      if (db.emailExists(email)) {
        return res.status(409).json({
          success: false,
          message: 'Email already registered'
        });
      }

      if (db.usernameExists(username)) {
        return res.status(409).json({
          success: false,
          message: 'Username already taken'
        });
      }

      const hashedPassword = await bcrypt.hash(password, config.bcryptRounds);

      const newUser = db.createUser({
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

// Login endpoint (existing code)
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

      db.logLoginAttempt(email, clientIp, false);

      const user = db.findUserByEmail(email);
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

      db.updateUserLastLogin(user.id);
      db.logLoginAttempt(email, clientIp, true);

      const token = generateToken(user.id);

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      db.createSession({
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

// Get profile endpoint (existing code)
app.get('/api/auth/profile', authenticateToken, (req, res) => {
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

// Verify token endpoint (existing code)
app.get('/api/auth/verify-token', authenticateToken, (req, res) => {
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

// Logout endpoint (existing code)
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const tokenHash = createSessionHash(token);
      db.deleteSession(tokenHash);
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

// Get login attempts endpoint (existing code)
app.get('/api/auth/login-attempts', authenticateToken, (req, res) => {
  try {
    const { email, limit = 10 } = req.query;
    const attempts = db.getLoginAttempts(email, parseInt(limit));

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

// ===========================
// ✅ ENHANCED GOALS ENDPOINTS
// ===========================

// Get all goals for authenticated user
app.get('/api/goals', authenticateToken, (req, res) => {
  try {
    console.log(`📋 Getting goals for user: ${req.user.id}`);
    const userGoals = db.getGoalsByUserId(req.user.id);

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

// ✅ FIXED: Create goal with proper validation and persistence
app.post('/api/goals', authenticateToken, (req, res) => {
  try {
    console.log('🔵 Create goal request received');
    console.log('📋 Request body:', req.body);
    console.log('📋 User:', req.user.id);

    const { title, description, category, color, icon, target_frequency, target_count } = req.body;

    // Validation
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

    // Create goal with proper data structure
    const newGoal = db.createGoal({
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
app.get('/api/goals/:goalId', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;
    const goal = db.findGoalById(goalId);

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
app.put('/api/goals/:goalId', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;
    const updates = req.body;

    // Check if goal belongs to user
    const existingGoal = db.findGoalById(goalId);
    if (!existingGoal || existingGoal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    const updatedGoal = db.updateGoal(goalId, updates);

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
app.delete('/api/goals/:goalId', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;

    const deleted = db.deleteGoal(goalId, req.user.id);

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

// Get goal stats (enhanced with real data)
app.get('/api/goals/:goalId/stats', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;
    const { days = 30 } = req.query;

    // Check if goal belongs to user
    const goal = db.findGoalById(goalId);
    if (!goal || goal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    // Get logs for calculation
    const logs = db.getGoalLogsByGoalId(goalId, parseInt(days));

    // Calculate stats
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
      current_streak: 3, // This would need streak calculation logic
      longest_streak: 8  // This would need streak calculation logic
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
app.post('/api/goals/:goalId/logs', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;
    const { status, date, notes } = req.body;

    // Check if goal belongs to user
    const goal = db.findGoalById(goalId);
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

    const newLog = db.createGoalLog({
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

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);

  res.status(error.status || 500).json({
    success: false,
    message: error.message || 'Internal server error'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
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

// Add this endpoint for testing (REMOVE in production)
app.post('/api/debug/auto-complete-yesterday', (req, res) => {
  try {
    console.log('🔧 Manual auto-completion triggered via API');

    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];

    console.log(`📅 Processing date: ${yesterdayStr}`);

    // Get all active goals
    const allGoals = db.data.goals.filter(goal => goal.is_active);
    console.log(`📊 Total active goals in database: ${allGoals.length}`);

    let autoCompletedCount = 0;

    allGoals.forEach(goal => {
      console.log(`\n🎯 Checking Goal: "${goal.title}"`);
      console.log(`   Goal ID: ${goal.id}`);
      console.log(`   User ID: ${goal.user_id}`);
      console.log(`   Created: ${goal.created_at.split('T')[0]}`);
      console.log(`   Looking for date: ${yesterdayStr}`);

      // Check if goal existed on yesterday
      const goalCreatedDate = goal.created_at.split('T')[0];
      if (goalCreatedDate > yesterdayStr) {
        console.log(`   ⏭️  SKIPPED: Goal created AFTER ${yesterdayStr}`);
        return;
      }

      // Check if there's already a log for yesterday
      const existingLog = db.data.goalLogs.find(log =>
        log.goal_id === goal.id &&
        log.date === yesterdayStr
      );

      if (existingLog) {
        console.log(`   ⏭️  SKIPPED: Already logged as "${existingLog.status}" for ${yesterdayStr}`);
        return;
      }

      // No log exists for yesterday - auto-complete it as "missed"
      const autoLog = db.createGoalLog({
        goal_id: goal.id,
        user_id: goal.user_id,
        status: 'completed',
        date: yesterdayStr,
        notes: 'Auto-marked as Completed'
      });

      autoCompletedCount++;
      console.log(`   ✅ SUCCESS: Auto-marked as MISSED for ${yesterdayStr}`);
    });

    console.log(`\n🎉 SUMMARY: ${autoCompletedCount} goals auto-missed for ${yesterdayStr}`);
    console.log(`📊 Total goals processed: ${allGoals.length}`);
    console.log(`✅ Goals auto-missed: ${autoCompletedCount}`);
    console.log(`⏭️  Goals skipped: ${allGoals.length - autoCompletedCount}`);

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


// ===========================
// 📊 HISTORY & ANALYTICS ENDPOINTS
// ===========================

// Get goal logs for a specific period
app.get('/api/goals/:goalId/logs', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;
    const { period = 'month', limit = 365 } = req.query;

    // Check if goal belongs to user
    const goal = db.findGoalById(goalId);
    if (!goal || goal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    // Get date range for period
    const dateRange = getDateRangeForPeriod(period);

    // Get logs within date range
    const logs = db.data.goalLogs
      .filter(log =>
        log.goal_id === goalId &&
        dateRange.start <= new Date(log.date) &&
        new Date(log.date) <= dateRange.end
      )
      .sort((a, b) => new Date(b.date) - new Date(a.date))
      .slice(0, parseInt(limit));

    res.json({
      success: true,
      data: {
        logs,
        period,
        dateRange: {
          start: dateRange.start.toISOString().split('T')[0],
          end: dateRange.end.toISOString().split('T')[0]
        }
      }
    });
  } catch (error) {
    console.error('Get goal logs error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get comprehensive goal statistics
app.get('/api/goals/:goalId/analytics', authenticateToken, (req, res) => {
  try {
    const { goalId } = req.params;
    const { period = 'month' } = req.query;

    // Check if goal belongs to user
    const goal = db.findGoalById(goalId);
    if (!goal || goal.user_id !== req.user.id) {
      return res.status(404).json({
        success: false,
        message: 'Goal not found'
      });
    }

    const dateRange = getDateRangeForPeriod(period);

    // Get logs for the period
    const logs = db.data.goalLogs.filter(log =>
      log.goal_id === goalId &&
      dateRange.start <= new Date(log.date) &&
      new Date(log.date) <= dateRange.end
    );

    // Calculate statistics
    const stats = calculateGoalStatistics(logs, dateRange, goal);

    res.json({
      success: true,
      data: {
        goal: {
          id: goal.id,
          title: goal.title,
          category: goal.category,
          color: goal.color,
          icon: goal.icon
        },
        period,
        stats,
        logs: logs.sort((a, b) => new Date(b.date) - new Date(a.date))
      }
    });
  } catch (error) {
    console.error('Get goal analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get overall user analytics
app.get('/api/analytics/overview', authenticateToken, (req, res) => {
  try {
    const { period = 'month' } = req.query;

    // Get user's active goals
    const userGoals = db.data.goals.filter(goal =>
      goal.user_id === req.user.id && goal.is_active
    );

    const dateRange = getDateRangeForPeriod(period);

    // Get all logs for user's goals in the period
    const allLogs = db.data.goalLogs.filter(log =>
      userGoals.some(goal => goal.id === log.goal_id) &&
      dateRange.start <= new Date(log.date) &&
      new Date(log.date) <= dateRange.end
    );

    // Calculate overall statistics
    const overallStats = calculateOverallStatistics(allLogs, userGoals, dateRange);

    res.json({
      success: true,
      data: {
        period,
        totalGoals: userGoals.length,
        dateRange: {
          start: dateRange.start.toISOString().split('T')[0],
          end: dateRange.end.toISOString().split('T')[0]
        },
        stats: overallStats,
        goals: userGoals.map(goal => {
          const goalLogs = allLogs.filter(log => log.goal_id === goal.id);
          const goalStats = calculateGoalStatistics(goalLogs, dateRange, goal);

          return {
            ...goal,
            stats: goalStats
          };
        })
      }
    });
  } catch (error) {
    console.error('Get overview analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Helper functions for analytics
function getDateRangeForPeriod(period) {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  switch (period) {
    case 'month':
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      return { start: startOfMonth, end: endOfMonth };

    case 'quarter':
      const quarter = Math.floor((now.getMonth()) / 3);
      const startOfQuarter = new Date(now.getFullYear(), quarter * 3, 1);
      const endOfQuarter = new Date(now.getFullYear(), quarter * 3 + 3, 0);
      return { start: startOfQuarter, end: endOfQuarter };

    case 'halfyear':
      const startOfHalfYear = new Date(now.getFullYear(), now.getMonth() - 5, 1);
      return { start: startOfHalfYear, end: today };

    case 'year':
      const startOfYear = new Date(now.getFullYear(), 0, 1);
      return { start: startOfYear, end: today };

    default:
      return { start: today, end: today };
  }
}

function calculateGoalStatistics(logs, dateRange, goal) {
  const totalDays = Math.ceil((dateRange.end - dateRange.start) / (1000 * 60 * 60 * 24)) + 1;

  // Count by status
  const completed = logs.filter(log => log.status === 'completed').length;
  const missed = logs.filter(log => log.status === 'missed').length;
  const holiday = logs.filter(log => log.status === 'holiday').length;
  const sick = logs.filter(log => log.status === 'sick').length;
  const skipped = logs.filter(log => log.status === 'skipped').length;

  const completionRate = totalDays > 0 ? Math.round((completed / totalDays) * 100) : 0;

  // Calculate streaks
  const sortedLogs = logs
    .filter(log => log.status === 'completed')
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  const streaks = calculateStreaks(sortedLogs);

  return {
    totalDays,
    completed,
    missed,
    holiday,
    sick,
    skipped,
    loggedDays: logs.length,
    unloggedDays: totalDays - logs.length,
    completionRate,
    currentStreak: streaks.current,
    longestStreak: streaks.longest
  };
}

function calculateOverallStatistics(allLogs, goals, dateRange) {
  const totalDays = Math.ceil((dateRange.end - dateRange.start) / (1000 * 60 * 60 * 24)) + 1;
  const totalPossibleLogs = goals.length * totalDays;

  const completed = allLogs.filter(log => log.status === 'completed').length;
  const missed = allLogs.filter(log => log.status === 'missed').length;
  const holiday = allLogs.filter(log => log.status === 'holiday').length;
  const sick = allLogs.filter(log => log.status === 'sick').length;
  const skipped = allLogs.filter(log => log.status === 'skipped').length;

  const overallCompletionRate = totalPossibleLogs > 0 ?
    Math.round((completed / totalPossibleLogs) * 100) : 0;

  return {
    totalDays,
    completed,
    missed,
    holiday,
    sick,
    skipped,
    totalLogs: allLogs.length,
    totalPossibleLogs,
    completionRate: overallCompletionRate
  };
}

function calculateStreaks(completedLogs) {
  if (completedLogs.length === 0) {
    return { current: 0, longest: 0 };
  }

  let currentStreak = 0;
  let longestStreak = 0;
  let tempStreak = 1;

  // Calculate longest streak from historical data
  for (let i = 1; i < completedLogs.length; i++) {
    const prevDate = new Date(completedLogs[i - 1].date);
    const currDate = new Date(completedLogs[i].date);
    const daysDiff = (currDate - prevDate) / (1000 * 60 * 60 * 24);

    if (daysDiff === 1) {
      tempStreak++;
    } else {
      longestStreak = Math.max(longestStreak, tempStreak);
      tempStreak = 1;
    }
  }
  longestStreak = Math.max(longestStreak, tempStreak);

  // Calculate current streak (from today backwards)
  const today = new Date().toISOString().split('T')[0];
  const recentLogs = completedLogs.reverse();

  for (const log of recentLogs) {
    if (log.date === today ||
        (new Date(today) - new Date(log.date)) / (1000 * 60 * 60 * 24) === currentStreak + 1) {
      currentStreak++;
    } else {
      break;
    }
  }

  return { current: currentStreak, longest: longestStreak };
}


// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Database initialized: ${config.dbName}`);
  console.log(`✅ Goals storage: ${db.data.goals.length} goals loaded`);
  console.log(`✅ API available at: http://localhost:${PORT}`);
  console.log('\n📊 API Endpoints:');
  console.log('  POST /api/auth/register   - Register user');
  console.log('  POST /api/auth/login      - Login user');
  console.log('  GET  /api/auth/profile    - Get profile (protected)');
  console.log('  GET  /api/auth/verify-token - Verify token (protected)');
  console.log('  POST /api/auth/logout     - Logout (protected)');
  console.log('  GET  /api/auth/login-attempts - Login attempts (protected)');
  console.log('  GET  /api/auth/health     - Health check');
  console.log('  GET  /api/goals           - Get all goals (protected)');
  console.log('  POST /api/goals           - Create goal (protected)');
  console.log('  GET  /api/goals/:id       - Get goal by ID (protected)');
  console.log('  PUT  /api/goals/:id       - Update goal (protected)');
  console.log('  DELETE /api/goals/:id     - Delete goal (protected)');
  console.log('  GET  /api/goals/:id/stats - Get goal stats (protected)');
  console.log('  POST /api/goals/:id/logs  - Log goal status (protected)');
});

module.exports = app;