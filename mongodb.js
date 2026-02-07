require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb');

class MongoDB {
  constructor() {
    this.client = null;
    this.db = null;
    this.isConnected = false;
  }

  async connect() {
    if (this.isConnected) {
      return this.db;
    }

    try {
      console.log('🔄 Connecting to MongoDB Atlas...');
      this.client = new MongoClient(process.env.MONGODB_URI);
      await this.client.connect();
      this.db = this.client.db('habit_harbor');
      this.isConnected = true;
      console.log('✅ MongoDB Atlas connected successfully!');
      return this.db;
    } catch (error) {
      console.error('❌ MongoDB connection error:', error);
      throw error;
    }
  }

  async close() {
    if (this.client) {
      await this.client.close();
      this.isConnected = false;
      console.log('✅ MongoDB connection closed');
    }
  }

  // ============================================
  // USER OPERATIONS
  // ============================================

  async createUser(userData) {
    const db = await this.connect();
    const user = {
      username: userData.username,
      email: userData.email,
      password_hash: userData.password_hash,
      first_name: userData.first_name || null,
      last_name: userData.last_name || null,
      is_active: true,
      created_at: new Date(),
      updated_at: new Date(),
      last_login: null
    };

    const result = await db.collection('users').insertOne(user);
    user.id = result.insertedId.toString();
    console.log(`✅ User created: ${user.email}`);
    return user;
  }

  async findUserByEmail(email) {
    const db = await this.connect();
    const user = await db.collection('users').findOne({
      email: email,
      is_active: true
    });

    if (user) {
      user.id = user._id.toString();
    }
    return user;
  }

  async findUserByUsername(username) {
    const db = await this.connect();
    const user = await db.collection('users').findOne({
      username: username,
      is_active: true
    });

    if (user) {
      user.id = user._id.toString();
    }
    return user;
  }

  async findUserById(id) {
    const db = await this.connect();
    let query;

    // Handle both string IDs and ObjectIds
    try {
      query = { _id: new ObjectId(id), is_active: true };
    } catch {
      query = { id: id, is_active: true };
    }

    const user = await db.collection('users').findOne(query);

    if (user) {
      user.id = user._id.toString();
    }
    return user;
  }

  async updateUserLastLogin(userId) {
    const db = await this.connect();

    let query;
    try {
      query = { _id: new ObjectId(userId) };
    } catch {
      query = { id: userId };
    }

    await db.collection('users').updateOne(
      query,
      { $set: { last_login: new Date() } }
    );

    return await this.findUserById(userId);
  }

  async emailExists(email) {
    const db = await this.connect();
    const count = await db.collection('users').countDocuments({ email: email });
    return count > 0;
  }

  async usernameExists(username) {
    const db = await this.connect();
    const count = await db.collection('users').countDocuments({ username: username });
    return count > 0;
  }

  // ============================================
  // SESSION OPERATIONS
  // ============================================

  async createSession(sessionData) {
    const db = await this.connect();
    const session = {
      user_id: sessionData.user_id,
      token_hash: sessionData.token_hash,
      expires_at: new Date(sessionData.expires_at),
      created_at: new Date(),
      ip_address: sessionData.ip_address,
      user_agent: sessionData.user_agent
    };

    const result = await db.collection('sessions').insertOne(session);
    session.id = result.insertedId.toString();
    return session;
  }

  async deleteSession(tokenHash) {
    const db = await this.connect();
    await db.collection('sessions').deleteOne({ token_hash: tokenHash });
  }

  // ============================================
  // LOGIN ATTEMPTS
  // ============================================

  async logLoginAttempt(email, ipAddress, success) {
    const db = await this.connect();
    const attempt = {
      email: email,
      ip_address: ipAddress,
      success: success,
      attempted_at: new Date()
    };

    await db.collection('login_attempts').insertOne(attempt);
    return attempt;
  }

  async getLoginAttempts(email = null, limit = 10) {
    const db = await this.connect();
    const query = email ? { email: email } : {};

    const attempts = await db.collection('login_attempts')
      .find(query)
      .sort({ attempted_at: -1 })
      .limit(limit)
      .toArray();

    return attempts;
  }

  // ============================================
  // GOAL OPERATIONS
  // ============================================

  async createGoal(goalData) {
    const db = await this.connect();
    const goal = {
      user_id: goalData.user_id,
      title: goalData.title,
      description: goalData.description || '',
      category: goalData.category || 'General',
      color: goalData.color || '#4CAF50',
      icon: goalData.icon || 'star',
      target_frequency: goalData.target_frequency || 'daily',
      target_count: goalData.target_count || 1,
      is_active: true,
      created_at: new Date(),
      updated_at: new Date()
    };

    const result = await db.collection('goals').insertOne(goal);
    goal.id = result.insertedId.toString();
    console.log(`✅ Goal created: ${goal.title} for user ${goal.user_id}`);
    return goal;
  }

  async getGoalsByUserId(userId) {
    const db = await this.connect();
    const goals = await db.collection('goals')
      .find({ user_id: userId, is_active: true })
      .toArray();

    // Add today's status for each goal
    const today = new Date().toISOString().split('T')[0];
    const enrichedGoals = await Promise.all(
      goals.map(async (goal) => {
        goal.id = goal._id.toString();

        const todayLog = await db.collection('goal_logs').findOne({
          goal_id: goal.id,
          date: today
        });

        return {
          ...goal,
          todayStatus: todayLog ? todayLog.status : null,
          todayLogId: todayLog ? todayLog._id.toString() : null
        };
      })
    );

    console.log(`📋 Retrieved ${enrichedGoals.length} goals for user ${userId}`);
    return enrichedGoals;
  }

  async findGoalById(goalId) {
    const db = await this.connect();
    let query;

    try {
      query = { _id: new ObjectId(goalId), is_active: true };
    } catch {
      query = { id: goalId, is_active: true };
    }

    const goal = await db.collection('goals').findOne(query);

    if (goal) {
      goal.id = goal._id.toString();
    }
    return goal;
  }

  async updateGoal(goalId, updates) {
    const db = await this.connect();
    let query;

    try {
      query = { _id: new ObjectId(goalId), is_active: true };
    } catch {
      query = { id: goalId, is_active: true };
    }

    const updateData = {
      ...updates,
      updated_at: new Date()
    };

    delete updateData.id;
    delete updateData._id;

    await db.collection('goals').updateOne(
      query,
      { $set: updateData }
    );

    console.log(`✅ Goal updated: ${goalId}`);
    return await this.findGoalById(goalId);
  }

  async deleteGoal(goalId, userId) {
    const db = await this.connect();
    let query;

    try {
      query = { _id: new ObjectId(goalId), user_id: userId, is_active: true };
    } catch {
      query = { id: goalId, user_id: userId, is_active: true };
    }

    const result = await db.collection('goals').updateOne(
      query,
      {
        $set: {
          is_active: false,
          updated_at: new Date()
        }
      }
    );

    console.log(`✅ Goal deleted: ${goalId}`);
    return result.modifiedCount > 0;
  }

  // ============================================
  // GOAL LOG OPERATIONS
  // ============================================

  async createGoalLog(logData) {
    const db = await this.connect();
    const log = {
      goal_id: logData.goal_id,
      user_id: logData.user_id,
      date: logData.date || new Date().toISOString().split('T')[0],
      status: logData.status,
      notes: logData.notes || '',
      created_at: new Date(),
      updated_at: new Date()
    };

    const result = await db.collection('goal_logs').insertOne(log);
    log.id = result.insertedId.toString();
    console.log(`✅ Goal log created: ${log.status} for goal ${log.goal_id}`);
    return log;
  }

  async getGoalLogsByGoalId(goalId, limit = 30) {
    const db = await this.connect();
    const logs = await db.collection('goal_logs')
      .find({ goal_id: goalId })
      .sort({ date: -1 })
      .limit(limit)
      .toArray();

    logs.forEach(log => {
      log.id = log._id.toString();
    });

    return logs;
  }

  async getAllActiveGoals() {
    const db = await this.connect();
    const goals = await db.collection('goals')
      .find({ is_active: true })
      .toArray();

    goals.forEach(goal => {
      goal.id = goal._id.toString();
    });

    return goals;
  }

  async findGoalLog(goalId, date) {
    const db = await this.connect();
    const log = await db.collection('goal_logs').findOne({
      goal_id: goalId,
      date: date
    });

    if (log) {
      log.id = log._id.toString();
    }
    return log;
  }

  // ============================================
  // METADATA OPERATIONS (for auto-completion)
  // ============================================

  async getMetadata(key) {
    const db = await this.connect();
    const metadata = await db.collection('metadata').findOne({ key: key });
    return metadata ? metadata.value : null;
  }

  async setMetadata(key, value) {
    const db = await this.connect();
    await db.collection('metadata').updateOne(
      { key: key },
      { $set: { key: key, value: value, updated_at: new Date() } },
      { upsert: true }
    );
  }
}

// Export singleton instance
const mongodb = new MongoDB();
module.exports = mongodb;