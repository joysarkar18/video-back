const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Data storage with ban tracking
const users = new Map(); // socketId -> user data
const rooms = new Map(); // roomId -> room data
const bannedIPs = new Map(); // IP -> { timestamp, reason, duration }
const userIPs = new Map(); // socketId -> IP
const userReports = new Map(); // IP -> array of reports
const verifiedUnbans = new Map(); // transactionId -> { ip, timestamp }

// Admin system
let adminKey = 'admin123';
const superAdminToken = 'super-admin-' + uuidv4();

console.log(`🔐 Super Admin Panel: http://localhost:${process.env.PORT || 3000}/super-admin/${superAdminToken}`);

// RevenueCat configuration
const rcApiKey = process.env.REVENUECAT_API_KEY || 'your_revenuecat_api_key';

// User class
class User {
  constructor(socketId, countries, userInfo, ip) {
    this.socketId = socketId;
    this.countries = countries;
    this.userInfo = userInfo;
    this.ip = ip;
    this.isOnline = true;
    this.isMatched = false;
    this.roomId = null;
    this.connectedAt = new Date();
  }
}

// Report class
class UserReport {
  constructor(reportedIp, reporterSocketId, reason) {
    this.id = uuidv4();
    this.reportedIp = reportedIp;
    this.reporterSocketId = reporterSocketId;
    this.reason = reason;
    this.timestamp = new Date();
  }
}

// Get client IP
function getClientIP(socket) {
  const forwarded = socket.handshake.headers['x-forwarded-for'];
  const real = socket.handshake.headers['x-real-ip'];
  let ip = forwarded ? forwarded.split(',')[0].trim() : 
           real || socket.handshake.address || socket.conn.remoteAddress;
  
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  return ip;
}

// Check if IP is banned and return ban info
function checkBanStatus(ip) {
  if (!bannedIPs.has(ip)) {
    return null;
  }

  const banInfo = bannedIPs.get(ip);
  const now = Date.now();
  const banElapsed = now - banInfo.timestamp;
  
  // If ban duration has passed, remove it
  if (banInfo.duration && banElapsed >= banInfo.duration) {
    bannedIPs.delete(ip);
    console.log(`✅ Ban expired for IP: ${ip}`);
    return null;
  }

  // Calculate remaining ban time
  const remainingMs = banInfo.duration ? banInfo.duration - banElapsed : null;

  return {
    isBanned: true,
    reason: banInfo.reason,
    remainingMs: remainingMs,
    message: 'You have been banned from this service'
  };
}

// Ban IP function
function banIP(ip, reason = 'No reason provided', durationHours = 24) {
  const durationMs = durationHours * 60 * 60 * 1000;
  
  bannedIPs.set(ip, {
    timestamp: Date.now(),
    reason: reason,
    duration: durationMs
  });
  
  console.log(`🔨 Banned IP: ${ip} for ${durationHours} hours - Reason: ${reason}`);
  
  // Disconnect all users from this IP
  for (const [socketId, userIP] of userIPs.entries()) {
    if (userIP === ip) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit('banned', { 
          message: 'You have been banned from this service',
          reason: reason,
          banDurationMs: durationMs
        });
      }
    }
  }
  
  broadcastStats();
  return true;
}

// Unban IP function
function unbanIP(ip) {
  const removed = bannedIPs.delete(ip);
  if (removed) {
    console.log(`✅ Unbanned IP: ${ip}`);
    userReports.delete(ip);
  }
  
  broadcastStats();
  return removed;
}

// Verify RevenueCat transaction
async function verifyRevenueCatTransaction(transactionId, receiptToken) {
  try {
    console.log(`🔍 Verifying RevenueCat transaction: ${transactionId}`);

    // Call RevenueCat API to verify the receipt
    const response = await fetch('https://api.revenuecat.com/v1/receipts/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${rcApiKey}`,
        'Content-Type': 'application/json',
        'X-Platform': 'android'
      },
      body: JSON.stringify({
        receipt_token: receiptToken,
        transaction_id: transactionId
      })
    });

    if (!response.ok) {
      console.error(`❌ RevenueCat API error: ${response.status}`);
      console.error(`Response: ${await response.text()}`);
      return false;
    }

    const data = await response.json();
    console.log(`✅ RevenueCat verification response:`, data);

    // Check if the receipt is valid and has the unban entitlement
    if (data.is_valid && data.entitlements && data.entitlements.active) {
      const hasUnbanEntitlement = Object.keys(data.entitlements.active).some(key => 
        key.includes('unban') || key === 'unban_entitlement'
      );

      if (hasUnbanEntitlement) {
        console.log(`✅ Unban entitlement confirmed for transaction: ${transactionId}`);
        return true;
      }
    }

    console.log(`❌ No unban entitlement found in transaction: ${transactionId}`);
    return false;
  } catch (error) {
    console.error('❌ Error verifying RevenueCat transaction:', error);
    return false;
  }
}

// Broadcast stats
function broadcastStats() {
  const onlineUsers = Array.from(users.values()).filter(u => u.isOnline);
  const matchedUsers = onlineUsers.filter(u => u.isMatched);
  const totalReports = Array.from(userReports.values()).reduce((sum, reports) => sum + reports.length, 0);
  const reportedIPs = userReports.size;
  
  const stats = {
    totalUsers: users.size,
    onlineUsers: onlineUsers.length,
    matchedUsers: matchedUsers.length,
    waitingUsers: onlineUsers.length - matchedUsers.length,
    activeRooms: rooms.size,
    bannedIPs: bannedIPs.size,
    totalReports,
    reportedIPs
  };
  
  io.emit('stats-updated', stats);
}

// Report handling
function reportUser(reportedIp, reporterSocketId, reason) {
  const reporterIP = userIPs.get(reporterSocketId);
  if (reporterIP === reportedIp) {
    return { success: false, message: 'Cannot report yourself' };
  }

  if (bannedIPs.has(reportedIp)) {
    return { success: false, message: 'User is already banned' };
  }

  const report = new UserReport(reportedIp, reporterSocketId, reason);
  
  if (!userReports.has(reportedIp)) {
    userReports.set(reportedIp, []);
  }
  userReports.get(reportedIp).push(report);

  const reportCount = userReports.get(reportedIp).length;
  console.log(`📋 Report #${reportCount} filed against IP: ${reportedIp}`);
  console.log(`   Reason: ${reason}`);

  broadcastStats();

  return { 
    success: true, 
    message: `User reported (${reportCount} reports)`,
    reportCount: reportCount
  };
}

// Matching logic
function findMatch(user) {
  for (const [, otherUser] of users.entries()) {
    if (otherUser.socketId !== user.socketId && 
        !otherUser.isMatched && 
        otherUser.countries.some(country => user.countries.includes(country))) {
      return otherUser;
    }
  }
  return null;
}

function createRoom(user1, user2) {
  const roomId = uuidv4();
  const room = {
    id: roomId,
    users: [user1, user2],
    createdAt: new Date()
  };
  
  rooms.set(roomId, room);
  user1.isMatched = true;
  user1.roomId = roomId;
  user2.isMatched = true;
  user2.roomId = roomId;
  
  return room;
}

// Socket.IO events
io.on('connection', (socket) => {
  const clientIP = getClientIP(socket);
  userIPs.set(socket.id, clientIP);
  
  console.log(`👤 User connected: ${socket.id} from ${clientIP}`);
  
  // Send current user count immediately
  const currentUserCount = io.sockets.sockets.size;
  socket.emit('update-user-count', currentUserCount);
  io.emit('update-user-count', currentUserCount);
  
  broadcastStats();

  socket.on('join', (data) => {
    const { countries, userInfo } = data;
    console.log(`📍 Join request from ${socket.id} (${clientIP})`);

    if (!countries || countries.length === 0) {
      return socket.emit('error', { message: 'Please select at least one country' });
    }

    const banStatus = checkBanStatus(clientIP);
    if (banStatus && banStatus.isBanned) {
        console.log(`🚫 Banned user tried to join: ${clientIP}`);
        socket.emit('banned', {
            message: banStatus.message,
            reason: banStatus.reason,
            banDurationMs: banStatus.remainingMs
        });
        return socket.disconnect(true);
    }

    const user = new User(socket.id, countries, userInfo, clientIP);
    users.set(socket.id, user);
    console.log(`✅ User ${socket.id} created and waiting for ready signal.`);
    socket.emit('waiting');
    broadcastStats();
  });

  socket.on('ready-for-match', () => {
    const user = users.get(socket.id);
    if (!user) {
        return console.log(`[Warning] 'ready-for-match' from unknown user ${socket.id}`);
    }
    if(user.isMatched) {
        return console.log(`[Warning] 'ready-for-match' from already matched user ${socket.id}`);
    }

    console.log(`[Ready] User ${socket.id} is ready for a match.`);
    const match = findMatch(user);
    
    if (match) {
        const room = createRoom(user, match);
        const userSocket = io.sockets.sockets.get(user.socketId);
        const matchSocket = io.sockets.sockets.get(match.socketId);
        
        userSocket?.join(room.id);
        matchSocket?.join(room.id);
        
        userSocket?.emit('matched', {
            roomId: room.id,
            isOfferer: true,
            partner: { socketId: match.socketId, userInfo: match.userInfo, ip: match.ip }
        });
        
        matchSocket?.emit('matched', {
            roomId: room.id,
            isOfferer: false,
            partner: { socketId: user.socketId, userInfo: user.userInfo, ip: user.ip }
        });
        
        console.log(`🤝 Match: ${user.socketId} <-> ${match.socketId}`);
    } else {
        socket.emit('waiting', { message: 'Looking for a match...' });
        console.log(`⏳ ${socket.id} is waiting for a match.`);
    }
    broadcastStats();
  });
  
  socket.on('next', () => {
    const user = users.get(socket.id);
    if (!user || !user.isMatched) return;

    const room = rooms.get(user.roomId);
    if (!room) return;

    const partner = room.users.find(u => u.socketId !== socket.id);
    
    console.log(`[Next] User ${socket.id} is leaving their room.`);
    rooms.delete(user.roomId);
    user.isMatched = false;
    user.roomId = null;
    
    if (partner) {
        partner.isMatched = false;
        partner.roomId = null;
        io.to(partner.socketId).emit('partner-next');
    }
    
    socket.emit('waiting'); 
    broadcastStats();
  });

  // Ban status check handler
  socket.on('check-ban-status', (data, callback) => {
    const clientIP = userIPs.get(socket.id);
    
    if (!clientIP) {
      console.log(`⚠️ Check ban status: No IP found for socket ${socket.id}`);
      if (callback) {
        callback({ isBanned: false });
      }
      return;
    }

    const banStatus = checkBanStatus(clientIP);
    
    if (banStatus && banStatus.isBanned) {
      console.log(`🚫 Ban check: IP ${clientIP} is currently BANNED`);
      
      if (callback) {
        callback({
          isBanned: true,
          message: banStatus.message,
          reason: banStatus.reason,
          banDurationMs: banStatus.remainingMs,
          timestamp: new Date().toISOString()
        });
      }
    } else {
      console.log(`✅ Ban check: IP ${clientIP} is NOT banned`);
      
      if (callback) {
        callback({
          isBanned: false,
          message: 'User is not banned'
        });
      }
    }
  });

  // Confirm unban after payment
  socket.on('confirm-unban', async (data, callback) => {
    const clientIP = userIPs.get(socket.id);
    const { revenueCatTransactionId, receiptToken } = data;

    console.log(`\n💰 Unban request received`);
    console.log(`   Socket ID: ${socket.id}`);
    console.log(`   Client IP: ${clientIP}`);
    console.log(`   Transaction ID: ${revenueCatTransactionId}`);

    if (!clientIP) {
      console.log(`❌ No IP found for socket`);
      if (callback) {
        callback({ success: false, message: 'User IP not found' });
      }
      return;
    }

    if (!revenueCatTransactionId) {
      console.log(`❌ No transaction ID provided`);
      if (callback) {
        callback({ success: false, message: 'Invalid transaction ID' });
      }
      return;
    }

    try {
      // Verify the transaction with RevenueCat
      const isValid = await verifyRevenueCatTransaction(
        revenueCatTransactionId,
        receiptToken || 'verified_by_revenuecat'
      );

      if (!isValid) {
        console.log(`❌ RevenueCat verification failed for transaction: ${revenueCatTransactionId}`);
        if (callback) {
          callback({ success: false, message: 'Payment verification failed' });
        }
        return;
      }

      console.log(`✅ Payment verified! Unbanning IP: ${clientIP}`);

      // Unban the IP
      const success = unbanIP(clientIP);

      if (success) {
        // Store verified unban
        verifiedUnbans.set(revenueCatTransactionId, {
          ip: clientIP,
          timestamp: Date.now(),
          socketId: socket.id
        });

        // Notify the user
        socket.emit('unban-success', {
          message: 'Ban has been removed! You can now join the chat.',
          success: true
        });

        console.log(`🎉 User ${socket.id} from IP ${clientIP} has been unbanned after payment\n`);

        if (callback) {
          callback({ success: true, message: 'Ban removed successfully' });
        }
      } else {
        console.log(`⚠️ Unban failed for IP: ${clientIP}`);
        if (callback) {
          callback({ success: false, message: 'Failed to remove ban' });
        }
      }

      broadcastStats();
    } catch (error) {
      console.error(`❌ Error during unban process: ${error}`);
      if (callback) {
        callback({ success: false, message: 'Server error during unban process' });
      }
    }
  });

  socket.on('report-user', (data) => {
    const { reportedUserIp, reason } = data;
    
    if (!reportedUserIp || !reason) {
      socket.emit('report-response', { 
        success: false, 
        message: 'Missing required fields' 
      });
      return;
    }

    console.log(`📢 Report received from ${socket.id} against IP: ${reportedUserIp}`);
    const result = reportUser(reportedUserIp, socket.id, reason);
    socket.emit('report-response', result);
  });

  socket.on('get-user-count', () => {
    const currentUserCount = io.sockets.sockets.size;
    socket.emit('update-user-count', currentUserCount);
  });

  // WebRTC signaling
  socket.on('offer', (data) => {
    const user = users.get(socket.id);
    if (user && user.roomId) {
      socket.to(user.roomId).emit('offer', { offer: data.offer, from: socket.id });
    }
  });

  socket.on('answer', (data) => {
    const user = users.get(socket.id);
    if (user && user.roomId) {
      socket.to(user.roomId).emit('answer', { answer: data.answer, from: socket.id });
    }
  });

  socket.on('ice-candidate', (data) => {
    const user = users.get(socket.id);
    if (user && user.roomId) {
      socket.to(user.roomId).emit('ice-candidate', { candidate: data.candidate, from: socket.id });
    }
  });

  socket.on('message', (data) => {
    const user = users.get(socket.id);
    if (user && user.roomId) {
      socket.to(user.roomId).emit('message', {
        message: data.message,
        from: socket.id,
        timestamp: new Date()
      });
    }
  });



  socket.on('disconnect', () => {
    console.log(`👋 User disconnected: ${socket.id}`);
    
    const user = users.get(socket.id);
    if (user) {
      user.isOnline = false;
      
      if (user.isMatched && user.roomId) {
        const room = rooms.get(user.roomId);
        if (room) {
          const partner = room.users.find(u => u.socketId !== socket.id);
          if (partner) {
            io.to(partner.socketId).emit('partner-disconnected');
            partner.isMatched = false;
            partner.roomId = null;
            
            const newMatch = findMatch(partner);
            if (newMatch) {
              const newRoom = createRoom(partner, newMatch);
              const partnerSocket = io.sockets.sockets.get(partner.socketId);
              const matchSocket = io.sockets.sockets.get(newMatch.socketId);
              
              partnerSocket?.join(newRoom.id);
              matchSocket?.join(newRoom.id);
              
              io.to(partner.socketId).emit('matched', {
                roomId: newRoom.id,
                isOfferer: true,
                partner: { 
                  socketId: newMatch.socketId, 
                  userInfo: newMatch.userInfo,
                  ip: newMatch.ip
                }
              });
              
              io.to(newMatch.socketId).emit('matched', {
                roomId: newRoom.id,
                isOfferer: false,
                partner: { 
                  socketId: partner.socketId, 
                  userInfo: partner.userInfo,
                  ip: partner.ip
                }
              });
            } else {
              io.to(partner.socketId).emit('waiting', { message: 'Looking for a match...' });
            }
          }
          rooms.delete(user.roomId);
        }
      }
      
      users.delete(socket.id);
    }
    
    userIPs.delete(socket.id);
    
    const currentUserCount = io.sockets.sockets.size;
    io.emit('update-user-count', currentUserCount);
    
    broadcastStats();
  });
});

// REST API Endpoints

app.get('/api/stats', (req, res) => {
  const onlineUsers = Array.from(users.values()).filter(u => u.isOnline);
  const matchedUsers = onlineUsers.filter(u => u.isMatched);
  const totalReports = Array.from(userReports.values()).reduce((sum, reports) => sum + reports.length, 0);
  
  res.json({
    totalUsers: users.size,
    onlineUsers: onlineUsers.length,
    matchedUsers: matchedUsers.length,
    waitingUsers: onlineUsers.length - matchedUsers.length,
    activeRooms: rooms.size,
    bannedIPs: bannedIPs.size,
    totalReports,
    reportedIPs: userReports.size
  });
});

app.get('/api/admin/reports', (req, res) => {
  const { adminKey: providedKey } = req.query;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }

  const reportsArray = [];
  for (const [ip, reports] of userReports.entries()) {
    reportsArray.push({
      ip,
      reportCount: reports.length,
      reports: reports.map(r => ({
        id: r.id,
        reporterSocketId: r.reporterSocketId,
        reason: r.reason,
        timestamp: r.timestamp
      })),
      isBanned: bannedIPs.has(ip)
    });
  }

  res.json({ reports: reportsArray });
});

app.post('/api/admin/ban', (req, res) => {
  const { ip, reason, adminKey: providedKey, durationHours = 24 } = req.body;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  banIP(ip, reason || 'No reason provided', durationHours);
  res.json({ success: true, message: `Banned IP: ${ip} for ${durationHours} hours` });
});

app.post('/api/admin/unban', (req, res) => {
  const { ip, adminKey: providedKey } = req.body;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  const success = unbanIP(ip);
  res.json({ 
    success, 
    message: success ? `Unbanned IP: ${ip}` : `IP ${ip} was not banned` 
  });
});

app.get('/api/admin/users', (req, res) => {
  const { adminKey: providedKey } = req.query;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  const userList = Array.from(users.values()).map(user => ({
    socketId: user.socketId,
    ip: user.ip,
    countries: user.countries,
    userInfo: user.userInfo,
    isOnline: user.isOnline,
    isMatched: user.isMatched,
    connectedAt: user.connectedAt,
    reportCount: userReports.has(user.ip) ? userReports.get(user.ip).length : 0
  }));
  
  res.json({ users: userList });
});

app.get('/api/admin/banned-ips', (req, res) => {
  const { adminKey: providedKey } = req.query;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  const bannedList = Array.from(bannedIPs.entries()).map(([ip, info]) => ({
    ip,
    reason: info.reason,
    bannedAt: new Date(info.timestamp).toISOString(),
    remainingMs: info.duration ? Math.max(0, info.duration - (Date.now() - info.timestamp)) : null
  }));
  
  res.json({ bannedIPs: bannedList });
});

app.post('/api/admin/clear-reports', (req, res) => {
  const { ip, adminKey: providedKey } = req.body;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  const hadReports = userReports.has(ip);
  if (hadReports) {
    userReports.delete(ip);
  }
  
  broadcastStats();
  
  res.json({ 
    success: true, 
    message: hadReports ? `Cleared reports for IP: ${ip}` : `No reports found for IP: ${ip}` 
  });
});

// REST endpoint for confirming unban (alternative to Socket.IO)
app.post('/api/confirm-unban', async (req, res) => {
  const { ip, revenueCatTransactionId, receiptToken, adminKey: providedKey } = req.body;

  if (!ip || !revenueCatTransactionId) {
    return res.status(400).json({ 
      error: 'Missing required fields: ip, revenueCatTransactionId' 
    });
  }

  try {
    // Verify the transaction with RevenueCat
    const isValid = await verifyRevenueCatTransaction(revenueCatTransactionId, receiptToken);

    if (!isValid) {
      return res.status(403).json({ 
        error: 'Payment verification failed' 
      });
    }

    // Unban the IP
    const success = unbanIP(ip);

    if (success) {
      console.log(`🎉 IP ${ip} unbanned via REST API after payment verification`);
      
      // Notify all connected users from this IP about the unban
      for (const [socketId, userIP] of userIPs.entries()) {
        if (userIP === ip) {
          const socket = io.sockets.sockets.get(socketId);
          if (socket) {
            socket.emit('unban-success', {
              message: 'Ban has been removed!',
              success: true
            });
          }
        }
      }

      res.json({ 
        success: true, 
        message: `IP ${ip} has been unbanned` 
      });
    } else {
      res.status(400).json({ 
        error: 'Failed to unban IP' 
      });
    }
  } catch (error) {
    console.error('Error confirming unban:', error);
    res.status(500).json({ 
      error: 'Server error during unban process',
      details: error.message 
    });
  }
});

app.post('/api/super-admin/change-key', (req, res) => {
  const { newKey, token } = req.body;
  
  if (token !== superAdminToken) {
    return res.status(403).json({ error: 'Invalid super admin token' });
  }
  
  if (!newKey || newKey.length < 6) {
    return res.status(400).json({ error: 'Admin key must be at least 6 characters' });
  }
  
  const oldKey = adminKey;
  adminKey = newKey;
  
  console.log(`Admin key changed from "${oldKey}" to "${newKey}"`);
  
  res.json({ 
    success: true, 
    message: 'Admin key changed successfully!',
    newKey: newKey
  });
});

app.get('/api/super-admin/current-key', (req, res) => {
  const { token } = req.query;
  
  if (token !== superAdminToken) {
    return res.status(403).json({ error: 'Invalid super admin token' });
  }
  
  res.json({ currentKey: adminKey });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get(`/super-admin/${superAdminToken}`, (req, res) => {
  res.sendFile(path.join(__dirname, 'super-admin.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Video Chat Server running on port ${PORT}`);
  console.log(`📊 Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`🔐 Super Admin Panel: http://localhost:${PORT}/super-admin/${superAdminToken}`);
  console.log(`🔑 Current Admin Key: ${adminKey}`);
  console.log(`💰 RevenueCat API configured: ${rcApiKey ? '✅' : '❌'}`);
});

module.exports = { app, server, io };