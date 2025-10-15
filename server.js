const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

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

// Simple data storage
const users = new Map(); // socketId -> user data
const rooms = new Map(); // roomId -> room data
const bannedIPs = new Set();
const userIPs = new Map(); // socketId -> IP

// Admin system
let adminKey = 'admin123'; // Default admin key
const superAdminToken = 'super-admin-' + uuidv4(); // Secret token for super admin

console.log(`🔐 Super Admin Panel: http://localhost:${process.env.PORT || 3000}/super-admin/${superAdminToken}`);

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

// Ban/unban functions
function banIP(ip, reason = 'No reason') {
  bannedIPs.add(ip);
  console.log(`Banned IP: ${ip} - ${reason}`);
  
  // Disconnect banned users
  for (const [socketId, userIP] of userIPs.entries()) {
    if (userIP === ip) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit('banned', { message: 'You have been banned', reason });
        socket.disconnect(true);
      }
    }
  }
  return true;
}

function unbanIP(ip) {
  const removed = bannedIPs.delete(ip);
  if (removed) {
    console.log(`Unbanned IP: ${ip}`);
  }
  return removed;
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
  
  console.log(`User connected: ${socket.id} from ${clientIP}`);
  
  // Check if IP is banned
  if (bannedIPs.has(clientIP)) {
    socket.emit('banned', { message: 'You are banned from this service' });
    socket.disconnect(true);
    return;
  }

  // Send current user count immediately when user connects
  const currentUserCount = io.sockets.sockets.size;
  socket.emit('update-user-count', currentUserCount);
  
  // Broadcast updated count to all users
  io.emit('update-user-count', currentUserCount);

  socket.on('join', (data) => {
    const { countries, userInfo } = data;
    
    if (!countries || countries.length === 0) {
      socket.emit('error', { message: 'Please select at least one country' });
      return;
    }

    const user = new User(socket.id, countries, userInfo, clientIP);
    users.set(socket.id, user);

    // Try to find a match
    const match = findMatch(user);
    
    if (match) {
      const room = createRoom(user, match);
      
      // Join room
      socket.join(room.id);
      io.sockets.sockets.get(match.socketId)?.join(room.id);
      
      // Notify users
      socket.emit('matched', {
        roomId: room.id,
        isOfferer: true,
        partner: { socketId: match.socketId, userInfo: match.userInfo }
      });
      
      io.to(match.socketId).emit('matched', {
        roomId: room.id,
        isOfferer: false,
        partner: { socketId: user.socketId, userInfo: user.userInfo }
      });
      
      console.log(`Match: ${user.socketId} <-> ${match.socketId}`);
    } else {
      socket.emit('waiting', { message: 'Looking for a match...' });
    }
  });

  // Add handler for manual user count request
  socket.on('get-user-count', () => {
    const currentUserCount = io.sockets.sockets.size;
    socket.emit('update-user-count', currentUserCount);
    console.log(`Sent user count to ${socket.id}: ${currentUserCount}`);
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

  socket.on('next', () => {
    const user = users.get(socket.id);
    if (!user || !user.isMatched) return;

    const room = rooms.get(user.roomId);
    if (!room) return;

    const partner = room.users.find(u => u.socketId !== socket.id);
    
    // Clean up room
    rooms.delete(user.roomId);
    user.isMatched = false;
    user.roomId = null;
    
    if (partner) {
      io.to(partner.socketId).emit('partner-next');
      partner.isMatched = false;
      partner.roomId = null;
      
      // Try to rematch partner
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
          partner: { socketId: newMatch.socketId, userInfo: newMatch.userInfo }
        });
        
        io.to(newMatch.socketId).emit('matched', {
          roomId: newRoom.id,
          isOfferer: false,
          partner: { socketId: partner.socketId, userInfo: partner.userInfo }
        });
      } else {
        io.to(partner.socketId).emit('waiting', { message: 'Looking for a match...' });
      }
    }
    
    // Try to rematch current user
    const newMatch = findMatch(user);
    if (newMatch) {
      const newRoom = createRoom(user, newMatch);
      socket.join(newRoom.id);
      io.sockets.sockets.get(newMatch.socketId)?.join(newRoom.id);
      
      socket.emit('matched', {
        roomId: newRoom.id,
        isOfferer: true,
        partner: { socketId: newMatch.socketId, userInfo: newMatch.userInfo }
      });
      
      io.to(newMatch.socketId).emit('matched', {
        roomId: newRoom.id,
        isOfferer: false,
        partner: { socketId: user.socketId, userInfo: user.userInfo }
      });
    } else {
      socket.emit('waiting', { message: 'Looking for a match...' });
    }
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    
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
            
            // Try to find new match for partner
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
                partner: { socketId: newMatch.socketId, userInfo: newMatch.userInfo }
              });
              
              io.to(newMatch.socketId).emit('matched', {
                roomId: newRoom.id,
                isOfferer: false,
                partner: { socketId: partner.socketId, userInfo: partner.userInfo }
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
    
    // Broadcast updated user count after disconnect
    const currentUserCount = io.sockets.sockets.size;
    io.emit('update-user-count', currentUserCount);
  });
});

// Serve admin panels
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get(`/super-admin/${superAdminToken}`, (req, res) => {
  res.sendFile(path.join(__dirname, 'super-admin.html'));
});

// API endpoints
app.get('/api/stats', (req, res) => {
  const onlineUsers = Array.from(users.values()).filter(u => u.isOnline);
  const matchedUsers = onlineUsers.filter(u => u.isMatched);
  
  res.json({
    totalUsers: users.size,
    onlineUsers: onlineUsers.length,
    matchedUsers: matchedUsers.length,
    waitingUsers: onlineUsers.length - matchedUsers.length,
    activeRooms: rooms.size,
    bannedIPs: bannedIPs.size
  });
});

// Admin API (for normal admins)
app.post('/api/admin/ban', (req, res) => {
  const { ip, reason, adminKey: providedKey } = req.body;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  if (!ip) {
    return res.status(400).json({ error: 'IP address required' });
  }
  
  banIP(ip, reason);
  res.json({ success: true, message: `Banned IP: ${ip}` });
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
    connectedAt: user.connectedAt
  }));
  
  res.json({ users: userList });
});

app.get('/api/admin/banned-ips', (req, res) => {
  const { adminKey: providedKey } = req.query;
  
  if (providedKey !== adminKey) {
    return res.status(401).json({ error: 'Invalid admin key' });
  }
  
  res.json({ bannedIPs: Array.from(bannedIPs) });
});

// Super Admin API (for you only)
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

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Video Chat Server running on port ${PORT}`);
  console.log(`📊 Public Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`🔐 Super Admin Panel: http://localhost:${PORT}/super-admin/${superAdminToken}`);
  console.log(`🔑 Current Admin Key: ${adminKey}`);
});

module.exports = { app, server, io };