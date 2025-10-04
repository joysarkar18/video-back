const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
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

// Data structures to manage users and rooms
const activeUsers = new Map();
const waitingQueue = new Map();
const activeRooms = new Map();
const userRooms = new Map();

class User {
  constructor(socketId, countries, userInfo = {}) {
    this.socketId = socketId;
    this.countries = Array.isArray(countries) ? countries : [countries];
    this.userInfo = userInfo;
    this.isMatched = false;
    this.roomId = null;
    this.connectedAt = new Date();
  }
}

class Room {
  constructor(user1, user2) {
    this.id = uuidv4();
    this.users = [user1, user2];
    this.createdAt = new Date();
    this.isActive = true;
  }
}

function findMatch(user) {
  for (const country of user.countries) {
    const queue = waitingQueue.get(country) || [];
    
    const matchIndex = queue.findIndex(waitingUser => 
      waitingUser.socketId !== user.socketId && !waitingUser.isMatched
    );
    
    if (matchIndex !== -1) {
      const match = queue[matchIndex];
      queue.splice(matchIndex, 1);
      
      if (queue.length === 0) {
        waitingQueue.delete(country);
      }
      
      return match;
    }
  }
  return null;
}

function addToWaitingQueue(user) {
  user.countries.forEach(country => {
    if (!waitingQueue.has(country)) {
      waitingQueue.set(country, []);
    }
    waitingQueue.get(country).push(user);
  });
}

function removeFromWaitingQueue(user) {
  user.countries.forEach(country => {
    const queue = waitingQueue.get(country);
    if (queue) {
      const index = queue.findIndex(u => u.socketId === user.socketId);
      if (index !== -1) {
        queue.splice(index, 1);
      }
      if (queue.length === 0) {
        waitingQueue.delete(country);
      }
    }
  });
}

function broadcastUserCount() {
  const userCount = io.sockets.sockets.size;
  console.log(`Broadcasting user count: ${userCount}`);
  io.emit('update-user-count', userCount);
}

// CRITICAL FIX: New function to try matching a user
function tryMatchUser(user, socket) {
  const match = findMatch(user);
  
  if (match) {
    const room = new Room(user, match);
    
    user.isMatched = true;
    user.roomId = room.id;
    match.isMatched = true;
    match.roomId = room.id;
    
    activeRooms.set(room.id, room);
    userRooms.set(user.socketId, room.id);
    userRooms.set(match.socketId, room.id);
    
    socket.join(room.id);
    io.sockets.sockets.get(match.socketId)?.join(room.id);
    
    // User who just joined is the offerer
    socket.emit('matched', {
      roomId: room.id,
      isOfferer: true,
      partner: {
        socketId: match.socketId,
        userInfo: match.userInfo
      }
    });
    
    // Waiting user is the answerer
    io.to(match.socketId).emit('matched', {
      roomId: room.id,
      isOfferer: false,
      partner: {
        socketId: user.socketId,
        userInfo: user.userInfo
      }
    });
    
    console.log(`Match found: ${user.socketId} (offerer) <-> ${match.socketId} (answerer) in room ${room.id}`);
    return true;
  } else {
    addToWaitingQueue(user);
    socket.emit('waiting', { message: 'Looking for a match...' });
    console.log(`User ${user.socketId} added to waiting queue for countries: ${user.countries.join(', ')}`);
    return false;
  }
}

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);
  broadcastUserCount();

  socket.on('join', (data) => {
    const { countries, userInfo } = data;
    
    if (!countries || countries.length === 0) {
      socket.emit('error', { message: 'Please select at least one country' });
      return;
    }

    const user = new User(socket.id, countries, userInfo);
    activeUsers.set(socket.id, user);

    tryMatchUser(user, socket);
  });

  socket.on('offer', (data) => {
    const roomId = userRooms.get(socket.id);
    if (roomId) {
      socket.to(roomId).emit('offer', {
        offer: data.offer,
        from: socket.id
      });
    }
  });

  socket.on('answer', (data) => {
    const roomId = userRooms.get(socket.id);
    if (roomId) {
      socket.to(roomId).emit('answer', {
        answer: data.answer,
        from: socket.id
      });
    }
  });

  socket.on('ice-candidate', (data) => {
    const roomId = userRooms.get(socket.id);
    if (roomId) {
      socket.to(roomId).emit('ice-candidate', {
        candidate: data.candidate,
        from: socket.id
      });
    }
  });

  socket.on('message', (data) => {
    const roomId = userRooms.get(socket.id);
    if (roomId) {
      socket.to(roomId).emit('message', {
        message: data.message,
        from: socket.id,
        timestamp: new Date()
      });
    }
  });

  // CRITICAL FIX: Handle "next" properly
  socket.on('next', () => {
    console.log(`User ${socket.id} pressed next`);
    handleUserNext(socket.id);
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    handleUserDisconnect(socket.id);
    broadcastUserCount();
  });

  // CRITICAL FIX: Separate function for "next" action
  function handleUserNext(socketId) {
    const user = activeUsers.get(socketId);
    if (!user) return;

    if (user.isMatched && user.roomId) {
      const room = activeRooms.get(user.roomId);
      if (room) {
        const partner = room.users.find(u => u.socketId !== socketId);
        
        if (partner) {
          // Notify partner
          io.to(partner.socketId).emit('partner-next');
          
          // Reset partner state
          partner.isMatched = false;
          partner.roomId = null;
          userRooms.delete(partner.socketId);
          
          // Try to match partner with someone else
          const partnerSocket = io.sockets.sockets.get(partner.socketId);
          if (partnerSocket) {
            tryMatchUser(partner, partnerSocket);
          }
        }
        
        // Clean up room
        activeRooms.delete(user.roomId);
      }
      
      // CRITICAL: Reset current user and try to find them a new match
      user.isMatched = false;
      user.roomId = null;
      userRooms.delete(socketId);
      
      // Try to match current user with someone else
      tryMatchUser(user, socket);
    }
  }

  // Separate function for actual disconnect
  function handleUserDisconnect(socketId) {
    const user = activeUsers.get(socketId);
    if (!user) return;

    if (user.isMatched && user.roomId) {
      const room = activeRooms.get(user.roomId);
      if (room) {
        const partner = room.users.find(u => u.socketId !== socketId);
        
        if (partner) {
          // Notify partner about disconnect
          io.to(partner.socketId).emit('partner-disconnected');
          
          // Reset partner state
          partner.isMatched = false;
          partner.roomId = null;
          userRooms.delete(partner.socketId);
          
          // Try to match partner with someone else
          const partnerSocket = io.sockets.sockets.get(partner.socketId);
          if (partnerSocket) {
            tryMatchUser(partner, partnerSocket);
          }
        }
        
        // Clean up room
        activeRooms.delete(user.roomId);
      }
      userRooms.delete(socketId);
    } else {
      // User was in waiting queue
      removeFromWaitingQueue(user);
    }

    // Clean up user data completely on disconnect
    activeUsers.delete(socketId);
  }
});

// REST API endpoints
app.get('/api/stats', (req, res) => {
  const totalUsers = activeUsers.size;
  const waitingUsers = Array.from(waitingQueue.values()).reduce((sum, queue) => sum + queue.length, 0);
  const matchedUsers = totalUsers - waitingUsers;
  const activeRoomsCount = activeRooms.size;

  res.json({
    totalOnlineUsers: io.sockets.sockets.size,
    totalUsersInLogic: totalUsers,
    waitingUsers,
    matchedUsers,
    activeRooms: activeRoomsCount,
    queueByCountry: Object.fromEntries(
      Array.from(waitingQueue.entries()).map(([country, users]) => [country, users.length])
    )
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Video chat server running on port ${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}`);
  console.log(`REST API available at: http://localhost:${PORT}/api`);
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

module.exports = { app, server, io };