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
const activeUsers = new Map(); // socketId -> user data
const waitingQueue = new Map(); // country -> array of user objects
const activeRooms = new Map(); // roomId -> room data
const userRooms = new Map(); // socketId -> roomId

// User class to represent connected users
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

// Room class to represent video chat rooms
class Room {
  constructor(user1, user2) {
    this.id = uuidv4();
    this.users = [user1, user2];
    this.createdAt = new Date();
    this.isActive = true;
  }
}

// Helper function to find matching users
function findMatch(user) {
  for (const country of user.countries) {
    const queue = waitingQueue.get(country) || [];
    
    // Find a user in the queue who isn't the same user
    const matchIndex = queue.findIndex(waitingUser => 
      waitingUser.socketId !== user.socketId && !waitingUser.isMatched
    );
    
    if (matchIndex !== -1) {
      const match = queue[matchIndex];
      // Remove matched user from queue
      queue.splice(matchIndex, 1);
      
      // Clean up empty queues
      if (queue.length === 0) {
        waitingQueue.delete(country);
      }
      
      return match;
    }
  }
  return null;
}

// Helper function to add user to waiting queue
function addToWaitingQueue(user) {
  user.countries.forEach(country => {
    if (!waitingQueue.has(country)) {
      waitingQueue.set(country, []);
    }
    waitingQueue.get(country).push(user);
  });
}

// Helper function to remove user from waiting queue
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

// Helper function to broadcast the current online user count
function broadcastUserCount() {
  const userCount = io.sockets.sockets.size;
  console.log(`Broadcasting user count: ${userCount}`);
  io.emit('update-user-count', userCount); // Emits to all connected clients
}

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);
  broadcastUserCount(); // Broadcast count on new connection

  // Handle user joining with country preferences
  socket.on('join', (data) => {
    const { countries, userInfo } = data;
    
    if (!countries || countries.length === 0) {
      socket.emit('error', { message: 'Please select at least one country' });
      return;
    }

    // Create new user
    const user = new User(socket.id, countries, userInfo);
    activeUsers.set(socket.id, user);

    // Try to find a match
    const match = findMatch(user);
    
    if (match) {
      // Create room for matched users
      const room = new Room(user, match);
      
      // Update user states
      user.isMatched = true;
      user.roomId = room.id;
      match.isMatched = true;
      match.roomId = room.id;
      
      // Store room and user-room mapping
      activeRooms.set(room.id, room);
      userRooms.set(user.socketId, room.id);
      userRooms.set(match.socketId, room.id);
      
      // Join socket rooms
      socket.join(room.id);
      io.sockets.sockets.get(match.socketId)?.join(room.id);
      
      // Notify both users about the match
      io.to(room.id).emit('matched', {
        roomId: room.id,
        partner: {
          socketId: match.socketId === socket.id ? user.socketId : match.socketId,
          userInfo: match.socketId === socket.id ? user.userInfo : match.userInfo
        }
      });
      
      console.log(`Match found: ${user.socketId} <-> ${match.socketId} in room ${room.id}`);
    } else {
      // Add to waiting queue
      addToWaitingQueue(user);
      socket.emit('waiting', { message: 'Looking for a match...' });
      console.log(`User ${socket.id} added to waiting queue for countries: ${countries.join(', ')}`);
    }
  });

  // Handle WebRTC signaling
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

  // Handle chat messages
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

  // Handle user wanting to skip/next partner
  socket.on('next', () => {
    handleUserLeave(socket.id, true);
  });

  // Handle user disconnect
  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    handleUserLeave(socket.id, false);
    broadcastUserCount(); // Broadcast count on disconnect
  });

  // Helper function to handle user leaving
  function handleUserLeave(socketId, isNext = false) {
    const user = activeUsers.get(socketId);
    if (!user) return;

    if (user.isMatched && user.roomId) {
      // User was in a room
      const room = activeRooms.get(user.roomId);
      if (room) {
        const partner = room.users.find(u => u.socketId !== socketId);
        if (partner) {
          // Notify partner about disconnect
          io.to(partner.socketId).emit(isNext ? 'partner-next' : 'partner-disconnected');
          
          // Reset partner state and try to find new match
          partner.isMatched = false;
          partner.roomId = null;
          userRooms.delete(partner.socketId);
          
          if (isNext) {
            // If partner is still connected, try to find them a new match
            const newMatch = findMatch(partner);
            if (newMatch) {
              const newRoom = new Room(partner, newMatch);
              
              partner.isMatched = true;
              partner.roomId = newRoom.id;
              newMatch.isMatched = true;
              newMatch.roomId = newRoom.id;
              
              activeRooms.set(newRoom.id, newRoom);
              userRooms.set(partner.socketId, newRoom.id);
              userRooms.set(newMatch.socketId, newRoom.id);
              
              io.sockets.sockets.get(partner.socketId)?.join(newRoom.id);
              io.sockets.sockets.get(newMatch.socketId)?.join(newRoom.id);
              
              io.to(newRoom.id).emit('matched', {
                roomId: newRoom.id,
                partner: {
                  socketId: newMatch.socketId === partner.socketId ? partner.socketId : newMatch.socketId,
                  userInfo: newMatch.socketId === partner.socketId ? partner.userInfo : newMatch.userInfo
                }
              });
            } else {
              addToWaitingQueue(partner);
              io.to(partner.socketId).emit('waiting', { message: 'Looking for a new match...' });
            }
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

    // Clean up user data
    activeUsers.delete(socketId);
  }
});

// REST API endpoints for statistics and monitoring
app.get('/api/stats', (req, res) => {
  const totalUsers = activeUsers.size;
  const waitingUsers = Array.from(waitingQueue.values()).reduce((sum, queue) => sum + queue.length, 0);
  const matchedUsers = totalUsers - waitingUsers;
  const activeRoomsCount = activeRooms.size;

  res.json({
    totalOnlineUsers: io.sockets.sockets.size, // Also adding the real-time count here
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

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Video chat server running on port ${PORT}`);
  console.log(`WebSocket endpoint: ws://localhost:${PORT}`);
  console.log(`REST API available at: http://localhost:${PORT}/api`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

module.exports = { app, server, io };