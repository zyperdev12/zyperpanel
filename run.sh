#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                    ZyperPanel Installer                        ║
║              Game Server Management Panel v1.0                 ║
╚═══════════════════════════════════════════════════════════════╝
`);

const BASE_DIR = process.cwd();

// Create directories
const dirs = [
  'docs',
  'prisma/migrations/20250811211549_init',
  'public/assets/world_icons',
  'public/javascript',
  'public/js',
  'public/uploads/favicons',
  'src/handlers/cmd',
  'src/handlers/install',
  'src/handlers/utils/api',
  'src/handlers/utils/auth',
  'src/handlers/utils/core',
  'src/handlers/utils/node',
  'src/handlers/utils/security',
  'src/handlers/utils/server',
  'src/handlers/utils/user',
  'src/modules/admin',
  'src/modules/api/Alternative',
  'src/modules/api/v1',
  'src/modules/auth',
  'src/modules/core',
  'src/modules/test',
  'src/modules/user',
  'src/types',
  'src/utils/core',
  'storage/addons',
  'storage/lang/en',
  'storage/lang/fr',
  'storage/plugins',
  'storage/radar',
  'views/addons/test-addon',
  'views/admin/addons',
  'views/admin/analytics',
  'views/admin/apikeys',
  'views/admin/images',
  'views/admin/nodes',
  'views/admin/overview',
  'views/admin/playerstats',
  'views/admin/servers',
  'views/admin/settings',
  'views/admin/users',
  'views/api',
  'views/auth',
  'views/components',
  'views/user/server'
];

dirs.forEach(dir => {
  const fullPath = path.join(BASE_DIR, dir);
  if (!fs.existsSync(fullPath)) {
    fs.mkdirSync(fullPath, { recursive: true });
    console.log(`Created: ${dir}`);
  }
});

// Package.json
const packageJson = {
  "name": "zyperpanel",
  "version": "1.0.0",
  "description": "ZyperPanel - Game Server Management Panel",
  "main": "src/app.ts",
  "scripts": {
    "dev": "nodemon src/app.ts",
    "start": "ts-node src/app.ts",
    "build": "tsc",
    "db:migrate": "prisma migrate dev",
    "db:push": "prisma db push",
    "seed": "ts-node src/handlers/cmd/seed.ts",
    "adduser": "ts-node src/handlers/cmd/adduser.ts"
  },
  "dependencies": {
    "@prisma/client": "^5.0.0",
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "bcryptjs": "^2.4.3",
    "ejs": "^3.1.9",
    "socket.io": "^4.7.2",
    "dotenv": "^16.3.1",
    "uuid": "^9.0.0",
    "cors": "^2.8.5",
    "body-parser": "^1.20.2",
    "cookie-parser": "^1.4.6"
  },
  "devDependencies": {
    "@types/express": "^4.17.17",
    "@types/node": "^20.4.5",
    "@types/bcryptjs": "^2.4.2",
    "nodemon": "^3.0.1",
    "prisma": "^5.0.0",
    "typescript": "^5.1.6",
    "ts-node": "^10.9.1"
  }
};

fs.writeFileSync(
  path.join(BASE_DIR, 'package.json'),
  JSON.stringify(packageJson, null, 2)
);
console.log('Created: package.json');

// tsconfig.json
const tsconfig = {
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
};

fs.writeFileSync(
  path.join(BASE_DIR, 'tsconfig.json'),
  JSON.stringify(tsconfig, null, 2)
);
console.log('Created: tsconfig.json');

// .env file
const envContent = `
DATABASE_URL="file:./dev.db"
SESSION_SECRET="${require('crypto').randomBytes(32).toString('hex')}"
PANEL_PORT=3000
PANEL_NAME=ZyperPanel
PANEL_ICON=/favicon.ico
NODE_ENV=development
`;

fs.writeFileSync(path.join(BASE_DIR, '.env'), envContent.trim());
fs.writeFileSync(path.join(BASE_DIR, 'example.env'), envContent.trim());
console.log('Created: .env');

// Prisma Schema
const prismaSchema = `
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}

model User {
  id        String   @id @default(uuid())
  username  String   @unique
  email     String   @unique
  password  String
  isAdmin   Boolean  @default(false)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  servers   Server[]
}

model Node {
  id        String   @id @default(uuid())
  name      String
  cpu       Int
  ram       Int
  location  String
  key       String   @unique @default(uuid())
  status    String   @default("offline")
  createdAt DateTime @default(now())
  servers   Server[]
}

model Server {
  id          String   @id @default(uuid())
  name        String
  type        String   @default("minecraft")
  version     String   @default("1.20.1")
  port        Int
  memory      Int
  cpu         Int
  status      String   @default("stopped")
  nodeId      String
  node        Node     @relation(fields: [nodeId], references: [id], onDelete: Cascade)
  userId      String
  user        User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  createdAt   DateTime @default(now())
  players     Player[]
  plugins     Plugin[]
  files       ServerFile[]
  backups     Backup[]
}

model Player {
  id        String   @id @default(uuid())
  uuid      String
  username  String
  serverId  String
  server    Server   @relation(fields: [serverId], references: [id], onDelete: Cascade)
  lastSeen  DateTime @default(now())
  banned    Boolean  @default(false)
  op        Boolean  @default(false)
}

model Plugin {
  id        String   @id @default(uuid())
  name      String
  version   String
  enabled   Boolean  @default(true)
  serverId  String
  server    Server   @relation(fields: [serverId], references: [id], onDelete: Cascade)
}

model ServerFile {
  id        String   @id @default(uuid())
  name      String
  path      String
  size      Int
  isDir     Boolean  @default(false)
  serverId  String
  server    Server   @relation(fields: [serverId], references: [id], onDelete: Cascade)
  updatedAt DateTime @updatedAt
}

model Backup {
  id        String   @id @default(uuid())
  name      String
  size      Int
  serverId  String
  server    Server   @relation(fields: [serverId], references: [id], onDelete: Cascade)
  createdAt DateTime @default(now())
}

model Settings {
  id        String   @id @default(uuid())
  panelName String   @default("ZyperPanel")
  panelPort Int      @default(3000)
  panelIcon String   @default("/favicon.ico")
}

model ConsoleLog {
  id        String   @id @default(uuid())
  serverId  String
  message   String
  type      String   @default("info")
  createdAt DateTime @default(now())
}
`;

fs.writeFileSync(path.join(BASE_DIR, 'prisma/schema.prisma'), prismaSchema.trim());
console.log('Created: prisma/schema.prisma');

// Main App.ts
const appTs = `
import express from 'express';
import session from 'express-session';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { createServer } from 'http';
import { Server as SocketServer } from 'socket.io';
import path from 'path';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const httpServer = createServer(app);
const io = new SocketServer(httpServer, { cors: { origin: '*' } });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'zyperpanel-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));
app.use(express.static(path.join(__dirname, '../public')));

// Auth middleware
const requireAuth = (req: any, res: any, next: any) => {
  if (!req.session?.userId) {
    return res.redirect('/auth/login');
  }
  next();
};

const requireAdmin = async (req: any, res: any, next: any) => {
  if (!req.session?.userId) {
    return res.redirect('/auth/login');
  }
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  if (!user?.isAdmin) {
    return res.status(403).send('Admin access required');
  }
  req.user = user;
  next();
};

// Get settings helper
const getSettings = async () => {
  let settings = await prisma.settings.findFirst();
  if (!settings) {
    settings = await prisma.settings.create({
      data: { panelName: 'ZyperPanel', panelPort: 3000, panelIcon: '/favicon.ico' }
    });
  }
  return settings;
};

// ============== PUBLIC ROUTES ==============

// Landing Page
app.get('/', async (req, res) => {
  const settings = await getSettings();
  res.render('index', { settings });
});

// ============== AUTH ROUTES ==============

app.get('/auth/login', async (req, res) => {
  const settings = await getSettings();
  res.render('auth/login', { settings, error: null });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const settings = await getSettings();
  const bcrypt = require('bcryptjs');
  
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render('auth/login', { settings, error: 'Invalid credentials' });
  }
  
  (req.session as any).userId = user.id;
  res.redirect(user.isAdmin ? '/admin/overview' : '/dashboard');
});

app.get('/auth/register', async (req, res) => {
  const settings = await getSettings();
  res.render('auth/register', { settings, error: null });
});

app.post('/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const settings = await getSettings();
  const bcrypt = require('bcryptjs');
  
  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const userCount = await prisma.user.count();
    
    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        isAdmin: userCount === 0 // First user is admin
      }
    });
    
    (req.session as any).userId = user.id;
    res.redirect(user.isAdmin ? '/admin/overview' : '/dashboard');
  } catch (error) {
    res.render('auth/register', { settings, error: 'User already exists' });
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// ============== USER DASHBOARD ==============

app.get('/dashboard', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const servers = await prisma.server.findMany({
    where: { userId: req.session.userId },
    include: { node: true, players: true }
  });
  res.render('user/dashboard', { settings, user, servers });
});

// ============== SERVER MANAGEMENT ==============

app.get('/server/:id', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({
    where: { id: req.params.id },
    include: { node: true, players: true, plugins: true }
  });
  if (!server || server.userId !== req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('user/server/manage', { settings, user, server });
});

// Server Console
app.get('/server/:id/console', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({
    where: { id: req.params.id },
    include: { node: true }
  });
  const logs = await prisma.consoleLog.findMany({
    where: { serverId: req.params.id },
    orderBy: { createdAt: 'desc' },
    take: 100
  });
  res.render('user/server/console', { settings, user, server, logs: logs.reverse() });
});

// Server Files
app.get('/server/:id/files', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({ where: { id: req.params.id } });
  const files = await prisma.serverFile.findMany({ where: { serverId: req.params.id } });
  res.render('user/server/files', { settings, user, server, files, currentPath: '/' });
});

// Server Players
app.get('/server/:id/players', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({ where: { id: req.params.id } });
  const players = await prisma.player.findMany({ where: { serverId: req.params.id } });
  res.render('user/server/players', { settings, user, server, players });
});

// Server Plugins
app.get('/server/:id/plugins', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({ where: { id: req.params.id } });
  const plugins = await prisma.plugin.findMany({ where: { serverId: req.params.id } });
  res.render('user/server/plugins', { settings, user, server, plugins });
});

// Server Settings
app.get('/server/:id/settings', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({ where: { id: req.params.id } });
  res.render('user/server/settings', { settings, user, server });
});

// Server Versions
app.get('/server/:id/versions', requireAuth, async (req: any, res) => {
  const settings = await getSettings();
  const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
  const server = await prisma.server.findUnique({ where: { id: req.params.id } });
  const versions = ['1.20.4', '1.20.3', '1.20.2', '1.20.1', '1.19.4', '1.18.2', '1.17.1', '1.16.5'];
  res.render('user/server/versions', { settings, user, server, versions });
});

// ============== ADMIN ROUTES ==============

// Admin Overview
app.get('/admin/overview', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  const users = await prisma.user.count();
  const servers = await prisma.server.count();
  const nodes = await prisma.node.count();
  res.render('admin/overview/overview', { settings, user: req.user, stats: { users, servers, nodes } });
});

// Admin Nodes
app.get('/admin/nodes', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  const nodes = await prisma.node.findMany({ include: { servers: true } });
  res.render('admin/nodes/nodes', { settings, user: req.user, nodes });
});

app.get('/admin/nodes/create', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  res.render('admin/nodes/create', { settings, user: req.user });
});

app.post('/admin/nodes/create', requireAdmin, async (req: any, res) => {
  const { name, cpu, ram, location } = req.body;
  const { v4: uuidv4 } = require('uuid');
  
  await prisma.node.create({
    data: {
      name,
      cpu: parseInt(cpu),
      ram: parseInt(ram),
      location,
      key: uuidv4()
    }
  });
  
  res.redirect('/admin/nodes?success=Node created successfully');
});

app.get('/admin/nodes/:id/edit', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  const node = await prisma.node.findUnique({ where: { id: req.params.id } });
  res.render('admin/nodes/edit', { settings, user: req.user, node });
});

app.post('/admin/nodes/:id/edit', requireAdmin, async (req: any, res) => {
  const { name, cpu, ram, location } = req.body;
  await prisma.node.update({
    where: { id: req.params.id },
    data: { name, cpu: parseInt(cpu), ram: parseInt(ram), location }
  });
  res.redirect('/admin/nodes?success=Node updated');
});

app.post('/admin/nodes/:id/delete', requireAdmin, async (req: any, res) => {
  await prisma.node.delete({ where: { id: req.params.id } });
  res.redirect('/admin/nodes?success=Node deleted');
});

// Admin Users
app.get('/admin/users', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  const users = await prisma.user.findMany({ include: { servers: true } });
  res.render('admin/users/users', { settings, user: req.user, users });
});

app.get('/admin/users/create', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  res.render('admin/users/create', { settings, user: req.user });
});

app.post('/admin/users/create', requireAdmin, async (req: any, res) => {
  const { username, email, password, isAdmin } = req.body;
  const bcrypt = require('bcryptjs');
  
  await prisma.user.create({
    data: {
      username,
      email,
      password: bcrypt.hashSync(password, 10),
      isAdmin: isAdmin === 'yes'
    }
  });
  
  res.redirect('/admin/users?success=User created');
});

app.post('/admin/users/:id/delete', requireAdmin, async (req: any, res) => {
  await prisma.user.delete({ where: { id: req.params.id } });
  res.redirect('/admin/users?success=User deleted');
});

// Admin Servers
app.get('/admin/servers', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  const servers = await prisma.server.findMany({ include: { node: true, user: true } });
  res.render('admin/servers/servers', { settings, user: req.user, servers });
});

app.get('/admin/servers/create', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  const nodes = await prisma.node.findMany();
  const users = await prisma.user.findMany();
  res.render('admin/servers/create', { settings, user: req.user, nodes, users });
});

app.post('/admin/servers/create', requireAdmin, async (req: any, res) => {
  const { name, type, version, port, memory, cpu, nodeId, userId } = req.body;
  
  await prisma.server.create({
    data: {
      name,
      type,
      version,
      port: parseInt(port),
      memory: parseInt(memory),
      cpu: parseInt(cpu),
      nodeId,
      userId
    }
  });
  
  res.redirect('/admin/servers?success=Server created');
});

// Admin Settings
app.get('/admin/settings', requireAdmin, async (req: any, res) => {
  const settings = await getSettings();
  res.render('admin/settings/settings', { settings, user: req.user, success: req.query.success });
});

app.post('/admin/settings', requireAdmin, async (req: any, res) => {
  const { panelName, panelPort, panelIcon } = req.body;
  const settings = await getSettings();
  
  await prisma.settings.update({
    where: { id: settings.id },
    data: {
      panelName,
      panelPort: parseInt(panelPort),
      panelIcon
    }
  });
  
  res.redirect('/admin/settings?success=Settings saved');
});

// ============== API ROUTES ==============

app.get('/api/v1/nodes', async (req, res) => {
  const nodes = await prisma.node.findMany();
  res.json(nodes);
});

app.get('/api/v1/servers', async (req, res) => {
  const servers = await prisma.server.findMany({ include: { node: true } });
  res.json(servers);
});

// ============== WEBSOCKET ==============

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('join-server', (serverId) => {
    socket.join(\`server-\${serverId}\`);
  });
  
  socket.on('console-command', async (data) => {
    const { serverId, command } = data;
    
    // Log command
    await prisma.consoleLog.create({
      data: { serverId, message: \`> \${command}\`, type: 'command' }
    });
    
    // Simulate response
    const response = \`Executed: \${command}\`;
    await prisma.consoleLog.create({
      data: { serverId, message: response, type: 'info' }
    });
    
    io.to(\`server-\${serverId}\`).emit('console-output', { message: response });
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ============== START SERVER ==============

const PORT = process.env.PANEL_PORT || 3000;

httpServer.listen(PORT, async () => {
  console.log(\`
╔═══════════════════════════════════════════════════════════════╗
║                    ZyperPanel Started                          ║
║              Running on http://localhost:\${PORT}                 ║
╚═══════════════════════════════════════════════════════════════╝
  \`);
});

export { app, prisma, io };
`;

fs.writeFileSync(path.join(BASE_DIR, 'src/app.ts'), appTs.trim());
console.log('Created: src/app.ts');

// Add User CLI
const adduserTs = `
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import readline from 'readline';

const prisma = new PrismaClient();

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (prompt: string): Promise<string> => {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
};

async function main() {
  console.log('');
  console.log('==== Zyper User Creation ====');
  console.log('');
  
  const username = await question('Username: ');
  const email = await question('Email: ');
  const password = await question('Password: ');
  const isAdminInput = await question('Admin (yes/no) [no]: ');
  
  const isAdmin = isAdminInput.toLowerCase() === 'yes';
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  try {
    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        isAdmin
      }
    });
    
    console.log('');
    console.log('User created successfully!');
    console.log('ID:', user.id);
    console.log('Username:', user.username);
    console.log('Email:', user.email);
    console.log('Admin:', user.isAdmin ? 'Yes' : 'No');
  } catch (error: any) {
    console.error('Error creating user:', error.message);
  }
  
  rl.close();
  await prisma.$disconnect();
}

main();
`;

fs.writeFileSync(path.join(BASE_DIR, 'src/handlers/cmd/adduser.ts'), adduserTs.trim());
console.log('Created: src/handlers/cmd/adduser.ts');

// ============== VIEW TEMPLATES ==============

// Landing Page
const indexEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= settings.panelName %> - Game Server Panel</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="icon" href="<%= settings.panelIcon %>">
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="fixed w-full bg-gray-900/80 backdrop-blur-lg border-b border-gray-800 z-50">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>
          </svg>
        </div>
        <span class="text-xl font-bold"><%= settings.panelName %></span>
      </div>
      <div class="flex items-center gap-4">
        <a href="/auth/login" class="px-4 py-2 text-gray-300 hover:text-white transition">Login</a>
        <a href="/auth/register" class="px-6 py-2 bg-gradient-to-r from-violet-500 to-purple-600 rounded-lg hover:from-violet-600 hover:to-purple-700 transition">Register</a>
      </div>
    </div>
  </nav>
  
  <main class="pt-32 pb-20 px-6">
    <div class="max-w-4xl mx-auto text-center">
      <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-violet-500/10 border border-violet-500/20 text-violet-400 text-sm mb-8">
        <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        Open Source Game Panel
      </div>
      <h1 class="text-5xl md:text-7xl font-bold mb-6">
        <span class="bg-gradient-to-r from-white via-violet-200 to-purple-200 bg-clip-text text-transparent">Powerful Game Server</span>
        <br>
        <span class="bg-gradient-to-r from-violet-400 to-purple-500 bg-clip-text text-transparent">Management Panel</span>
      </h1>
      <p class="text-xl text-gray-400 max-w-2xl mx-auto mb-10">
        <%= settings.panelName %> is a modern game server management panel. Manage Minecraft and other game servers with ease.
      </p>
      <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="/auth/register" class="px-8 py-3 bg-gradient-to-r from-violet-500 to-purple-600 rounded-lg text-lg font-semibold hover:from-violet-600 hover:to-purple-700 transition">Get Started</a>
        <a href="#features" class="px-8 py-3 border border-violet-500/30 rounded-lg text-lg hover:bg-violet-500/10 transition">View Features</a>
      </div>
    </div>
    
    <section id="features" class="max-w-6xl mx-auto mt-32 grid md:grid-cols-2 lg:grid-cols-4 gap-6">
      <div class="p-6 bg-gray-800/50 rounded-xl border border-gray-700/50">
        <div class="w-12 h-12 rounded-xl bg-violet-500/20 flex items-center justify-center mb-4">
          <svg class="w-6 h-6 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
          </svg>
        </div>
        <h3 class="text-lg font-semibold mb-2">Node System</h3>
        <p class="text-gray-400 text-sm">Distribute servers across multiple nodes</p>
      </div>
      <div class="p-6 bg-gray-800/50 rounded-xl border border-gray-700/50">
        <div class="w-12 h-12 rounded-xl bg-violet-500/20 flex items-center justify-center mb-4">
          <svg class="w-6 h-6 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
          </svg>
        </div>
        <h3 class="text-lg font-semibold mb-2">Live Console</h3>
        <p class="text-gray-400 text-sm">Real-time console with command execution</p>
      </div>
      <div class="p-6 bg-gray-800/50 rounded-xl border border-gray-700/50">
        <div class="w-12 h-12 rounded-xl bg-violet-500/20 flex items-center justify-center mb-4">
          <svg class="w-6 h-6 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z"/>
          </svg>
        </div>
        <h3 class="text-lg font-semibold mb-2">File Manager</h3>
        <p class="text-gray-400 text-sm">Browse and edit server files</p>
      </div>
      <div class="p-6 bg-gray-800/50 rounded-xl border border-gray-700/50">
        <div class="w-12 h-12 rounded-xl bg-violet-500/20 flex items-center justify-center mb-4">
          <svg class="w-6 h-6 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
        </div>
        <h3 class="text-lg font-semibold mb-2">Player Manager</h3>
        <p class="text-gray-400 text-sm">Manage players, kick, ban, and more</p>
      </div>
    </section>
  </main>
  
  <footer class="border-t border-gray-800 py-8 px-6">
    <div class="max-w-7xl mx-auto text-center text-gray-500">
      <p>&copy; 2024 <%= settings.panelName %>. Open source under MIT License.</p>
    </div>
  </footer>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/index.ejs'), indexEjs.trim());

// Login Page
const loginEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen flex items-center justify-center p-6">
  <div class="w-full max-w-md">
    <a href="/" class="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-8">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>
      Back to home
    </a>
    
    <div class="bg-gray-800/50 rounded-2xl border border-gray-700/50 p-8">
      <div class="text-center mb-8">
        <div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center mx-auto mb-4">
          <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>
        </div>
        <h1 class="text-2xl font-bold">Welcome back</h1>
        <p class="text-gray-400">Sign in to <%= settings.panelName %></p>
      </div>
      
      <% if (error) { %>
        <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-6 text-red-400 text-sm"><%= error %></div>
      <% } %>
      
      <form method="POST" action="/auth/login" class="space-y-4">
        <div>
          <label class="block text-sm font-medium mb-2">Email</label>
          <input type="email" name="email" required class="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Password</label>
          <input type="password" name="password" required class="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <button type="submit" class="w-full py-3 bg-gradient-to-r from-violet-500 to-purple-600 rounded-lg font-semibold hover:from-violet-600 hover:to-purple-700 transition">Sign in</button>
      </form>
      
      <p class="text-center mt-6 text-gray-400">
        Don't have an account? <a href="/auth/register" class="text-violet-400 hover:text-violet-300">Register</a>
      </p>
    </div>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/auth/login.ejs'), loginEjs.trim());

// Register Page
const registerEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen flex items-center justify-center p-6">
  <div class="w-full max-w-md">
    <a href="/" class="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-8">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>
      Back to home
    </a>
    
    <div class="bg-gray-800/50 rounded-2xl border border-gray-700/50 p-8">
      <div class="text-center mb-8">
        <div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center mx-auto mb-4">
          <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>
        </div>
        <h1 class="text-2xl font-bold">Create account</h1>
        <p class="text-gray-400">Register for <%= settings.panelName %></p>
      </div>
      
      <% if (error) { %>
        <div class="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-6 text-red-400 text-sm"><%= error %></div>
      <% } %>
      
      <form method="POST" action="/auth/register" class="space-y-4">
        <div>
          <label class="block text-sm font-medium mb-2">Username</label>
          <input type="text" name="username" required class="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Email</label>
          <input type="email" name="email" required class="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Password</label>
          <input type="password" name="password" required class="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <button type="submit" class="w-full py-3 bg-gradient-to-r from-violet-500 to-purple-600 rounded-lg font-semibold hover:from-violet-600 hover:to-purple-700 transition">Create account</button>
      </form>
      
      <p class="text-center mt-6 text-gray-400">
        Already have an account? <a href="/auth/login" class="text-violet-400 hover:text-violet-300">Sign in</a>
      </p>
    </div>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/auth/register.ejs'), registerEjs.trim());

// User Dashboard
const dashboardEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
      <span class="text-xl font-bold"><%= settings.panelName %></span>
      <div class="flex items-center gap-4">
        <span class="text-gray-400"><%= user.username %></span>
        <% if (user.isAdmin) { %>
          <a href="/admin/overview" class="px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30">Admin</a>
        <% } %>
        <a href="/auth/logout" class="text-gray-400 hover:text-white">Logout</a>
      </div>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <h1 class="text-3xl font-bold mb-8">My Servers</h1>
    
    <% if (servers.length === 0) { %>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-12 text-center">
        <p class="text-gray-400 mb-4">You don't have any servers yet.</p>
        <p class="text-sm text-gray-500">Contact an administrator to create a server for you.</p>
      </div>
    <% } else { %>
      <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
        <% servers.forEach(server => { %>
          <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-semibold"><%= server.name %></h3>
              <span class="px-2 py-1 rounded text-xs <%= server.status === 'running' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400' %>">
                <%= server.status %>
              </span>
            </div>
            <div class="space-y-2 text-sm text-gray-400 mb-4">
              <p>Type: <%= server.type %> (<%= server.version %>)</p>
              <p>Node: <%= server.node.name %></p>
              <p>Memory: <%= server.memory %> MB | CPU: <%= server.cpu %>%</p>
            </div>
            <a href="/server/<%= server.id %>" class="block w-full py-2 text-center bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30">Manage</a>
          </div>
        <% }) %>
      </div>
    <% } %>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/dashboard.ejs'), dashboardEjs.trim());

// Server Manage Page
const serverManageEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= server.name %> - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
      <div class="flex items-center gap-4">
        <a href="/dashboard" class="text-gray-400 hover:text-white">← Back</a>
        <span class="text-xl font-bold"><%= server.name %></span>
      </div>
    </div>
  </nav>
  
  <div class="max-w-7xl mx-auto px-6 py-4 flex gap-4 border-b border-gray-800">
    <a href="/server/<%= server.id %>" class="px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Overview</a>
    <a href="/server/<%= server.id %>/console" class="px-4 py-2 text-gray-400 hover:bg-gray-800 rounded-lg">Console</a>
    <a href="/server/<%= server.id %>/files" class="px-4 py-2 text-gray-400 hover:bg-gray-800 rounded-lg">Files</a>
    <a href="/server/<%= server.id %>/players" class="px-4 py-2 text-gray-400 hover:bg-gray-800 rounded-lg">Players</a>
    <a href="/server/<%= server.id %>/plugins" class="px-4 py-2 text-gray-400 hover:bg-gray-800 rounded-lg">Plugins</a>
    <a href="/server/<%= server.id %>/versions" class="px-4 py-2 text-gray-400 hover:bg-gray-800 rounded-lg">Versions</a>
    <a href="/server/<%= server.id %>/settings" class="px-4 py-2 text-gray-400 hover:bg-gray-800 rounded-lg">Settings</a>
  </div>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <div class="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
        <p class="text-gray-400 text-sm">Status</p>
        <p class="text-2xl font-bold <%= server.status === 'running' ? 'text-green-400' : 'text-gray-400' %>"><%= server.status %></p>
      </div>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
        <p class="text-gray-400 text-sm">Players</p>
        <p class="text-2xl font-bold"><%= server.players.length %></p>
      </div>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
        <p class="text-gray-400 text-sm">Memory</p>
        <p class="text-2xl font-bold"><%= server.memory %> MB</p>
      </div>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
        <p class="text-gray-400 text-sm">CPU</p>
        <p class="text-2xl font-bold"><%= server.cpu %>%</p>
      </div>
    </div>
    
    <div class="flex gap-4">
      <button class="px-6 py-3 bg-green-500/20 text-green-400 rounded-lg hover:bg-green-500/30">Start</button>
      <button class="px-6 py-3 bg-yellow-500/20 text-yellow-400 rounded-lg hover:bg-yellow-500/30">Restart</button>
      <button class="px-6 py-3 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30">Stop</button>
    </div>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/manage.ejs'), serverManageEjs.trim());

// Console Page
const consoleEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Console - <%= server.name %></title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="/socket.io/socket.io.js"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center gap-4">
      <a href="/server/<%= server.id %>" class="text-gray-400 hover:text-white">← Back</a>
      <span class="text-xl font-bold"><%= server.name %> - Console</span>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <div class="bg-black rounded-xl border border-gray-700 p-4 h-96 overflow-y-auto font-mono text-sm" id="console">
      <% logs.forEach(log => { %>
        <div class="<%= log.type === 'command' ? 'text-yellow-400' : 'text-gray-300' %>"><%= log.message %></div>
      <% }) %>
    </div>
    
    <form id="commandForm" class="mt-4 flex gap-4">
      <input type="text" id="command" placeholder="Enter command..." class="flex-1 px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none font-mono">
      <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Send</button>
    </form>
  </main>
  
  <script>
    const socket = io();
    const serverId = '<%= server.id %>';
    const consoleEl = document.getElementById('console');
    
    socket.emit('join-server', serverId);
    
    socket.on('console-output', (data) => {
      const div = document.createElement('div');
      div.className = 'text-gray-300';
      div.textContent = data.message;
      consoleEl.appendChild(div);
      consoleEl.scrollTop = consoleEl.scrollHeight;
    });
    
    document.getElementById('commandForm').addEventListener('submit', (e) => {
      e.preventDefault();
      const input = document.getElementById('command');
      const command = input.value.trim();
      if (command) {
        socket.emit('console-command', { serverId, command });
        const div = document.createElement('div');
        div.className = 'text-yellow-400';
        div.textContent = '> ' + command;
        consoleEl.appendChild(div);
        input.value = '';
        consoleEl.scrollTop = consoleEl.scrollHeight;
      }
    });
  </script>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/console.ejs'), consoleEjs.trim());

// Files Page
const filesEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Files - <%= server.name %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center gap-4">
      <a href="/server/<%= server.id %>" class="text-gray-400 hover:text-white">← Back</a>
      <span class="text-xl font-bold"><%= server.name %> - Files</span>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-4 mb-4">
      <p class="text-gray-400 font-mono"><%= currentPath %></p>
    </div>
    
    <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 divide-y divide-gray-700/50">
      <% if (files.length === 0) { %>
        <div class="p-8 text-center text-gray-400">No files found</div>
      <% } else { %>
        <% files.forEach(file => { %>
          <div class="flex items-center justify-between p-4 hover:bg-gray-700/30">
            <div class="flex items-center gap-3">
              <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <% if (file.isDir) { %>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"/>
                <% } else { %>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                <% } %>
              </svg>
              <span><%= file.name %></span>
            </div>
            <span class="text-gray-500 text-sm"><%= file.size %> bytes</span>
          </div>
        <% }) %>
      <% } %>
    </div>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/files.ejs'), filesEjs.trim());

// Players Page
const playersEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Players - <%= server.name %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center gap-4">
      <a href="/server/<%= server.id %>" class="text-gray-400 hover:text-white">← Back</a>
      <span class="text-xl font-bold"><%= server.name %> - Players</span>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <% if (players.length === 0) { %>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-12 text-center text-gray-400">
        No players online
      </div>
    <% } else { %>
      <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
        <% players.forEach(player => { %>
          <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-4 flex items-center justify-between">
            <div class="flex items-center gap-3">
              <img src="https://mc-heads.net/avatar/<%= player.username %>/32" class="w-8 h-8 rounded">
              <div>
                <p class="font-semibold"><%= player.username %></p>
                <p class="text-xs text-gray-500"><%= player.op ? 'OP' : 'Player' %></p>
              </div>
            </div>
            <div class="flex gap-2">
              <button class="px-3 py-1 text-sm bg-yellow-500/20 text-yellow-400 rounded hover:bg-yellow-500/30">Kick</button>
              <button class="px-3 py-1 text-sm bg-red-500/20 text-red-400 rounded hover:bg-red-500/30">Ban</button>
            </div>
          </div>
        <% }) %>
      </div>
    <% } %>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/players.ejs'), playersEjs.trim());

// Plugins Page
const pluginsEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Plugins - <%= server.name %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center gap-4">
      <a href="/server/<%= server.id %>" class="text-gray-400 hover:text-white">← Back</a>
      <span class="text-xl font-bold"><%= server.name %> - Plugins</span>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <div class="flex justify-between items-center mb-6">
      <h2 class="text-xl font-semibold">Installed Plugins</h2>
      <button class="px-4 py-2 bg-violet-500 rounded-lg hover:bg-violet-600">Install Plugin</button>
    </div>
    
    <% if (plugins.length === 0) { %>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-12 text-center text-gray-400">
        No plugins installed
      </div>
    <% } else { %>
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 divide-y divide-gray-700/50">
        <% plugins.forEach(plugin => { %>
          <div class="flex items-center justify-between p-4">
            <div>
              <p class="font-semibold"><%= plugin.name %></p>
              <p class="text-sm text-gray-500">v<%= plugin.version %></p>
            </div>
            <div class="flex items-center gap-4">
              <label class="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" class="sr-only peer" <%= plugin.enabled ? 'checked' : '' %>>
                <div class="w-11 h-6 bg-gray-700 rounded-full peer peer-checked:bg-violet-500"></div>
              </label>
              <button class="text-red-400 hover:text-red-300">Delete</button>
            </div>
          </div>
        <% }) %>
      </div>
    <% } %>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/plugins.ejs'), pluginsEjs.trim());

// Versions Page
const versionsEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Versions - <%= server.name %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center gap-4">
      <a href="/server/<%= server.id %>" class="text-gray-400 hover:text-white">← Back</a>
      <span class="text-xl font-bold"><%= server.name %> - Version Manager</span>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6 mb-6">
      <p class="text-gray-400 text-sm">Current Version</p>
      <p class="text-2xl font-bold"><%= server.version %></p>
    </div>
    
    <h2 class="text-xl font-semibold mb-4">Available Versions</h2>
    <div class="grid md:grid-cols-4 gap-4">
      <% versions.forEach(version => { %>
        <button class="p-4 rounded-xl border <%= version === server.version ? 'bg-violet-500/20 border-violet-500' : 'bg-gray-800/50 border-gray-700/50 hover:border-violet-500/50' %>">
          <p class="font-semibold"><%= version %></p>
          <% if (version === server.version) { %>
            <p class="text-xs text-violet-400">Current</p>
          <% } %>
        </button>
      <% }) %>
    </div>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/versions.ejs'), versionsEjs.trim());

// Server Settings Page
const serverSettingsEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Settings - <%= server.name %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <nav class="bg-gray-800 border-b border-gray-700">
    <div class="max-w-7xl mx-auto px-6 h-16 flex items-center gap-4">
      <a href="/server/<%= server.id %>" class="text-gray-400 hover:text-white">← Back</a>
      <span class="text-xl font-bold"><%= server.name %> - Settings</span>
    </div>
  </nav>
  
  <main class="max-w-7xl mx-auto px-6 py-8">
    <form class="space-y-6 max-w-xl">
      <div>
        <label class="block text-sm font-medium mb-2">Server Name</label>
        <input type="text" value="<%= server.name %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Port</label>
        <input type="number" value="<%= server.port %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">Memory (MB)</label>
        <input type="number" value="<%= server.memory %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
      </div>
      <div>
        <label class="block text-sm font-medium mb-2">CPU Limit (%)</label>
        <input type="number" value="<%= server.cpu %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
      </div>
      <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Save Settings</button>
    </form>
  </main>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/user/server/settings.ejs'), serverSettingsEjs.trim());

// Admin Overview
const adminOverviewEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>
        </div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      
      <nav class="space-y-2">
        <a href="/admin/overview" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Overview</a>
        <a href="/admin/nodes" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Nodes</a>
        <a href="/admin/servers" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Servers</a>
        <a href="/admin/users" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Users</a>
        <a href="/admin/settings" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Settings</a>
      </nav>
      
      <div class="mt-auto pt-8">
        <a href="/dashboard" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">← User Dashboard</a>
        <a href="/auth/logout" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Logout</a>
      </div>
    </aside>
    
    <main class="flex-1 p-8">
      <h1 class="text-3xl font-bold mb-8">Admin Overview</h1>
      
      <div class="grid md:grid-cols-3 gap-6">
        <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
          <p class="text-gray-400 text-sm">Total Users</p>
          <p class="text-3xl font-bold"><%= stats.users %></p>
        </div>
        <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
          <p class="text-gray-400 text-sm">Total Servers</p>
          <p class="text-3xl font-bold"><%= stats.servers %></p>
        </div>
        <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
          <p class="text-gray-400 text-sm">Total Nodes</p>
          <p class="text-3xl font-bold"><%= stats.nodes %></p>
        </div>
      </div>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/overview/overview.ejs'), adminOverviewEjs.trim());

// Admin Nodes
const adminNodesEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nodes - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>
        </div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/overview" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Overview</a>
        <a href="/admin/nodes" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Nodes</a>
        <a href="/admin/servers" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Servers</a>
        <a href="/admin/users" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Users</a>
        <a href="/admin/settings" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Settings</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-bold">Nodes</h1>
        <a href="/admin/nodes/create" class="px-4 py-2 bg-violet-500 rounded-lg hover:bg-violet-600">Create Node</a>
      </div>
      
      <% if (nodes.length === 0) { %>
        <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-12 text-center">
          <p class="text-gray-400 mb-4">No nodes created yet.</p>
          <a href="/admin/nodes/create" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600 inline-block">Create Node</a>
        </div>
      <% } else { %>
        <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          <% nodes.forEach(node => { %>
            <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 p-6">
              <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold"><%= node.name %></h3>
                <span class="px-2 py-1 rounded text-xs <%= node.status === 'online' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400' %>"><%= node.status %></span>
              </div>
              <div class="space-y-2 text-sm text-gray-400 mb-4">
                <p>CPU: <%= node.cpu %> Cores</p>
                <p>RAM: <%= node.ram %> GB</p>
                <p>Location: <%= node.location %></p>
                <p>Servers: <%= node.servers.length %></p>
              </div>
              <div class="space-y-2">
                <button onclick="showConfig('<%= settings.panelPort %>', '<%= node.key %>')" class="w-full py-2 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30">Configure</button>
                <div class="flex gap-2">
                  <a href="/admin/nodes/<%= node.id %>/edit" class="flex-1 py-2 text-center bg-yellow-500/20 text-yellow-400 rounded-lg hover:bg-yellow-500/30">Edit</a>
                  <form method="POST" action="/admin/nodes/<%= node.id %>/delete" class="flex-1">
                    <button type="submit" class="w-full py-2 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30" onclick="return confirm('Delete this node?')">Delete</button>
                  </form>
                </div>
              </div>
            </div>
          <% }) %>
        </div>
      <% } %>
    </main>
  </div>
  
  <div id="configModal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center z-50">
    <div class="bg-gray-800 rounded-xl p-6 max-w-lg w-full mx-4">
      <h3 class="text-xl font-bold mb-4">Node Configuration</h3>
      <p class="text-gray-400 mb-4">Run this command on your node server:</p>
      <code id="configCommand" class="block p-4 bg-black rounded-lg text-green-400 font-mono text-sm break-all"></code>
      <button onclick="closeModal()" class="mt-4 px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600">Close</button>
    </div>
  </div>
  
  <script>
    function showConfig(port, key) {
      document.getElementById('configCommand').textContent = 'npm run configure -- --panel "http://localhost:' + port + '" --key "' + key + '"';
      document.getElementById('configModal').classList.remove('hidden');
    }
    function closeModal() {
      document.getElementById('configModal').classList.add('hidden');
    }
  </script>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/nodes/nodes.ejs'), adminNodesEjs.trim());

// Create Node Page
const createNodeEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Create Node - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/overview" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Overview</a>
        <a href="/admin/nodes" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Nodes</a>
        <a href="/admin/servers" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Servers</a>
        <a href="/admin/users" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Users</a>
        <a href="/admin/settings" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Settings</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <h1 class="text-3xl font-bold mb-8">Create Node</h1>
      
      <form method="POST" action="/admin/nodes/create" class="space-y-6 max-w-xl">
        <div>
          <label class="block text-sm font-medium mb-2">Node Name</label>
          <input type="text" name="name" required placeholder="Node-01" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">CPU (Cores)</label>
          <input type="number" name="cpu" required placeholder="8" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">RAM (GB)</label>
          <input type="number" name="ram" required placeholder="16" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Location</label>
          <input type="text" name="location" required placeholder="New York, US" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div class="flex gap-4">
          <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Create Node</button>
          <a href="/admin/nodes" class="px-6 py-3 bg-gray-700 rounded-lg hover:bg-gray-600">Cancel</a>
        </div>
      </form>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/nodes/create.ejs'), createNodeEjs.trim());

// Edit Node Page
const editNodeEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Edit Node - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/nodes" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Nodes</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <h1 class="text-3xl font-bold mb-8">Edit Node: <%= node.name %></h1>
      
      <form method="POST" action="/admin/nodes/<%= node.id %>/edit" class="space-y-6 max-w-xl">
        <div>
          <label class="block text-sm font-medium mb-2">Node Name</label>
          <input type="text" name="name" required value="<%= node.name %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">CPU (Cores)</label>
          <input type="number" name="cpu" required value="<%= node.cpu %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">RAM (GB)</label>
          <input type="number" name="ram" required value="<%= node.ram %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Location</label>
          <input type="text" name="location" required value="<%= node.location %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Save Changes</button>
      </form>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/nodes/edit.ejs'), editNodeEjs.trim());

// Admin Users
const adminUsersEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Users - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/overview" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Overview</a>
        <a href="/admin/nodes" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Nodes</a>
        <a href="/admin/servers" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Servers</a>
        <a href="/admin/users" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Users</a>
        <a href="/admin/settings" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Settings</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-bold">Users</h1>
        <a href="/admin/users/create" class="px-4 py-2 bg-violet-500 rounded-lg hover:bg-violet-600">Create User</a>
      </div>
      
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 overflow-hidden">
        <table class="w-full">
          <thead class="bg-gray-700/50">
            <tr>
              <th class="px-6 py-3 text-left text-sm">Username</th>
              <th class="px-6 py-3 text-left text-sm">Email</th>
              <th class="px-6 py-3 text-left text-sm">Role</th>
              <th class="px-6 py-3 text-left text-sm">Servers</th>
              <th class="px-6 py-3 text-left text-sm">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-700/50">
            <% users.forEach(u => { %>
              <tr>
                <td class="px-6 py-4"><%= u.username %></td>
                <td class="px-6 py-4 text-gray-400"><%= u.email %></td>
                <td class="px-6 py-4">
                  <span class="px-2 py-1 rounded text-xs <%= u.isAdmin ? 'bg-violet-500/20 text-violet-400' : 'bg-gray-500/20 text-gray-400' %>">
                    <%= u.isAdmin ? 'Admin' : 'User' %>
                  </span>
                </td>
                <td class="px-6 py-4"><%= u.servers.length %></td>
                <td class="px-6 py-4">
                  <form method="POST" action="/admin/users/<%= u.id %>/delete" class="inline">
                    <button type="submit" class="text-red-400 hover:text-red-300" onclick="return confirm('Delete this user?')">Delete</button>
                  </form>
                </td>
              </tr>
            <% }) %>
          </tbody>
        </table>
      </div>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/users/users.ejs'), adminUsersEjs.trim());

// Create User Page
const createUserEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Create User - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/users" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Users</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <h1 class="text-3xl font-bold mb-8">Create User</h1>
      
      <form method="POST" action="/admin/users/create" class="space-y-6 max-w-xl">
        <div>
          <label class="block text-sm font-medium mb-2">Username</label>
          <input type="text" name="username" required class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Email</label>
          <input type="email" name="email" required class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Password</label>
          <input type="password" name="password" required class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Admin</label>
          <select name="isAdmin" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
            <option value="no">No</option>
            <option value="yes">Yes</option>
          </select>
        </div>
        <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Create User</button>
      </form>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/users/create.ejs'), createUserEjs.trim());

// Admin Servers
const adminServersEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Servers - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/overview" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Overview</a>
        <a href="/admin/nodes" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Nodes</a>
        <a href="/admin/servers" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Servers</a>
        <a href="/admin/users" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Users</a>
        <a href="/admin/settings" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Settings</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-bold">Servers</h1>
        <a href="/admin/servers/create" class="px-4 py-2 bg-violet-500 rounded-lg hover:bg-violet-600">Create Server</a>
      </div>
      
      <div class="bg-gray-800/50 rounded-xl border border-gray-700/50 overflow-hidden">
        <table class="w-full">
          <thead class="bg-gray-700/50">
            <tr>
              <th class="px-6 py-3 text-left text-sm">Name</th>
              <th class="px-6 py-3 text-left text-sm">Node</th>
              <th class="px-6 py-3 text-left text-sm">Owner</th>
              <th class="px-6 py-3 text-left text-sm">Status</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-700/50">
            <% servers.forEach(s => { %>
              <tr>
                <td class="px-6 py-4"><%= s.name %></td>
                <td class="px-6 py-4 text-gray-400"><%= s.node.name %></td>
                <td class="px-6 py-4 text-gray-400"><%= s.user.username %></td>
                <td class="px-6 py-4">
                  <span class="px-2 py-1 rounded text-xs <%= s.status === 'running' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400' %>"><%= s.status %></span>
                </td>
              </tr>
            <% }) %>
          </tbody>
        </table>
      </div>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/servers/servers.ejs'), adminServersEjs.trim());

// Create Server Page
const createServerEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Create Server - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/servers" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Servers</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <h1 class="text-3xl font-bold mb-8">Create Server</h1>
      
      <form method="POST" action="/admin/servers/create" class="space-y-6 max-w-xl">
        <div>
          <label class="block text-sm font-medium mb-2">Server Name</label>
          <input type="text" name="name" required class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Type</label>
          <select name="type" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
            <option value="minecraft">Minecraft</option>
            <option value="paper">Paper</option>
            <option value="spigot">Spigot</option>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Version</label>
          <input type="text" name="version" value="1.20.1" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Port</label>
          <input type="number" name="port" value="25565" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Memory (MB)</label>
          <input type="number" name="memory" value="1024" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">CPU Limit (%)</label>
          <input type="number" name="cpu" value="100" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Node</label>
          <select name="nodeId" required class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
            <% nodes.forEach(n => { %>
              <option value="<%= n.id %>"><%= n.name %></option>
            <% }) %>
          </select>
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Owner</label>
          <select name="userId" required class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg">
            <% users.forEach(u => { %>
              <option value="<%= u.id %>"><%= u.username %></option>
            <% }) %>
          </select>
        </div>
        <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Create Server</button>
      </form>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/servers/create.ejs'), createServerEjs.trim());

// Admin Settings
const adminSettingsEjs = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Settings - <%= settings.panelName %></title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
  <div class="flex">
    <aside class="w-64 min-h-screen bg-gray-800 border-r border-gray-700 p-4">
      <div class="flex items-center gap-3 mb-8">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600"></div>
        <span class="font-bold"><%= settings.panelName %></span>
      </div>
      <nav class="space-y-2">
        <a href="/admin/overview" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Overview</a>
        <a href="/admin/nodes" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Nodes</a>
        <a href="/admin/servers" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Servers</a>
        <a href="/admin/users" class="block px-4 py-2 text-gray-400 hover:bg-gray-700 rounded-lg">Users</a>
        <a href="/admin/settings" class="block px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg">Settings</a>
      </nav>
    </aside>
    
    <main class="flex-1 p-8">
      <h1 class="text-3xl font-bold mb-8">Panel Settings</h1>
      
      <% if (success) { %>
        <div class="bg-green-500/10 border border-green-500/30 rounded-lg p-4 mb-6 text-green-400">Settings saved successfully!</div>
      <% } %>
      
      <form method="POST" action="/admin/settings" class="space-y-6 max-w-xl">
        <div>
          <label class="block text-sm font-medium mb-2">Panel Name</label>
          <input type="text" name="panelName" value="<%= settings.panelName %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Panel Port</label>
          <input type="number" name="panelPort" value="<%= settings.panelPort %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-sm font-medium mb-2">Panel Icon (URL)</label>
          <input type="text" name="panelIcon" value="<%= settings.panelIcon %>" class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg focus:border-violet-500 focus:outline-none">
        </div>
        <button type="submit" class="px-6 py-3 bg-violet-500 rounded-lg hover:bg-violet-600">Save Settings</button>
      </form>
    </main>
  </div>
</body>
</html>
`;

fs.writeFileSync(path.join(BASE_DIR, 'views/admin/settings/settings.ejs'), adminSettingsEjs.trim());

// Language files
const langEn = { welcome: "Welcome", login: "Login", register: "Register" };
const langFr = { welcome: "Bienvenue", login: "Connexion", register: "S'inscrire" };

fs.writeFileSync(path.join(BASE_DIR, 'storage/lang/en/lang.json'), JSON.stringify(langEn, null, 2));
fs.writeFileSync(path.join(BASE_DIR, 'storage/lang/fr/lang.json'), JSON.stringify(langFr, null, 2));

// Config
fs.writeFileSync(path.join(BASE_DIR, 'storage/config.json'), JSON.stringify({ version: "1.0.0" }, null, 2));

console.log('');
console.log('╔═══════════════════════════════════════════════════════════════╗');
console.log('║              ZyperPanel Installation Complete!                 ║');
console.log('╚═══════════════════════════════════════════════════════════════╝');
console.log('');
console.log('Next steps:');
console.log('1. npm install');
console.log('2. npx prisma generate');
console.log('3. npx prisma db push');
console.log('4. npm start');
console.log('');
console.log('Add users with: npm run adduser');
console.log('');