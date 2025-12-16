# 🚀 ZyperPanel - Powerful Game Server Management Panel

_A modern, open-source game server management panel with multi-node support_

[![Discord](https://img.shields.io/discord/123456789012345678?color=7289DA&label=Support%20Server&logo=discord&logoColor=white)](https://discord.gg/v8swAnehVP)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/yourusername/zyperpanel)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)

## ✨ Features

### 🎮 **Game Server Support**

- **Minecraft**: Paper, Spigot, Purpur, Vanilla, BungeeCord, Velocity
- **Multiple Versions**: Support for all major Minecraft versions
- **Auto-Updates**: Keep servers updated with latest builds
- **Plugin Management**: One-click plugin installation from SpigotMC & Modrinth

### 🖥️ **Management Tools**

- **Live Console**: Real-time console with command execution
- **File Manager**: Full-featured web-based file browser and editor
- **Player Management**: Kick, ban, whitelist, and op management
- **Server Stats**: Real-time CPU, RAM, and player monitoring
- **Backup System**: Automated server backups

### 🌐 **Multi-Node Architecture**

- **Distributed Nodes**: Deploy servers across multiple physical machines
- **Load Balancing**: Automatic server distribution
- **Node Health Monitoring**: Real-time node status checking
- **Geographic Distribution**: Deploy servers closer to your players

### 🔒 **Security & Permissions**

- **User Roles**: Admin, Moderator, User permissions
- **Server Isolation**: Each user's servers are fully isolated
- **API Security**: Secure API keys and authentication
- **SSL Support**: HTTPS encryption for all communications

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm
- Docker & Docker Compose
- PostgreSQL or MySQL (SQLite for development)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/zyperdev12/zyperpanel.git
cd zyperpanel
```

2. **Install dependencies**

```bash
npm install
```

3. **Configure environment**

```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Set up database**

```bash
npx prisma db push
npx prisma generate
```

5. **Start Panel**

```bash
npm run build
npm install -g pm2
pm2 start npm --name "Zyper-Daemon" -- start
pm2 save
pm2 startup

```

6. **Access the panel**

### Open your Panel on port 3000 and Can get the credintials on the .env




7. **Note to add multiple admin users/non-admin users via terminal**

```bash
sudo npm run adduser
```
