import express from "express";
import session from "express-session";
import cors from "cors";
import cookieParser from "cookie-parser";
import { createServer } from "http";
import { Server as SocketServer } from "socket.io";
import path from "path";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

import { checkNodeStatus } from "./handlers/utils/node/statusChecker";
import axios from "axios";
import favicon from "serve-favicon";
dotenv.config();

// Add TypeScript declarations for session
declare module "express-session" {
  interface SessionData {
    userId: string;
  }
}

// Extended request type with user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        username: string;
        email: string;
        isAdmin: boolean;
      };
    }
  }
}

// Extended server type with containerId
interface ServerWithContainer {
  id: string;
  name: string;
  type: string;
  version: string;
  port: number;
  memory: number;
  cpu: number;
  status: string;
  containerId?: string;
  nodeId: string;
  userId: string;
  createdAt: Date;
  node: {
    id: string;
    key: string;
    name: string;
    cpu: number;
    ram: number;
    location: string;
    host: string;
    port: number;
    status: string;
    createdAt: Date;
  };
}

const app = express();
const prisma = new PrismaClient();

const ensureDefaultAdmin = async () => {
  const adminEmail = process.env.DEFAULT_ADMIN_EMAIL;
  const adminUsername = process.env.DEFAULT_ADMIN_USERNAME;
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;

  if (!adminEmail || !adminUsername || !adminPassword) {
    console.warn("⚠️ Default admin env vars not set");
    return;
  }

  const existingAdmin = await prisma.user.findFirst({
    where: { isAdmin: true },
  });

  if (existingAdmin) {
    console.log("✅ Admin already exists");
    return;
  }

  const hashedPassword = bcrypt.hashSync(adminPassword, 10);

  await prisma.user.create({
    data: {
      email: adminEmail.toLowerCase(),
      username: adminUsername,
      password: hashedPassword,
      isAdmin: true,
    },
  });

  console.log("✅ Default admin created:", adminEmail);
};

// ============== CRITICAL FIX: ADD DEFAULT NODE ==============
const ensureDefaultNode = async () => {
  try {
    // Check if we already have the CodeSandbox node added
    const existingNode = await prisma.node.findFirst({
      where: { name: "codesandbox-20251210" },
    });

    if (existingNode) {
      console.log("✅ Default node already exists");
      return;
    }

    // Add the CodeSandbox daemon node to the panel
    const nodeData = {
      id: "c3e315df-646d-4590-98e1-0c624097054b", // From daemon output
      name: "codesandbox-20251210",
      cpu: 2000, // 2 CPU cores
      ram: 4096, // 4GB RAM
      location: "CodeSandbox",
      host: "localhost", // Daemon is running locally
      port: 8080, // Daemon port
      key: "ac315994f3a9bde8c6821d9384a2ebe56361f45e67bf73105699ab3ec07d2d36", // Node Key from daemon
      status: "online",
      createdAt: new Date(),
    };

    await prisma.node.create({
      data: nodeData,
    });

    console.log("✅ Default node created:", nodeData.name);
    console.log("📡 Node configured with:");
    console.log("   - ID:", nodeData.id);
    console.log("   - Key:", nodeData.key);
    console.log("   - Host:", nodeData.host);
    console.log("   - Port:", nodeData.port);
  } catch (error: any) {
    console.error("❌ Failed to create default node:", error.message);
  }
};

const httpServer = createServer(app);
const io = new SocketServer(httpServer, {
  cors: {
    origin: [
      "http://localhost:3000",
      "http://localhost:8080",
      "https://*.csb.app",
      "https://t2sqjj-3000.csb.app",
    ],
    credentials: true,
  },
});

// Middleware
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:8080",
      "https://*.csb.app",
      "https://t2sqjj-3000.csb.app",
      "https://zyperpanel.dev.tc/",
      "https://zyperpanel.altracloud.fun/",
      "https://zyperpanel.dev.tc/?ref=site.ac/islem-URL",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "x-api-key",
      "x-node-key",
    ],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "zyperpanel-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../views"));
app.use(express.static(path.join(__dirname, "../public")));

// Get settings helper
const getSettings = async () => {
  let settings = await prisma.settings.findFirst();
  if (!settings) {
    settings = await prisma.settings.create({
      data: {
        panelName: "ZyperPanel",
        panelPort: 3000,
        panelIcon: "/favicon.ico",
      },
    });
  }
  return settings;
};

// Auth middleware
const requireAuth = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  if (!req.session.userId) {
    const settings = await getSettings();
    return res.status(401).render("error/500", {
      settings,
      errorType: "auth",
      originalUrl: req.originalUrl,
      method: req.method,
      isAuthenticated: false,
      user: null,
      sessionId: req.session.id,
      message: "Please login to access this page",
    });
  }
  next();
};

const requireAdmin = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  if (!req.session.userId) {
    const settings = await getSettings();
    return res.status(401).render("error/500", {
      settings,
      errorType: "auth",
      originalUrl: req.originalUrl,
      method: req.method,
      isAuthenticated: false,
      user: null,
      sessionId: req.session.id,
      message: "Please login to access this page",
    });
  }

  const user = await prisma.user.findUnique({
    where: { id: req.session.userId },
    select: { id: true, username: true, email: true, isAdmin: true },
  });

  if (!user?.isAdmin) {
    const settings = await getSettings();
    return res.status(403).render("error/500", {
      settings,
      errorType: "admin",
      originalUrl: req.originalUrl,
      method: req.method,
      isAuthenticated: true,
      user: user,
      sessionId: req.session.id,
      message: "Admin privileges required",
    });
  }

  // Add user to request object
  req.user = user;
  next();
};

// ============== NODE API HELPER (FIXED) ==============

class NodeAPI {
  static async call(
    nodeId: string,
    endpoint: string,
    method: string = "GET",
    data?: any
  ) {
    try {
      const node = await prisma.node.findUnique({ where: { id: nodeId } });
      if (!node) throw new Error("Node not found");

      const url = `http://${node.host || "localhost"}:${
        node.port || 8080
      }${endpoint}`;
      console.log(`[NodeAPI] ${method} ${url}`);

      // DEBUG: Log what key we're using
      console.log(
        `[NodeAPI Debug] Node key from DB: ${
          node.key ? `${node.key.substring(0, 20)}...` : "MISSING"
        }`
      );

      // FINAL FIX: Use the node.key from database (which matches daemon's nodeKey)
      const headers: any = {
        "Content-Type": "application/json",
        "x-api-key": node.key, // MUST be "ac315994f3a9bde8c6821d9384a2ebe56361f45e67bf73105699ab3ec07d2d36"
      };

      // Also include Authorization header as backup
      if (node.key) {
        headers["authorization"] = `Bearer ${node.key}`;
      }

      console.log(
        `[NodeAPI Headers] x-api-key: ${node.key ? "✓ Present" : "✗ Missing"}`
      );

      const response = await axios({
        method,
        url,
        data,
        headers,
        timeout: 15000,
      });

      return response.data;
    } catch (error: any) {
      console.error(`[NodeAPI Error] ${endpoint}:`, error.message);
      if (error.response) {
        console.error(`[NodeAPI Status] ${error.response.status}`);
        console.error(`[NodeAPI Response]`, error.response.data);
        console.error(
          `[NodeAPI Headers Sent]`,
          error.config?.headers
            ? {
                "x-api-key": error.config.headers["x-api-key"]
                  ? "✓ Sent"
                  : "✗ Missing",
                authorization: error.config.headers["authorization"]
                  ? "✓ Sent"
                  : "✗ Missing",
              }
            : "No headers"
        );
      }
      throw error;
    }
  }

  // FIXED: getServerVersions method
  static async getServerVersions(nodeId: string, serverType: string) {
    return await this.call(nodeId, `/versions/${serverType}`, "GET");
  }

  static async getPaperBuilds(nodeId: string, version: string) {
    return await this.call(nodeId, `/versions/paper/${version}/builds`, "GET");
  }

  static async changeServerVersion(
    serverId: string,
    version: string,
    serverType?: string,
    build?: string
  ) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/change-version`,
      "POST",
      { version, serverType, build }
    );
  }

  // Server management methods
  static async startServer(serverId: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/start`,
      "POST"
    );
  }

  static async stopServer(serverId: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/stop`,
      "POST"
    );
  }

  static async restartServer(serverId: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/restart`,
      "POST"
    );
  }

  static async createServer(nodeId: string, serverData: any) {
    return await this.call(nodeId, "/instances/create", "POST", serverData);
  }

  static async getServerFiles(serverId: string, path?: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/files/list`,
      "POST",
      { path: path || "/" }
    );
  }

  static async readFile(serverId: string, filePath: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/files/read`,
      "POST",
      { filePath }
    );
  }

  static async writeFile(serverId: string, filePath: string, content: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/files/write`,
      "POST",
      { filePath, content }
    );
  }

  static async uploadFile(
    serverId: string,
    filePath: string,
    fileName: string,
    fileData: string,
    encoding: string = "base64"
  ) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/files/upload`,
      "POST",
      { filePath, fileName, fileData, encoding }
    );
  }

  // Update the deleteFile method in NodeAPI class
  static async deleteFile(
    serverId: string,
    filePath: string,
    force: boolean = false
  ) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    const endpoint = `/instances/${server.containerId}/files/delete`;

    return await this.call(server.node.id, endpoint, "POST", {
      filePath,
      force,
    });
  }

  static async getServerLogs(serverId: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    console.log(
      `[NodeAPI] Getting logs for server ${serverId}, container ${server.containerId}`
    );

    try {
      const logs = await this.call(
        server.node.id,
        `/instances/${server.containerId}/logs`,
        "GET"
      );

      console.log(`[NodeAPI] Logs response:`, logs);
      return logs;
    } catch (error: any) {
      console.error(`[NodeAPI] Failed to get logs:`, error.message);
      return {
        success: false,
        logs: `Error fetching logs: ${error.message}`,
        error: error.message,
      };
    }
  }

  static async getServerStats(serverId: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/stats`,
      "GET"
    );
  }

  static async runCommand(serverId: string, command: string) {
    const server = await prisma.server.findUnique({
      where: { id: serverId },
      include: { node: true },
    });

    if (!server) throw new Error("Server not found");
    if (!server.node) throw new Error("Node not found");
    if (!server.containerId) throw new Error("Server has no container ID");

    return await this.call(
      server.node.id,
      `/instances/${server.containerId}/command`,
      "POST",
      { command }
    );
  }
}

// ============== PUBLIC ROUTES ==============

app.get("/", async (req, res) => {
  const settings = await getSettings();
  res.render("index", { settings });
});

// ============== AUTH ROUTES ==============

app.get("/auth/login", async (req, res) => {
  const settings = await getSettings();
  res.render("auth/login", { settings, error: null });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const settings = await getSettings();

  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (!user) {
    return res.render("auth/login", {
      settings,
      error: "Invalid credentials",
    });
  }

  const valid = bcrypt.compareSync(password, user.password);

  if (!valid) {
    return res.render("auth/login", {
      settings,
      error: "Invalid credentials",
    });
  }

  req.session.userId = user.id;
  res.redirect(user.isAdmin ? "/admin/overview" : "/dashboard");
});

app.get("/auth/register", async (req, res) => {
  const settings = await getSettings();
  res.render("auth/register", { settings, error: null });
});

app.post("/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  const settings = await getSettings();

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const userCount = await prisma.user.count();

    const user = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        isAdmin: userCount === 0,
      },
    });

    req.session.userId = user.id;
    res.redirect(user.isAdmin ? "/admin/overview" : "/dashboard");
  } catch (error) {
    res.render("auth/register", { settings, error: "User already exists" });
  }
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ============== USER DASHBOARD ==============

app.get(
  "/dashboard",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const servers = await prisma.server.findMany({
      where: { userId: req.session.userId },
      include: { node: true, players: true },
    });
    res.render("user/dashboard", { settings, user, servers });
  }
);

// ============== SERVER MANAGEMENT ==============

app.get(
  "/server/:id",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
      include: { node: true, players: true, plugins: true },
    });
    if (!server || server.userId !== req.session.userId) {
      return res.redirect("/dashboard");
    }
    res.render("user/server/manage", { settings, user, server });
  }
);

app.get(
  "/server/:id/console",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
      include: { node: true },
    });

    if (!server || server.userId !== req.session.userId) {
      return res.redirect("/dashboard");
    }

    const logs = await prisma.consoleLog.findMany({
      where: { serverId: req.params.id },
      orderBy: { createdAt: "desc" },
      take: 100,
    });

    res.render("user/server/console", {
      settings,
      user,
      server,
      logs: logs.reverse(),
      serverId: server.id,
    });
  }
);

app.get(
  "/server/:id/files",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const settings = await getSettings();
      const user = await prisma.user.findUnique({
        where: { id: req.session.userId },
      });
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.redirect("/dashboard");
      }

      const currentPath = (req.query.path as string) || "/";

      let files = [];
      let error = null;

      if (server.containerId) {
        try {
          const filesResponse = await NodeAPI.getServerFiles(
            server.id,
            currentPath
          );

          if (filesResponse.success && filesResponse.items) {
            files = filesResponse.items.map((item: any) => ({
              name: item.name,
              isDir: item.type === "directory",
              size: item.size || 0,
              path: item.path,
              modified: item.modified,
              permissions: item.permissions,
              type: item.type,
            }));

            console.log(
              `[Files] Found ${files.length} items in ${currentPath}`
            );
          } else {
            error = filesResponse.error || "Failed to fetch files";
          }
        } catch (fileError: any) {
          console.error("[Files] Daemon error:", fileError.message);
          error = "Could not connect to daemon: " + fileError.message;
        }
      } else {
        error = "Server not created yet";
      }

      res.render("user/server/files", {
        settings,
        user,
        server,
        files,
        currentPath,
        error,
        formatBytes: (bytes: number) => {
          if (bytes === 0) return "0 Bytes";
          const k = 1024;
          const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
          const i = Math.floor(Math.log(bytes) / Math.log(k));
          return (
            parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i]
          );
        },
      });
    } catch (error: any) {
      console.error("Files route error:", error);
      res.redirect("/dashboard");
    }
  }
);

// Delete file
app.post(
  "/server/:id/files/delete",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { filePath, force = false } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const result = await NodeAPI.call(
        server.node.id,
        `/instances/${server.containerId}/files/delete`,
        "POST",
        { filePath, force }
      );

      res.json(result);
    } catch (error: any) {
      console.error("Delete error:", error);
      res.status(500).json({
        success: false,
        error: error.message,
        message: "Failed to delete file",
      });
    }
  }
);

// Force delete (for non-empty directories)
app.post(
  "/server/:id/files/delete-force",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { filePath } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const result = await NodeAPI.call(
        server.node.id,
        `/instances/${server.containerId}/files/delete-force`,
        "POST",
        { filePath }
      );

      res.json(result);
    } catch (error: any) {
      console.error("Force delete error:", error);
      res.status(500).json({
        success: false,
        error: error.message,
        message: "Failed to force delete",
      });
    }
  }
);

app.post(
  "/server/:id/files/read",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { filePath } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const result = await NodeAPI.readFile(server.id, filePath);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/files/write",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { filePath, content } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const result = await NodeAPI.writeFile(server.id, filePath, content);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/files/create",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { type, name, path: basePath } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const fullPath = `${basePath || ""}/${name}`.replace(/\/\//g, "/");

      if (type === "file") {
        const result = await NodeAPI.writeFile(server.id, fullPath, "");
        res.json(result);
      } else if (type === "folder") {
        res.json({
          success: true,
          message: "Folder creation would be implemented here",
        });
      } else {
        res.status(400).json({ error: "Invalid type" });
      }
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/server/:id/players",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
    });
    const players = await prisma.player.findMany({
      where: { serverId: req.params.id },
    });
    res.render("user/server/players", { settings, user, server, players });
  }
);

app.get(
  "/server/:id/plugins",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
      include: { node: true },
    });

    if (!server || server.userId !== req.session.userId) {
      return res.redirect("/dashboard");
    }

    let plugins = [];
    if (server.containerId) {
      try {
        const pluginsResponse = await NodeAPI.getServerFiles(
          server.id,
          "plugins"
        );
        if (pluginsResponse.success && pluginsResponse.items) {
          plugins = pluginsResponse.items
            .filter((item: any) => item.name.endsWith(".jar"))
            .map((item: any) => ({
              name: item.name.replace(".jar", ""),
              fileName: item.name,
              size: item.size,
              path: item.path,
              installed: true,
              enabled: true,
              version: "1.0.0",
            }));
        }
      } catch (error) {
        console.error("[Plugins] Error fetching plugins:", error);
      }
    }

    res.render("user/server/plugins", {
      settings,
      user,
      server,
      plugins,
      serverVersion: server.version || "1.20.1",
    });
  }
);

app.get(
  "/server/:id/plugins/available",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { search = "", page = 1, source = "spigot" } = req.query;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      let plugins = [];
      if (source === "spigot") {
        plugins = await fetchSpigotPlugins(
          search as string,
          parseInt(page as string)
        );
      } else {
        plugins = await fetchModrinthPlugins(
          search as string,
          parseInt(page as string)
        );
      }

      res.json({ success: true, plugins });
    } catch (error: any) {
      console.error("Error fetching available plugins:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/plugins/install",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { pluginUrl, pluginName, source = "spigot" } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      let downloadUrl = pluginUrl;
      if (source === "spigot" && !pluginUrl.includes("download")) {
        downloadUrl = `https://api.spiget.org/v2/resources/${pluginUrl}/download`;
      }

      console.log(`[Plugin Install] Downloading from: ${downloadUrl}`);

      const response = await axios.get(downloadUrl, {
        responseType: "arraybuffer",
        timeout: 30000,
      });

      const pluginData = Buffer.from(response.data).toString("base64");
      const fileName = pluginName.endsWith(".jar")
        ? pluginName
        : `${pluginName}.jar`;

      const result = await NodeAPI.uploadFile(
        server.id,
        "plugins",
        fileName,
        pluginData,
        "base64"
      );

      if (result.success) {
        await prisma.consoleLog.create({
          data: {
            serverId: server.id,
            message: `Plugin installed: ${pluginName}`,
            type: "info",
          },
        });

        res.json({ success: true, message: "Plugin installed successfully" });
      } else {
        res.status(500).json({ error: "Failed to upload plugin" });
      }
    } catch (error: any) {
      console.error("Error installing plugin:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/plugins/toggle",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { pluginName, enabled } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const oldName = enabled
        ? `${pluginName}.jar.disabled`
        : `${pluginName}.jar`;
      const newName = enabled
        ? `${pluginName}.jar`
        : `${pluginName}.jar.disabled`;

      try {
        const checkResult = await NodeAPI.call(
          server.nodeId,
          `/instances/${server.containerId}/files/list`,
          "POST",
          { path: `plugins/${oldName}` }
        );

        if (checkResult.success) {
          res.json({
            success: true,
            message: enabled ? "Plugin enabled" : "Plugin disabled",
          });
        } else {
          res.status(404).json({ error: "Plugin not found" });
        }
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/plugins/delete",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { pluginName } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const fileName = pluginName.endsWith(".jar")
        ? pluginName
        : `${pluginName}.jar`;
      const disabledName = `${pluginName}.jar.disabled`;

      try {
        await NodeAPI.deleteFile(server.id, `plugins/${fileName}`);
        await NodeAPI.deleteFile(server.id, `plugins/${disabledName}`);

        res.json({ success: true, message: "Plugin deleted" });
      } catch (error: any) {
        res.status(500).json({ error: error.message });
      }
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

async function fetchSpigotPlugins(search: string, page: number) {
  try {
    const size = 20;
    const url = search
      ? `https://api.spiget.org/v2/search/resources/${encodeURIComponent(
          search
        )}?size=${size}&page=${page - 1}&field=name`
      : `https://api.spiget.org/v2/resources/free?size=${size}&page=${
          page - 1
        }&sort=-downloads`;

    const response = await axios.get(url, { timeout: 10000 });
    return response.data;
  } catch (error) {
    console.error("Error fetching from SpigotMC:", error);
    return [];
  }
}

async function fetchModrinthPlugins(search: string, page: number) {
  try {
    const limit = 20;
    const offset = (page - 1) * limit;
    const query = search || "minecraft plugin";

    const response = await axios.get(
      `https://api.modrinth.com/v2/search?query=${encodeURIComponent(
        query
      )}&limit=${limit}&offset=${offset}&facets=[["project_type:mod"]]`,
      {
        headers: { Accept: "application/json" },
        timeout: 10000,
      }
    );

    return response.data.hits || [];
  } catch (error) {
    console.error("Error fetching from Modrinth:", error);
    return [];
  }
}

app.get(
  "/server/:id/settings",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
    });
    res.render("user/server/settings", { settings, user, server });
  }
);

app.get(
  "/server/:id/versions",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const user = await prisma.user.findUnique({
      where: { id: req.session.userId },
    });
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
      include: { node: true },
    });

    if (!server || server.userId !== req.session.userId) {
      return res.redirect("/dashboard");
    }

    const serverTypes = [
      {
        id: "paper",
        name: "PaperMC",
        icon: "fas fa-copy",
        color: "text-blue-400",
      },
      {
        id: "purpur",
        name: "Purpur",
        icon: "fas fa-feather-alt",
        color: "text-purple-400",
      },
      {
        id: "spigot",
        name: "Spigot",
        icon: "fas fa-tools",
        color: "text-yellow-400",
      },
      {
        id: "vanilla",
        name: "Vanilla",
        icon: "fas fa-cube",
        color: "text-green-400",
      },
      {
        id: "bungee",
        name: "BungeeCord",
        icon: "fas fa-network-wired",
        color: "text-cyan-400",
      },
      {
        id: "velocity",
        name: "Velocity",
        icon: "fas fa-bolt",
        color: "text-orange-400",
      },
    ];

    const currentType =
      serverTypes.find((t) => t.id === (server.type || "paper")) ||
      serverTypes[0];

    let versions = [];
    try {
      if (server.node) {
        // FIXED: Pass both nodeId and serverType
        const versionsResponse = await NodeAPI.getServerVersions(
          server.node.id,
          server.type || "paper"
        );
        if (versionsResponse && versionsResponse.versions) {
          versions = versionsResponse.versions;
        }
      }
    } catch (error) {
      console.error("Error fetching versions:", error);
      versions = [
        "1.20.4",
        "1.20.3",
        "1.20.2",
        "1.20.1",
        "1.19.4",
        "1.18.2",
        "1.17.1",
        "1.16.5",
      ];
    }

    let paperBuilds = [];
    let latestBuild = "";
    if (server.type === "paper" && server.version && server.node) {
      try {
        // FIXED: Pass both nodeId and version
        const buildsResponse = await NodeAPI.getPaperBuilds(
          server.node.id,
          server.version
        );
        if (buildsResponse && buildsResponse.success) {
          paperBuilds = buildsResponse.builds
            ? buildsResponse.builds.slice(0, 10)
            : [];
          latestBuild = buildsResponse.latest || "";
        }
      } catch (error) {
        console.error("Error fetching Paper builds:", error);
      }
    }

    res.render("user/server/versions", {
      settings,
      user,
      server,
      serverTypes,
      currentType,
      versions,
      paperBuilds,
      latestBuild,
      formatBytes: (bytes: number) => {
        if (bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
      },
    });
  }
);

app.post(
  "/server/:id/versions/change",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { version, serverType, build } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      console.log(
        `Changing server ${server.name} to ${version} (${serverType})`
      );

      const result = await NodeAPI.changeServerVersion(
        req.params.id,
        version,
        serverType,
        build
      );

      if (result.success) {
        await prisma.server.update({
          where: { id: req.params.id },
          data: {
            version: version,
            type: serverType || server.type,
          },
        });

        await prisma.consoleLog.create({
          data: {
            serverId: req.params.id,
            message: `Server version changed to ${version} (${serverType})`,
            type: "info",
          },
        });

        res.json({
          success: true,
          message: "Version changed successfully",
          redirect: `/server/${req.params.id}/versions?success=Version changed to ${version}`,
        });
      } else {
        res.status(500).json({ error: result.error });
      }
    } catch (error: any) {
      console.error("Error changing version:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/server/:id/versions/fetch",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { type } = req.query;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.node) {
        return res.status(400).json({ error: "Server has no node" });
      }

      const versions = await NodeAPI.getServerVersions(
        server.node.id,
        (type as string) || server.type || "paper"
      );
      res.json(versions);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/server/:id/versions/builds",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { version } = req.query;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.node) {
        return res.status(400).json({ error: "Server has no node" });
      }

      const builds = await NodeAPI.getPaperBuilds(
        server.node.id,
        version as string
      );
      res.json(builds);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/start",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res
          .status(400)
          .json({ error: "Server has no container ID. Please contact admin." });
      }

      console.log(
        `Starting server: ${server.name} (Container: ${
          server.containerId || "none"
        })`
      );

      await NodeAPI.startServer(req.params.id);

      await prisma.server.update({
        where: { id: req.params.id },
        data: { status: "running" },
      });

      await prisma.consoleLog.create({
        data: {
          serverId: req.params.id,
          message: `Server started by user`,
          type: "info",
        },
      });

      res.json({ success: true, message: "Server started successfully" });
    } catch (error: any) {
      console.error("Error starting server:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/stop",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server has no container ID" });
      }

      console.log(
        `Stopping server: ${server.name} (Container: ${
          server.containerId || "none"
        })`
      );

      await NodeAPI.stopServer(req.params.id);

      await prisma.server.update({
        where: { id: req.params.id },
        data: { status: "stopped" },
      });

      await prisma.consoleLog.create({
        data: {
          serverId: req.params.id,
          message: `Server stopped by user`,
          type: "info",
        },
      });

      res.json({ success: true, message: "Server stopped successfully" });
    } catch (error: any) {
      console.error("Error stopping server:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/restart",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server has no container ID" });
      }

      console.log(
        `Restarting server: ${server.name} (Container: ${
          server.containerId || "none"
        })`
      );

      await NodeAPI.restartServer(req.params.id);

      await prisma.consoleLog.create({
        data: {
          serverId: req.params.id,
          message: `Server restarted by user`,
          type: "info",
        },
      });

      res.json({ success: true, message: "Server restarted successfully" });
    } catch (error: any) {
      console.error("Error restarting server:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/server/:id/logs",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.json({
          success: false,
          error: "Server has no container ID",
          logs: "Server not created yet",
        });
      }

      console.log(
        `[Logs] Getting logs for server: ${server.name} (Container: ${server.containerId})`
      );

      try {
        const daemonLogs = await NodeAPI.getServerLogs(req.params.id);

        console.log(`[Logs] Daemon response:`, daemonLogs);

        if (daemonLogs && daemonLogs.success !== false) {
          return res.json({
            success: true,
            logs: daemonLogs.logs || "No logs from daemon",
            count: daemonLogs.count || 0,
            source: "daemon",
          });
        } else {
          const dbLogs = await prisma.consoleLog.findMany({
            where: { serverId: req.params.id },
            orderBy: { createdAt: "desc" },
            take: 100,
          });

          const logMessages = dbLogs.map((log) => log.message).join("\n");
          return res.json({
            success: true,
            logs: logMessages || "No logs available",
            count: dbLogs.length,
            source: "database",
            warning: "Using panel database logs (daemon unavailable)",
          });
        }
      } catch (daemonError: any) {
        console.error(`[Logs] Daemon error:`, daemonError.message);

        const dbLogs = await prisma.consoleLog.findMany({
          where: { serverId: req.params.id },
          orderBy: { createdAt: "desc" },
          take: 100,
        });

        const logMessages = dbLogs.map((log) => log.message).join("\n");
        return res.json({
          success: true,
          logs:
            logMessages ||
            "No logs available (daemon error: " + daemonError.message + ")",
          count: dbLogs.length,
          source: "database-fallback",
          error: daemonError.message,
        });
      }
    } catch (error: any) {
      console.error("Error in logs endpoint:", error);
      res.json({
        success: false,
        error: error.message,
        logs: "Error fetching logs",
      });
    }
  }
);

app.get(
  "/server/:id/stats",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.json({
          success: false,
          error: "Server has no container ID",
        });
      }

      const stats = await NodeAPI.getServerStats(req.params.id);

      res.json({ success: true, stats });
    } catch (error: any) {
      console.error("Error getting server stats:", error);
      res.json({ success: false, error: error.message });
    }
  }
);

app.post(
  "/server/:id/command",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { command } = req.body;

      if (!command || command.trim() === "") {
        return res.status(400).json({ error: "Command cannot be empty" });
      }

      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server has no container ID" });
      }

      console.log(`Running command on server ${server.name}: ${command}`);

      const result = await NodeAPI.runCommand(req.params.id, command);

      await prisma.consoleLog.create({
        data: {
          serverId: req.params.id,
          message: `> ${command}`,
          type: "command",
        },
      });

      if (result.output) {
        await prisma.consoleLog.create({
          data: {
            serverId: req.params.id,
            message: result.output,
            type: "info",
          },
        });
      }

      res.json({ success: true, output: result.output });
    } catch (error: any) {
      console.error("Error running command:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/create",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { name, type, version, memory, cpu, nodeId } = req.body;

      const node = await prisma.node.findUnique({ where: { id: nodeId } });
      if (!node) {
        return res.status(400).json({ error: "Node not found" });
      }

      const userServers = await prisma.server.count({
        where: { userId: req.session.userId },
      });

      if (userServers >= 5) {
        return res
          .status(400)
          .json({ error: "Server limit reached (5 servers max)" });
      }

      const containerName = `mc-${name
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "-")}-${Date.now()}`;
      const port = 25565 + userServers;

      const containerData = {
        name: containerName,
        image: "itzg/minecraft-server",
        memory: parseInt(memory) || 1024,
        cpu: parseInt(cpu) || 100,
        port: port,
        env: ["EULA=TRUE", `VERSION=${version || "1.20.1"}`],
      };

      console.log(`Creating server container: ${containerName}`);

      const containerResult = await NodeAPI.createServer(nodeId, containerData);

      const userId = req.session.userId as string;

      const server = await prisma.server.create({
        data: {
          name,
          type: type || "minecraft",
          version: version || "1.20.1",
          port: port,
          memory: parseInt(memory) || 1024,
          cpu: parseInt(cpu) || 100,
          containerId: containerResult.id,
          nodeId,
          userId: userId,
          status: "stopped",
        },
      });

      res.json({
        success: true,
        serverId: server.id,
        message: "Server created successfully",
      });
    } catch (error: any) {
      console.error("Error creating server:", error);
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/files/upload",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { filePath, fileName, fileData, encoding } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      if (encoding === "base64" && fileData.length > 15 * 1024 * 1024) {
        return res.status(400).json({ error: "File too large (max 10MB)" });
      }

      const result = await NodeAPI.uploadFile(
        server.id,
        filePath,
        fileName,
        fileData,
        encoding || "base64"
      );

      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/server/:id/files/delete",
  requireAuth,
  async (req: express.Request, res: express.Response) => {
    try {
      const { filePath } = req.body;
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server || server.userId !== req.session.userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server not created" });
      }

      const filesResponse = await NodeAPI.getServerFiles(server.id, filePath);

      if (filesResponse.success && filesResponse.isFile !== true) {
        return res
          .status(400)
          .json({ error: "Cannot delete directories via API yet" });
      }

      const result = await NodeAPI.deleteFile(server.id, filePath);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

// ============== ADMIN ROUTES ==============

app.get(
  "/admin/overview",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const users = await prisma.user.count();
    const servers = await prisma.server.count();
    const nodes = await prisma.node.count();

    const recentLogs = await prisma.consoleLog.findMany({
      orderBy: { createdAt: "desc" },
      take: 10,
    });

    res.render("admin/overview/overview", {
      settings,
      user: req.user,
      stats: { users, servers, nodes },
      recentLogs,
    });
  }
);

app.get(
  "/admin/nodes",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const nodes = await prisma.node.findMany({ include: { servers: true } });
    res.render("admin/nodes/nodes", { settings, user: req.user, nodes });
  }
);

app.get(
  "/admin/nodes/create",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    res.render("admin/nodes/create", { settings, user: req.user });
  }
);

app.post(
  "/admin/nodes/create",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const { name, cpu, ram, location, host, port } = req.body;
    const { v4: uuidv4 } = require("uuid");

    await prisma.node.create({
      data: {
        name,
        cpu: parseInt(cpu),
        ram: parseInt(ram),
        location,
        host: host || "localhost",
        port: parseInt(port) || 8080,
        key: uuidv4(),
      },
    });

    res.redirect("/admin/nodes?success=Node created successfully");
  }
);

app.get(
  "/admin/nodes/:id/edit",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const node = await prisma.node.findUnique({ where: { id: req.params.id } });
    res.render("admin/nodes/edit", { settings, user: req.user, node });
  }
);

app.post(
  "/admin/nodes/:id/edit",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const { name, cpu, ram, location, host, port } = req.body;
    await prisma.node.update({
      where: { id: req.params.id },
      data: {
        name,
        cpu: parseInt(cpu),
        ram: parseInt(ram),
        location,
        host: host || "localhost",
        port: parseInt(port) || 8080,
      },
    });
    res.redirect("/admin/nodes?success=Node updated");
  }
);

app.post(
  "/admin/nodes/:id/delete",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    await prisma.node.delete({ where: { id: req.params.id } });
    res.redirect("/admin/nodes?success=Node deleted");
  }
);

app.get(
  "/admin/nodes/:id/test",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    try {
      const node = await prisma.node.findUnique({
        where: { id: req.params.nodeId || req.params.id },
      });

      if (!node) {
        return res.json({ error: "Node not found" });
      }

      const testUrl = `http://${node.host || "localhost"}:${
        node.port || 8080
      }/health`;

      console.log(`Testing connection to: ${testUrl}`);
      console.log(`Using node key: ${node.key.substring(0, 20)}...`);

      let response;
      let usedHeader = "";

      try {
        response = await axios.get(testUrl, {
          headers: { "x-node-key": node.key },
          timeout: 5000,
        });
        usedHeader = "x-node-key";
      } catch (error1: any) {
        console.log("x-node-key failed, trying x-api-key...");
        try {
          response = await axios.get(testUrl, {
            headers: { "x-api-key": node.key },
            timeout: 5000,
          });
          usedHeader = "x-api-key";
        } catch (error2: any) {
          console.log("x-api-key failed, trying configure key...");
          try {
            response = await axios.get(testUrl, {
              headers: { "x-api-key": "b29fcba0-adb0-4cc3-ac4f-4abe3579b96c" },
              timeout: 5000,
            });
            usedHeader = "x-api-key (configure)";
          } catch (error3: any) {
            throw new Error(
              `All authentication attempts failed. Last error: ${error3.message}`
            );
          }
        }
      }

      res.json({
        success: true,
        node: node.name,
        host: node.host,
        port: node.port,
        testUrl,
        usedHeader,
        status: response.data,
        servers: await prisma.server.count({ where: { nodeId: node.id } }),
      });
    } catch (error: any) {
      res.json({ success: false, error: error.message });
    }
  }
);

app.get(
  "/admin/users",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const users = await prisma.user.findMany({ include: { servers: true } });
    res.render("admin/users/users", { settings, user: req.user, users });
  }
);

app.get(
  "/admin/users/create",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    res.render("admin/users/create", { settings, user: req.user });
  }
);

app.post(
  "/admin/users/create",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const { username, email, password, isAdmin } = req.body;

    await prisma.user.create({
      data: {
        username,
        email,
        password: bcrypt.hashSync(password, 10),
        isAdmin: isAdmin === "yes",
      },
    });

    res.redirect("/admin/users?success=User created");
  }
);

app.post(
  "/admin/users/:id/delete",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    await prisma.user.delete({ where: { id: req.params.id } });
    res.redirect("/admin/users?success=User deleted");
  }
);

app.get(
  "/admin/servers",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const servers = await prisma.server.findMany({
      include: { node: true, user: true },
    });
    res.render("admin/servers/servers", { settings, user: req.user, servers });
  }
);

app.get(
  "/admin/servers/create",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    const nodes = await prisma.node.findMany();
    const users = await prisma.user.findMany();
    res.render("admin/servers/create", {
      settings,
      user: req.user,
      nodes,
      users,
    });
  }
);

app.post(
  "/admin/servers/create",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const { name, type, version, port, memory, cpu, nodeId, userId } = req.body;

    try {
      const node = await prisma.node.findUnique({ where: { id: nodeId } });
      if (!node) throw new Error("Node not found");

      const containerName = `mc-${name
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "-")}-${Date.now()}`;

      const containerData = {
        name: containerName,
        image: "itzg/minecraft-server",
        memory: parseInt(memory),
        cpu: parseInt(cpu),
        port: parseInt(port),
        env: ["EULA=TRUE", `VERSION=${version || "1.20.1"}`],
      };

      console.log(`[Admin] Creating server container: ${containerName}`);
      console.log(
        `[Admin] Using node: ${node.name} (${node.host}:${node.port})`
      );

      const containerResult = await NodeAPI.createServer(nodeId, containerData);

      const server = await prisma.server.create({
        data: {
          name,
          type: type || "minecraft",
          version: version || "1.20.1",
          port: parseInt(port),
          memory: parseInt(memory),
          cpu: parseInt(cpu),
          containerId: containerResult.id,
          nodeId,
          userId: userId as string,
          status: "stopped",
        },
      });

      res.redirect(
        "/admin/servers?success=Server created with Docker container"
      );
    } catch (error: any) {
      console.error("Error creating server:", error);
      res.redirect(
        `/admin/servers/create?error=${encodeURIComponent(error.message)}`
      );
    }
  }
);

app.post(
  "/admin/servers/:id/start",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server) {
        return res.status(404).json({ error: "Server not found" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server has no container ID" });
      }

      console.log(`[Admin] Starting server: ${server.name}`);

      await NodeAPI.startServer(req.params.id);

      await prisma.server.update({
        where: { id: req.params.id },
        data: { status: "running" },
      });

      res.json({ success: true, message: "Server started" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/admin/servers/:id/stop",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server) {
        return res.status(404).json({ error: "Server not found" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server has no container ID" });
      }

      console.log(`[Admin] Stopping server: ${server.name}`);

      await NodeAPI.stopServer(req.params.id);

      await prisma.server.update({
        where: { id: req.params.id },
        data: { status: "stopped" },
      });

      res.json({ success: true, message: "Server stopped" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/admin/servers/:id/restart",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server) {
        return res.status(404).json({ error: "Server not found" });
      }

      if (!server.containerId) {
        return res.status(400).json({ error: "Server has no container ID" });
      }

      console.log(`[Admin] Restarting server: ${server.name}`);

      await NodeAPI.restartServer(req.params.id);

      res.json({ success: true, message: "Server restarted" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post(
  "/admin/servers/:id/delete",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    try {
      const server = await prisma.server.findUnique({
        where: { id: req.params.id },
        include: { node: true },
      });

      if (!server) {
        return res.status(404).json({ error: "Server not found" });
      }

      if (server.containerId) {
        try {
          await NodeAPI.call(
            server.nodeId,
            `/instances/${server.containerId}`,
            "DELETE"
          );
        } catch (error: any) {
          console.warn(
            `Could not delete container ${server.containerId}:`,
            error.message
          );
        }
      }

      await prisma.server.delete({ where: { id: req.params.id } });

      res.json({ success: true, message: "Server deleted" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get(
  "/admin/settings",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const settings = await getSettings();
    res.render("admin/settings/settings", {
      settings,
      user: req.user,
      success: req.query.success,
    });
  }
);

app.post(
  "/admin/settings",
  requireAdmin,
  async (req: express.Request, res: express.Response) => {
    const { panelName, panelPort, panelIcon } = req.body;
    const settings = await getSettings();

    await prisma.settings.update({
      where: { id: settings.id },
      data: {
        panelName,
        panelPort: parseInt(panelPort),
        panelIcon,
      },
    });

    res.redirect("/admin/settings?success=Settings saved");
  }
);

// ============== API ROUTES ==============

app.get("/api/v1/nodes", async (req, res) => {
  const nodes = await prisma.node.findMany();
  res.json(nodes);
});

app.get("/api/v1/servers", async (req, res) => {
  const servers = await prisma.server.findMany({ include: { node: true } });
  res.json(servers);
});

app.get("/api/v1/health", async (req, res) => {
  const nodeCount = await prisma.node.count();
  const serverCount = await prisma.server.count();
  const userCount = await prisma.user.count();

  res.json({
    status: "ok",
    version: "1.0.0",
    stats: {
      nodes: nodeCount,
      servers: serverCount,
      users: userCount,
    },
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/debug/node-connection", async (req, res) => {
  try {
    const nodes = await prisma.node.findMany();
    const results = [];

    for (const node of nodes) {
      try {
        const response = await axios.get(
          `http://${node.host || "localhost"}:${node.port || 8080}/health`,
          {
            headers: { "x-node-key": node.key },
            timeout: 3000,
          }
        );
        results.push({
          node: node.name,
          status: "online",
          data: response.data,
        });
      } catch (error: any) {
        results.push({
          node: node.name,
          status: "offline",
          error: error.message,
        });
      }
    }

    res.json({ nodes: results });
  } catch (error: any) {
    res.json({ error: error.message });
  }
});

// ============== WEBSOCKET ==============

io.on("connection", (socket) => {
  console.log("Panel WebSocket: Client connected:", socket.id);

  socket.on("join-server", (serverId) => {
    socket.join(`server-${serverId}`);
    console.log(`Panel: Client ${socket.id} joined server ${serverId}`);
  });

  socket.on("console-command", async (data) => {
    const { serverId, command } = data;

    await prisma.consoleLog.create({
      data: { serverId, message: `> ${command}`, type: "command" },
    });

    try {
      const result = await NodeAPI.runCommand(serverId, command);

      io.to(`server-${serverId}`).emit("console-output", {
        message: result.output || "Command executed",
        type: "response",
      });

      await prisma.consoleLog.create({
        data: {
          serverId,
          message: result.output || "Command executed",
          type: "info",
        },
      });
    } catch (error: any) {
      const errorMessage = `Error: ${error.message}`;
      io.to(`server-${serverId}`).emit("console-output", {
        message: errorMessage,
        type: "error",
      });

      await prisma.consoleLog.create({
        data: {
          serverId,
          message: errorMessage,
          type: "error",
        },
      });
    }
  });

  socket.on("disconnect", () => {
    console.log("Panel WebSocket: Client disconnected:", socket.id);
  });
});

// ============== ERROR HANDLING ==============

app.use(async (req: express.Request, res: express.Response) => {
  const settings = await getSettings();
  const isAuthenticated = !!req.session.userId;
  let user = null;

  if (isAuthenticated) {
    user = await prisma.user.findUnique({
      where: { id: req.session.userId },
      select: { id: true, username: true, email: true, isAdmin: true },
    });
  }

  res.status(404).render("error/500", {
    settings,
    errorType: "404",
    originalUrl: req.originalUrl,
    method: req.method,
    isAuthenticated,
    user,
    sessionId: req.session.id,
    message: "Page not found",
  });
});

app.use(
  async (
    error: any,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    console.error("Server error:", error);

    const settings = await getSettings();
    const isAuthenticated = !!req.session.userId;
    let user = null;

    if (isAuthenticated) {
      user = await prisma.user.findUnique({
        where: { id: req.session.userId },
        select: { id: true, username: true, email: true, isAdmin: true },
      });
    }

    let errorType = "500";
    let statusCode = 500;
    let message = error.message || "Internal server error";

    if (error.status === 401) {
      errorType = "auth";
      statusCode = 401;
      message = "Authentication required";
    } else if (error.status === 403) {
      errorType = "admin";
      statusCode = 403;
      message = "Admin access required";
    } else if (error.status === 404) {
      errorType = "404";
      statusCode = 404;
      message = "Page not found";
    }

    res.status(statusCode).render("error/500", {
      settings,
      errorType,
      message,
      originalUrl: req.originalUrl,
      method: req.method,
      isAuthenticated,
      user,
      sessionId: req.session.id,
    });
  }
);

// ============== START SERVER ==============

const PORT = process.env.PANEL_PORT || 3000;

httpServer.listen(PORT, async () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                    ZyperPanel Started                          ║
║              Running on http://localhost:${PORT}                 ║
╚═══════════════════════════════════════════════════════════════╝
  `);
  try {
    console.log("Starting node status monitor...");

    await checkNodeStatus();
    console.log("Node status monitor started");
    await ensureDefaultAdmin();
    await ensureDefaultNode();
    dotenv.config();
    console.log("ENV ADMIN:", {
      email: process.env.DEFAULT_ADMIN_EMAIL,
      username: process.env.DEFAULT_ADMIN_USERNAME,
      password: process.env.DEFAULT_ADMIN_PASSWORD,
    });

    setInterval(async () => {
      try {
        await checkNodeStatus();
      } catch (error) {
        console.error("Error in scheduled status check:", error);
      }
    }, 30000);
  } catch (error) {
    console.error("Failed to start node status monitor:", error);
  }
});

export { app, prisma, io };
