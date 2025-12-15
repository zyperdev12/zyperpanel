/*
  Warnings:

  - Added the required column `updatedAt` to the `Server` table without a default value. This is not possible if the table is not empty.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_ConsoleLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "serverId" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'info',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ConsoleLog_serverId_fkey" FOREIGN KEY ("serverId") REFERENCES "Server" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_ConsoleLog" ("createdAt", "id", "message", "serverId", "type") SELECT "createdAt", "id", "message", "serverId", "type" FROM "ConsoleLog";
DROP TABLE "ConsoleLog";
ALTER TABLE "new_ConsoleLog" RENAME TO "ConsoleLog";
CREATE TABLE "new_Server" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'minecraft',
    "version" TEXT NOT NULL DEFAULT '1.20.1',
    "port" INTEGER NOT NULL,
    "memory" INTEGER NOT NULL,
    "cpu" INTEGER NOT NULL,
    "containerId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'stopped',
    "nodeId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Server_nodeId_fkey" FOREIGN KEY ("nodeId") REFERENCES "Node" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Server_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);
INSERT INTO "new_Server" ("containerId", "cpu", "createdAt", "id", "memory", "name", "nodeId", "port", "status", "type", "userId", "version") SELECT "containerId", "cpu", "createdAt", "id", "memory", "name", "nodeId", "port", "status", "type", "userId", "version" FROM "Server";
DROP TABLE "Server";
ALTER TABLE "new_Server" RENAME TO "Server";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
