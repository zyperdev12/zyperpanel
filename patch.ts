// patch.ts - Run this to update all type assertions
const fs = require("fs");
const path = require("path");

const appPath = path.join(__dirname, "src/app.ts");
let content = fs.readFileSync(appPath, "utf-8");

// Add type interface at the top
const interfaceToAdd = `
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
  players?: any[];
  plugins?: any[];
}
`;

// Insert after the imports
const importEnd =
  content.indexOf("dotenv.config();") + "dotenv.config();".length;
content =
  content.slice(0, importEnd) +
  "\n" +
  interfaceToAdd +
  content.slice(importEnd);

// Add type assertions to all findUnique calls
content = content.replace(
  /const server = await prisma\.server\.findUnique\(\{[^}]+include: \{ node: true \}[^}]*\}\);/g,
  "const server = await prisma.server.findUnique({\n    where: { id: req.params.id },\n    include: { node: true }\n  }) as ServerWithContainer;"
);

// Fix specific lines
content = content.replace(
  /if \(!server\.containerId\) \{/g,
  "if (!server.containerId) {"
);

// Fix the console log lines
content = content.replace(
  /Container: \$\{server\.containerId\}/g,
  'Container: ${server.containerId || "none"}'
);

// Fix the create server lines
content = content.replace(
  /containerId: containerResult\.id,/g,
  "containerId: containerResult.id,"
);

// Fix error handling
content = content.replace(/error\.message/g, "(error as any).message");

fs.writeFileSync(appPath, content);
console.log("Patched app.ts with type assertions");
