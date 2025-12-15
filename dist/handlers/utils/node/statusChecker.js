"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkNodeStatus = checkNodeStatus;
const client_1 = require("@prisma/client");
const axios_1 = __importDefault(require("axios"));
const prisma = new client_1.PrismaClient();
async function checkNodeStatus() {
    const nodes = await prisma.node.findMany();
    for (const node of nodes) {
        try {
            const response = await axios_1.default.get(`http://${node.host}:${node.port}/health`, {
                timeout: 5000,
                headers: {
                    "x-api-key": node.key,
                },
            });
            if (response.data.status === "ok") {
                await prisma.node.update({
                    where: { id: node.id },
                    data: { status: "online" },
                });
            }
            else {
                await prisma.node.update({
                    where: { id: node.id },
                    data: { status: "offline" },
                });
            }
        }
        catch (error) {
            await prisma.node.update({
                where: { id: node.id },
                data: { status: "offline" },
            });
        }
    }
}
// Run status check every 30 seconds
setInterval(checkNodeStatus, 30000);
