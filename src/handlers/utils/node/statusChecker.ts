import { PrismaClient } from "@prisma/client";
import axios from "axios";

const prisma = new PrismaClient();

export async function checkNodeStatus() {
  const nodes = await prisma.node.findMany();

  for (const node of nodes) {
    try {
      const response = await axios.get(
        `http://${node.host}:${node.port}/health`,
        {
          timeout: 5000,
          headers: {
            "x-api-key": node.key,
          },
        }
      );

      if (response.data.status === "ok") {
        await prisma.node.update({
          where: { id: node.id },
          data: { status: "online" },
        });
      } else {
        await prisma.node.update({
          where: { id: node.id },
          data: { status: "offline" },
        });
      }
    } catch (error) {
      await prisma.node.update({
        where: { id: node.id },
        data: { status: "offline" },
      });
    }
  }
}

// Run status check every 30 seconds
setInterval(checkNodeStatus, 30000);
