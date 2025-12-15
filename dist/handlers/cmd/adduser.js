"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const readline_1 = __importDefault(require("readline"));
const prisma = new client_1.PrismaClient();
const rl = readline_1.default.createInterface({
    input: process.stdin,
    output: process.stdout
});
const question = (prompt) => {
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
    const hashedPassword = bcryptjs_1.default.hashSync(password, 10);
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
    }
    catch (error) {
        console.error('Error creating user:', error.message);
    }
    rl.close();
    await prisma.$disconnect();
}
main();
