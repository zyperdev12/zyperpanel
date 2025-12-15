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