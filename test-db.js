// test-db.mjs
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from current directory
dotenv.config({ path: join(__dirname, '.env') });

console.log('Testing MongoDB connection...');
console.log('MONGO_URI exists?', !!process.env.MONGO_URI);

if (!process.env.MONGO_URI) {
    console.error('❌ MONGO_URI not found in .env file!');
    process.exit(1);
}

// Hide password in log
const hiddenUri = process.env.MONGO_URI.replace(/:[^:@]+@/, ':****@');
console.log('Using URI:', hiddenUri);

try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ Connected successfully!');
    await mongoose.disconnect();
    process.exit(0);
} catch (err) {
    console.error('❌ Connection failed:', err.message);
    process.exit(1);
}