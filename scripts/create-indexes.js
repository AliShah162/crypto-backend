// scripts/create-indexes.js
import mongoose from "mongoose";
import User from "../models/User.js";
import dotenv from "dotenv";
dotenv.config();

async function createIndexes() {
  console.log("🔵 ===== STARTING INDEX CREATION =====");
  console.log(`🔵 Environment: ${process.env.NODE_ENV || 'development'}`);
  
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      maxPoolSize: 50,
      minPoolSize: 10,
    });
    console.log("✅ Connected to MongoDB");

    console.log("\n📊 Creating indexes...");

    // 1. Username - Most frequent query
    await User.collection.createIndex(
      { username: 1 }, 
      { unique: true, background: true }
    );
    console.log("✅ Index 1/8: username (unique)");

    // 2. Email - Login queries
    await User.collection.createIndex(
      { email: 1 }, 
      { background: true }
    );
    console.log("✅ Index 2/8: email");

    // 3. RefKey - Virtual admin lookups
    await User.collection.createIndex(
      { refKey: 1 }, 
      { background: true }
    );
    console.log("✅ Index 3/8: refKey");

    // 4. CreatedAt - Sorting newest users first
    await User.collection.createIndex(
      { createdAt: -1 }, 
      { background: true }
    );
    console.log("✅ Index 4/8: createdAt (descending)");

    // 5. Balance - Dashboard stats
    await User.collection.createIndex(
      { balance: -1 }, 
      { background: true }
    );
    console.log("✅ Index 5/8: balance (descending)");

    // 6. Credit Score - Admin filtering
    await User.collection.createIndex(
      { creditScore: -1 }, 
      { background: true }
    );
    console.log("✅ Index 6/8: creditScore (descending)");

    // 7. Transaction date - History queries
    await User.collection.createIndex(
      { "transactions.date": -1 }, 
      { background: true }
    );
    console.log("✅ Index 7/8: transactions.date (descending)");

    // 8. Deposit status - Admin deposit management
    await User.collection.createIndex(
      { "depositRequests.status": 1 }, 
      { background: true }
    );
    console.log("✅ Index 8/8: depositRequests.status");

    console.log("\n✅ ALL INDEXES CREATED SUCCESSFULLY!");
    
    // Show existing indexes
    const indexes = await User.collection.indexes();
    console.log("\n📋 Current indexes:");
    indexes.forEach((idx, i) => {
      console.log(`  ${i + 1}. ${idx.name}: ${JSON.stringify(idx.key)}`);
    });

    console.log(`\n📊 Total indexes: ${indexes.length}`);
    await mongoose.connection.close();
    console.log("✅ MongoDB connection closed");
    process.exit(0);
  } catch (err) {
    console.error("❌ Error creating indexes:", err);
    await mongoose.connection.close();
    process.exit(1);
  }
}

createIndexes();