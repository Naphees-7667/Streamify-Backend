import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const connectDB = async () => {
    try {
        const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URI}`, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("\nMongoDB Connected:", connectionInstance.connection.host, "\n");
    } catch (err) {
        console.error("MongoDB Connection Failed:", err.message);
        process.exit(1);
    }
}

export default connectDB;
