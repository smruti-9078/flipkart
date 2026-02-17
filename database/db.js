import mongoose from "mongoose";
import 'dotenv/config'

const connectDB = async() =>{
    try{
        await mongoose.connect(`${process.env.MONGO_URI}/flipkart`)
        console.log('MongoDB connect successfully')
    
    }catch (error){
        console.log("MongoDB connection failed:", error);
    }
}
export default connectDB