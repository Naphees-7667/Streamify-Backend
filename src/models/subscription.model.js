import mongoose from "mongoose";

const subscriptionSchema = new mongoose.Schema({
    subscriber:{
        type:mongoose.Schema.Types.ObjectId,//one who is subscribing
        ref:"User",
        required:true
    },
    channel:{
        type:mongoose.Schema.Types.ObjectId,//one who is subscribed
        ref:"User",
        required:true
    }
},{timestamps:true});

const Subscription = mongoose.model("Subscription",subscriptionSchema);

export default Subscription;