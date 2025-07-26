const mongoose = require("mongoose");
const { Schema } = mongoose;
const jwt = require("jsonwebtoken");

const schema = new Schema({
  token: {
    type: String,
    required: true,
    // index: true,
  }, 
  userId: {
    type: mongoose.Types.ObjectId,
    ref: "users",
    required: [true, "Please, provide user id for refresh token"],

  }
})


// instance method 
schema.methods.createJWTToken = (payLoad) => {
  return jwt.sign(
    payLoad, 
    process.env.JWT_SECRET_KEY, 
    {expiresIn: process.env.JWT_LIFETIME}
  );
}

schema.methods.createJWTRefToken = (payLoad) => {
  return jwt.sign(
    payLoad,
    process.env.REFRESH_JWT_SECRET_KEY,
    {expiresIn: process.env.JWT_LIFETIME}
  )
}



module.exports = mongoose.model("refresh-token", schema);