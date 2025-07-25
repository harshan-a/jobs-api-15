const mongoose = require("mongoose");
const { Schema } = mongoose;
const jwt = require("jsonwebtoken");

const schema = new Schema({
  token: {
    type: String,
    required: true,
    index: true,
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

module.exports = mongoose.model("refresh-token", schema);