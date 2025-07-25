const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, "Please, provide name"],
    minlength: [3, "Name require atleast 3 characters"],
    maxlength: [20, "Name should not exceed 20 characters"],
    match: [
      /^([\w\d.]*[^\w\d.]{0})$/,
      "No special character is allowed for username"
    ]
  },
  email: {
    type: String,
    trim: true,
    required: [true, "Please, provide email"],
    match: [
      /[a-z0-9.]+@[a-z]+\.?[a-z]+?/,
      "Invalid Email"
    ],
    unique: [true, "Email already exists"],
    index: true
  },
  password: {
    type: String,
    required: [true, "Please, provide password"],
    select: false,
  },
  role: {
    type: String,
    default: "user",
    trim: true,
    enum: {
      values: ["user", "admin"],
      message: "Invalid role"
    }
  }
})

// mongoose middleware
userSchema.pre("save", async function(next) {
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  // next("error");
  next();
})

// mongoose instance method
// userSchema.methods.getName = function() {
//   return this.name;
// }

// or
// userSchema.method("getName", function() {
//   return this.name + " hello";
// })

// or
// userSchema.method({
//   getName: function() {
//     return this.name + " hi..";
//   }
// })

userSchema.methods.createJWTToken = function() {
  return jwt.sign(
    {userId: this._id, userName: this.name}, 
    process.env.JWT_SECRET_KEY,
    {expiresIn: process.env.JWT_LIFETIME}
  )
}
userSchema.methods.createJWTRefToken = function() {
  return jwt.sign(
    {userId: this._id, userName: this.name},
    process.env.REFRESH_JWT_SECRET_KEY
  )
}

userSchema.methods.checkPassword = function (password) {
  return bcrypt.compare(password, this.password);
}

const User = mongoose.model("users", userSchema);

module.exports = User;