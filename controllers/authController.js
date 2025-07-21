const User = require("../models/userModel");
const {
  BadRequestError,
  UnauthorizedError,
} = require("../errors");


const {StatusCodes} = require("http-status-codes");
// const bcrypt = require("bcryptjs");
// const jwt = require("jsonwebtoken");


const register = async (req, res) => {
  if(!req.body) 
    throw new BadRequestError("Please, provide credentials");
  
  // const clientData = req.body;
  
  // hash the password;
  // const {password} = clientData;
  // if(!password) 
  //   throw new BadRequestError("Please, provide password");

  // const saltRound = 10;
  // const salt = await bcrypt.genSalt(saltRound);
  // const hashedPassword = await bcrypt.hash(password, salt);
  // const saltRound = 10;
  // const hashedPassword = await bcrypt.hash(password, saltRound);

  // clientData.password = hashedPassword;

  const user = await User.create(req.body);
  
  const token = user.createJWTToken();

  // console.log(user.getName());

  res.status(StatusCodes.CREATED).json({success: true, token, data: user});
}


const login = async (req, res) => {
  if(!req.body) 
    throw new BadRequestError("Please, provide credentials");

  const {email, password} = req.body;

  const user = await User.findOne({email}, "+password");
  if(!user) 
    throw new UnauthorizedError("User not found");

  const passCheck = await user.checkPassword(password);
  if(!passCheck) 
    throw new UnauthorizedError("Incorrect Password");

  const token = user.createJWTToken();

  res.status(StatusCodes.OK).json({success: true, token, data: user});
}

module.exports = {login, register};
