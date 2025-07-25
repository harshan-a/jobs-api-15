const User = require("../models/userModel");
const RefToken = require("../models/refTokenModel");
const {
  BadRequestError,
  UnauthorizedError,
} = require("../errors");

const jwt = require("jsonwebtoken");


const {StatusCodes} = require("http-status-codes");
// const bcrypt = require("bcryptjs");
// const jwt = require("jsonwebtoken");

const refToken = async (req, res) => {
  // const token = req.body;
  // console.log(req.header("Origin"));
  const token = req.cookies.refreshToken;
  if(!token) 
    throw new BadRequestError("No Ref Token")

  const refToken = await RefToken.findOne({token});
  if(!refToken) 
    throw new UnauthorizedError("Unauthorized Access");


  jwt.verify(refToken.token, process.env.REFRESH_JWT_SECRET_KEY, (err, user) => {
    if(err) 
      throw new UnauthorizedError("Unauthorized Access")

    const {userId, userName} = user;
    const token = refToken.createJWTToken({userId, userName})
    res.status(200).json({success: true, token});

  })
}

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
  
  const accessToken = user.createJWTToken();
  const refreshToken = user.createJWTRefToken();

  // console.log(user.getName());

  await RefToken.deleteMany({});
  await RefToken.create({token: refreshToken});

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, 
    sameSite: "Strict", //  "None" 
    secure: true, // http = false, https = true
    maxAge: 7 * 24 * 60 * 60 * 1000
  })
  
  res.status(StatusCodes.CREATED).json({success: true, accessToken, data: user, msg: "Registered Successfully"});
}


const login = async (req, res) => {
  
  if(!req.body) 
    throw new BadRequestError("Please, provide credentials");

  const {email, password} = req.body;
  if(!email || !password) throw new BadRequestError("Please, provide email or password");

  const user = await User.findOne({email}, "+password");
  if(!user) 
    throw new UnauthorizedError("User not found");

  const passCheck = await user.checkPassword(password);
  if(!passCheck) 
    throw new UnauthorizedError("Incorrect Password");
  
  const accessToken = user.createJWTToken();
  const refreshToken = user.createJWTRefToken();

  await RefToken.deleteMany({});
  await RefToken.create({token: refreshToken});

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true, 
    sameSite: "Strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
  })
  
  res.status(StatusCodes.OK).json({success: true, accessToken, data: user, msg: "Logged in Successfully"});
}

module.exports = {login, register, refToken};
