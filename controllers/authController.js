const User = require("../models/userModel");
const RefToken = require("../models/refTokenModel");
const {
  BadRequestError,
  UnauthorizedError,
} = require("../errors");

const jwt = require("jsonwebtoken");


const { StatusCodes } = require("http-status-codes");
// const bcrypt = require("bcryptjs");
// const jwt = require("jsonwebtoken");

const refToken = async (req, res, next) => {
  // const token = req.body;
  // console.log(req.header("Origin"));
  const token = req.cookies.refreshToken;
  if (!token)
    throw new BadRequestError("No Refresh Token Found");

  const refToken = await RefToken.findOne({ token });
  if (!refToken)
    throw new UnauthorizedError("Unauthorized Access. Token no longer used");

  jwt.verify(refToken.token, process.env.REFRESH_JWT_SECRET_KEY, async (err, user) => {
    try {
      if (err)
        throw new UnauthorizedError("Unauthorized Access. " + err.message);

      const { userId, userName } = user;
      const newRefToken = refToken.createJWTRefToken({ userId, userName });
      const token = refToken.createJWTToken({ userId, userName })

      if (userId !== String(refToken.userId)) {
        throw new UnauthorizedError("Unauthorized Access. User id not match.");
      }
      refToken.token = newRefToken;
      await refToken.save();

      res.cookie("refreshToken", newRefToken, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
      })

      res.status(200).json({ success: true, token });

    } catch (err) {
      next(err);
    }
  })

}

const register = async (req, res) => {
  if (!req.body)
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

  let user = await User.create(req.body);

  const accessToken = user.createJWTToken();
  const refreshToken = user.createJWTRefToken();

  // console.log(user.getName());

  // const refToken = await RefToken.findOne({userId: user._id});
  // if(refToken) {
  //   refToken.token = refreshToken;
  //   await refToken.save();

  // } else {
  //   await RefToken.create({token: refreshToken, userId: user._id});
  // }

  await RefToken.findOneAndUpdate({ userId: user._id }, { token: refreshToken }, {
    runValidators: true,
    new: true,
    upsert: true,
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    sameSite: "Strict", //  "None" 
    secure: true, // http = false, https = true
    maxAge: 7 * 24 * 60 * 60 * 1000
  })


  user = user.toObject();
  delete user.password;
  res.status(StatusCodes.CREATED).json({ success: true, accessToken, data: user, msg: "Registered Successfully" });
}

const login = async (req, res) => {
  if (!req.body)
    throw new BadRequestError("Please, provide credentials");

  const { email, password } = req.body;
  if (!email || !password) throw new BadRequestError("Please, provide email or password");

  let user = await User.findOne({ email }, "+password");
  if (!user)
    throw new UnauthorizedError("User not found");

  const passCheck = await user.checkPassword(password);
  if (!passCheck)
    throw new UnauthorizedError("Incorrect Password");

  const accessToken = user.createJWTToken();
  const refreshToken = user.createJWTRefToken();



  // const refToken = await RefToken.findOne({userId: user._id});
  // if(refToken) {
  //   refToken.token = refreshToken;
  //   await refToken.save();

  // } else {
  //   await RefToken.create({token: refreshToken, userId: user._id});
  // }
  await RefToken.findOneAndUpdate({ userId: user._id }, { token: refreshToken }, {
    runValidators: true,
    new: true,
    upsert: true,
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
  })


  user = user.toObject();
  // const obj = {};
  // for(const field in user) {
  //   if(field === "password") continue;
  //   obj[field] = user[field];
  // }
  delete user.password;

  res.status(StatusCodes.OK).json({ success: true, accessToken, data: user, msg: "Logged in Successfully" });
}

module.exports = { login, register, refToken };
