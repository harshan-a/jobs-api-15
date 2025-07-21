const jwt = require("jsonwebtoken");
const {UnauthorizedError} = require("../errors");
const User = require("../models/userModel");


const authorizationMiddleware = async (req, res, next) => {
  const {authorization} = req.headers;
  const token = authorization && authorization.split(" ")[1];

  if(!token) 
    throw new UnauthorizedError("No token Found");

  try {
    const payLoad = jwt.verify(token, process.env.JWT_SECRET_KEY);
    // const {userId, userName} = payLoad;
    // // const user = await User.findOne({_id: userId});
    // const user = {userId, userName};
    const user = {};
    for(const field in payLoad) {
      if(payLoad.hasOwnProperty(field) && field === "userId" || field === "userName") {
        user[field] = payLoad[field];
      }
    }
    req.user = user;
    // console.log(req.user);
    // res.json(req.user);
    next();

  } catch(err) {
    next(new UnauthorizedError(err.message || "Unauthorized Request"));
  }
}

module.exports = authorizationMiddleware;