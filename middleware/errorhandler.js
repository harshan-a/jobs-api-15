const {StatusCodes} = require("http-status-codes");
// const {CustomError} = require("../errors");

const errorHandlerMiddlerware = (err, req, res, next) => {
  console.log(err);

  const customError = {
    msg: err.message || "Something went wrong, please try again later",

    statusCode: err.StatusCode || StatusCodes.INTERNAL_SERVER_ERROR,
  }

  // if(err instanceof CustomError) {
  //   return res.status(err.statusCode).json({msg: err.message});
  // }

  if(err.code && err.code === 11000) {
    const field = Object.keys(err.keyValues);
    customError.msg = `Duplication occur on${field}`;
    customError.statusCode = StatusCodes.BAD_REQUEST;
  }

  if(err.name === "ValidationError") {
    // const fields = [];
    // for(let field in obj = err.errors) {
    //   if(fields.includes(field)) {
    //     return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({msg: obj[field].message});
    //   }
    // }

    const message = Object.values(err.errors).map(err => err.message).join(" & ");
    
    customError.msg = message;
    customError.statusCode = StatusCodes.BAD_REQUEST;
  }

  if(err.name === "CastError") {
    customError.msg = `No item found with id ${err.value}`
    customError.statusCode = StatusCodes.BAD_REQUEST;
  }

  res
    .status(customError.statusCode)
    .json({ msg: customError.msg , err });
}

module.exports = errorHandlerMiddlerware;