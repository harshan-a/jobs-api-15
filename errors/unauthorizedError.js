const {StatusCodes} = require("http-status-codes");

const CustomError = require("./customError");


class UnauthorizedError extends CustomError {
  constructor(msg) {
    super(msg);
    this.statusCode = StatusCodes.UNAUTHORIZED;
  }
}

module.exports = UnauthorizedError;