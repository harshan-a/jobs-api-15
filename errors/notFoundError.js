const {StatusCodes} = require("http-status-codes");

const CustomError = require("./customError");



class NotFoundError extends CustomError {
  constructor(msg) {
    super(msg);
    this.statusCode = StatusCodes.NOT_FOUND;
  }
}

module.exports = NotFoundError;