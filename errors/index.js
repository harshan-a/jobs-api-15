const [
  CustomError,
  BadRequestError,
  UnauthorizedError,
  NotFoundError,

] = [ require("./customError.js"), require("./badRequestError.js"), require("./unauthorizedError.js"), require("./notFoundError.js") ];

module.exports = {
  CustomError,
  BadRequestError,
  UnauthorizedError,
  NotFoundError,
}