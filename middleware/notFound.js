const {StatusCodes, ReasonPhrases} = require("http-status-codes");

const notFoundMiddleware = (req, res) => {
  res
    .status(StatusCodes.NOT_FOUND)
    .send(StatusCodes.NOT_FOUND + "-" + ReasonPhrases.NOT_FOUND);
}

module.exports = notFoundMiddleware;