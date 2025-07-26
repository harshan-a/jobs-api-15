require("dotenv").config();
// require("./models/jobModel");


const express = require("express");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 5000;
const connectDB = require("./db/connect");

const cors = require("cors"); // cross-origin-resource-sharing;
const helmet = require("helmet");
// const xssClean = require("xss-clean");
const { xss } = require("express-xss-sanitizer");
const rateLimiter = require("express-rate-limit");

const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const swaggerDocument = YAML.load("./swagger.yaml");
// console.log(swaggerDocument);


// import middleware
const errorHandlerMiddleware = require("./middleware/errorhandler");
const notFoundMiddleware = require("./middleware/notFound");
const authorizationMiddleware = require("./middleware/auth");

// import routers
const authRouter = require("./routers/authRouter");
const jobsRouter = require("./routers/jobsRouter");



// common middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.static("./public"));



// security middlewares
// app.use(rateLimiter({
//   windowMS: 10 * 60 * 1000, // 10 min
//   max: 5, // allow only 5 req for each IP within 10min;
// }))
app.use(helmet()); // enhance security by setting various HTTP headers;
app.use(cors({
  origin: ["http://localhost:4000", "http://localhost:5000"]
})) // allow server to server communication;
// app.use(xssClean()); // sanitize the user input such as req.body, req.params, req.query, req.header and so on to prevent from cross-site-scripting(xss). But this xss-clean lib is no longer supported, so we use express-xss-sanitizer;
app.use(xss());

// app.get("/hello", (req, res) => {
//   // console.log(req.get("origin"));
//   console.log(req.header("Origin"));
//   res.send("hello, world!!!");
// })

// routers
app.use("/api/v1/auth", rateLimiter({ windowMs: 1000 * 60 * 15, max: 15 }), authRouter);
app.use("/api/v1/jobs", authorizationMiddleware, jobsRouter);

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
// swaggerUi.serve - is used for serve the static file like css and server the structure
// swaggerUi.setup - is used for setup our content 


// error handling middleware
app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);


// start server
const start = async () => {
  try {
    const db = await connectDB(process.env.MONGO_URI);
    db && console.log("CONNECTED TO DATABASE");

    app.listen(PORT, err => {
      if (err) throw err;
      console.log(`Server is running on port ${PORT}...`);
    })

  } catch (err) {
    console.log(err);
  }
}
start();
