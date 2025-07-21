const mongoose = require("mongoose");


module.exports = connectDB = (uri) => mongoose.connect(uri);