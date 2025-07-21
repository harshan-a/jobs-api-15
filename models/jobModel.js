const mongoose = require("mongoose");
const {Schema} = mongoose;

// console.log(mongoose.Types.ObjectId)
// console.log("--------------------------------------")
// console.log(Schema.Types.ObjectId);

const jobsSchema = new Schema({
  company: {
    type: String,
    required: [true, "Please, provide company name"],
    trim: true,
    maxlengeth: [30, "Company name do not exceeds 30 characters"]
  },
  position: {
    type: String,
    required: [true, "Please, provide position"],
    trim: true,
    maxlength: [50, "Position do not exceeds 50 characters"]
  },
  status: {
    type: String,
    required: [true, "Please, provide status"],
    enum: {
      values: ["interview", "pending", "declined"],
      message: "Invalid status"
    },
    trim: true,
    default: "pending"
  },
  createdBy: {
    type: mongoose.Types.ObjectId,
    ref: "users",
    required: [true, "Please, provide user"],
  }
}, {timestamps: true});

module.exports = mongoose.model("jobs", jobsSchema);