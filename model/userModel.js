const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  { collection: "users" }
);

const userModel = mongoose.model("userModel", userSchema);

module.exports = userModel;
