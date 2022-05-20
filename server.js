const express = require("express");
const mongoose = require("mongoose");
const userModel = require("./model/userModel.js");
const bcrypt = require("bcryptjs");
const path = require("path");
const app = express();
const jwt = require("jsonwebtoken");

const JWT_SECRET =
  "sfghkalj BHDLH ljg dojaskgn 9YWER5T9GH2xdcjba ajdgbajdjkejf nw ioeu0whojsbng";

mongoose.connect("mongodb://localhost:27017/jwt-auth-app", () => {
  console.log("database connected..");
});

app.use("/", express.static(path.join(__dirname, "static")));
app.use(express.json());

app.post("/api/register", async (req, res) => {
  const username = req.body.username;
  const enteredPassword = req.body.password;

  if (!username || typeof username !== "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }
  if (!enteredPassword || typeof enteredPassword !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }
  if (enteredPassword.length < 5) {
    return res.json({
      status: "error",
      error: "Password is too short. should be atleast 5 characters",
    });
  }
  const password = await bcrypt.hash(enteredPassword, 10);

  try {
    console.log(username, password);
    const resp = await userModel.create({ username, password });
    console.log(resp);
  } catch (error) {
    if (error.code === 11000) {
      return res.json({ status: "error", error: "username already in use" });
    }
    throw error;
  }

  res.json({ status: "OK" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await userModel.findOne({ username }).lean();

  if (!user) {
    return res.json({ status: "error", error: "invalid password/username" });
  }

  if (await bcrypt.compare(password, user.password)) {
    //console.log(await bcrypt.compare(password, user.password));
    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
      },
      JWT_SECRET
    );

    return res.json({ status: "OK", data: token });
  }

  res.json({ status: "error", error: "invalid password/username" });
});

app.post("/api/change-password", async (req, res) => {
  const { token, newpassword: enteredPassword } = req.body;

  if (!enteredPassword || typeof enteredPassword !== "string") {
    return res.json({ status: "error", error: "Invalid password" });
  }
  if (enteredPassword.length < 5) {
    return res.json({
      status: "error",
      error: "Password is too short. should be atleast 5 characters",
    });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    console.log("jwt decoded", user);

    //get user id from token
    const _id = user.id;

    //hash new password
    const password = await bcrypt.hash(enteredPassword, 10);

    //find user using retrieved id and update the password
    await userModel.updateOne(
      { _id },
      {
        $set: { password },
      }
    );
    res.json({ status: "OK" });
  } catch (error) {
    res.json({ status: "error", error: "errrorrr" });
  }
});

app.listen(5000, () => {
  console.log("server running on port 5000..");
});
