require("dotenv").config();
const router = require("express").Router();
const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
//Add a User
router.post("/register", async (req, res) => {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);
  try {
    const newUser = new User({
      name: req.body.name,
      username: req.body.username,
      password: hashedPassword,
      phoneNumber: req.body.phoneNumber,
    });
    const user = await newUser.save();
    res.status(200).json({
      message: "User successfully registered",
      id: user._id,
    });
  } catch (err) {
    res.status(500).json({ message: "Username already exist" });
  }
});
//Login the user
router.post("/login", async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
  });

  if (!user) {
    return { status: "error", error: "Invalid login" };
  }
  const isPasswordValid = await bcrypt.compare(
    req.body.password,
    user.password
  );
  if (isPasswordValid) {
    const token = jwt.sign(
      {
        _id: user._id,
        name: user.name,
        username: user.username,
      },
      `${process.env.SECRET_TOKEN}`
    );
    return res.json({ status: "ok", userid: user._id, jwttoken: token });
  } else {
    return res.json({ status: "error", user: false });
  }
});
//The homepage cookie storage
router.get("/homepage", async (req, res) => {
  const token = req.headers.authorization;

  try {
    const decoded = jwt.verify(token, `${process.env.SECRET_TOKEN}`);
    const username = decoded.username;
    const user = await User.findOne({ username: username });

    return res.json({ status: "ok" });
  } catch (error) {
    res.json({ status: "error", error: error });
  }
});

module.exports = router;
