const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { initialiseDatabase } = require("./db/db.connect.js");
const User = require("./models/users.model.js");
const Post = require("./models/post.model.js");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
const allowedOrigins = [
  "http://localhost:5173/",
  "https://playground-022-frontend.vercel.app/",
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

app.options("*", cors(corsOptions));
app.use(cookieParser());

initialiseDatabase();

const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

app.post("/auth/register", async (req, res) => {
  const { username, name, password, email } = req.body;

  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      name,
      email,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ message: "Error registering user", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      }
    );

    res.cookie("access_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 25 * 60 * 60 * 1000,
      path: "/",
    });

    res.json({ message: "Logged in successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

app.get("/auth/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error fetch in", error: error.message });
  }
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("access_token");
  res.json({ message: "Logged out successfully" });
});

app.post("/posts", verifyToken, async (req, res) => {
  const { title, image, content } = req.body;
  const userId = req.user.id;

  try {
    const newPost = new Post({
      title,
      image,
      content,
      author: userId,
    });

    const savedPost = await newPost.save();

    res.status(201).json({ message: "Posted", post: savedPost });
  } catch (error) {
    res.status(500).json({ message: "Error posting", error: error.message });
  }
});

app.get("/posts", async (req, res) => {
  try {
    const posts = await Post.find().populate("author", "username name");
    res.json({ posts });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error getting posts", error: error.message });
  }
});

app.put("/posts/:id", verifyToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    if (post.author.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorised to update the post" });
    }

    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );

    res.json({ message: "Post updated successfully", post: updatedPost });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating posts", error: error.message });
  }
});

app.delete("/posts/:id", verifyToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: "Post not found" });
    }

    if (post.author.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorised to delete the post" });
    }

    await Post.findByIdAndDelete(req.params.id);

    res.json({ message: "Post deleted successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating posts", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
