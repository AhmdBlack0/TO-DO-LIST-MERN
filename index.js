const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ======================
// Mongoose Schemas
// ======================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});

const User = mongoose.model("User", userSchema);
const Task = mongoose.model("Task", taskSchema);

// ======================
// Auth Middleware
// ======================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = decoded; // { id, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// ======================
// Auth Routes
// ======================

// Register
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashedPassword });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1h" }
    );
    res.status(201).json({ token });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "1h" }
    );
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ======================
// Task Routes (Protected)
// ======================

// Create Task
app.post("/api/tasks", authMiddleware, async (req, res) => {
  const { title, description } = req.body;
  const userId = req.user.id;

  try {
    const task = await Task.create({ title, description, user: userId });
    res.status(201).json(task);
  } catch (error) {
    res.status(500).json({ error: "Failed to create task" });
  }
});

// Get Tasks
app.get("/api/tasks", authMiddleware, async (req, res) => {
  try {
    const tasks = await Task.find({ user: req.user.id });
    res.status(200).json(tasks);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});

// Optional: Delete Task
app.delete("/api/tasks/:id", authMiddleware, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({
      _id: req.params.id,
      user: req.user.id,
    });
    if (!task) return res.status(404).json({ error: "Task not found" });
    res.status(200).json({ message: "Task deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete task" });
  }
});

// ======================
// Fallback Routes
// ======================
app.get("/test", (req, res) => {
  res.status(200).json({ status: "OK" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// ======================
// Start Server
// ======================
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
