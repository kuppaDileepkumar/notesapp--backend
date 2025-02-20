require("dotenv").config();  // Load environment variables from .env file
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const app = express();
const cors = require("cors");

// Middleware to parse JSON body data
app.use(express.json());  // Parse JSON requests
app.use(express.urlencoded({ extended: true })); // Parse form data
app.use(cors());

// Initialize SQLite database
const db = new sqlite3.Database("notesapp.db", (err) => {
  if (err) {
    console.error("❌ Database Connection Error:", err.message);
  } else {
    console.log("✅ Connected to SQLite Database");
  }
});

// JWT Secret Key (from .env file)
const SECRET_KEY = process.env.JWT_SECRET || "your_jwt_secret_key";

// **User Authentication Routes**

// 1. **POST /signup** – Register a user
app.post("/api/auth/Signup", async (req, res) => {
  const { name, email, password } = req.body;

  // 1️⃣ Check if all fields are provided
  if (!name || !email || !password) {
      console.error("❌ Missing Fields in Signup Request");
      return res.status(400).json({ message: "Name, email, and password are required." });
  }

  console.log("🔍 Checking if email exists:", email);

  // 2️⃣ Check if email already exists
  const checkEmailSQL = "SELECT email FROM users WHERE email = ?";
  db.get(checkEmailSQL, [email], async (err, existingUser) => {
      if (err) {
          console.error("❌ Database Error:", err.message);
          return res.status(500).json({ error: err.message });
      }

      if (existingUser) {
          console.warn("⚠️ Email already exists:", email);
          return res.status(400).json({ message: "Email already exists. Please use a different email." });
      }

      try {
          // 3️⃣ Hash the password before storing
          const hashedPassword = await bcrypt.hash(password, 10);
          console.log("✅ Hashed Password:", hashedPassword);

          // 4️⃣ Insert new user into the database
          const insertSQL = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
          db.run(insertSQL, [name, email, hashedPassword], function (err) {
              if (err) {
                  console.error("❌ Signup Database Error:", err.message);
                  return res.status(500).json({ error: err.message });
              }

              console.log("✅ User registered successfully:", { userId: this.lastID });
              res.status(201).json({ message: "User registered successfully", userId: this.lastID });
          });

      } catch (error) {
          console.error("❌ Error Hashing Password:", error.message);
          res.status(500).json({ error: "Error hashing password" });
      }
  });
});

// 2. **POST /login** – Authenticate user and return JWT token
app.post("/api/auth/Login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required." });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  db.get(sql, [email], async (err, user) => {
      if (err) {
          console.error("❌ Database Error:", err.message);
          return res.status(500).json({ error: err.message });
      }

      if (!user) {
          return res.status(401).json({ message: "User not found. Please sign up first." });
      }

      console.log("🔍 Checking password for user:", user.email);

      // Compare the hashed password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
          return res.status(401).json({ message: "Invalid password. Please try again." });
      }

      // Generate JWT Token
      const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: "1h" });
      console.log("✅ Login Successful. Token generated:", token);

      res.json({ message: "Login successful", userId: user.id, token });
  });
});


// **Middleware to authenticate JWT token**

const authenticate = (req, res, next) => {
  console.log("🛠 JWT Secret:", process.env.JWT_SECRET); // Debugging line

  if (!process.env.JWT_SECRET) {
    console.error("❌ JWT_SECRET is missing!");
    return res.status(500).json({ error: "Server configuration error: JWT_SECRET missing" });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.warn("⚠️ No token provided");
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("❌ JWT Verification Error:", err.message);
      return res.status(403).json({ error: "Forbidden: Invalid token" });
    }
    req.user = user;
    console.log("🔑 Authenticated User from Token:", req.user);
    next();
  });
};

module.exports = authenticate;


// **Note Management Routes**

// 3. **GET /notes** – Fetch all notes for a user
app.get("/api/notes", authenticate, (req, res) => {
  const userId = req.user.userId;
  db.all("SELECT * FROM notes WHERE user_id = ?", [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});


// 4. **POST /notes** – Create a new note
app.post("/api/notes", authenticate, (req, res) => {
  const { title, content, category } = req.body;
  const userId = req.user.userId;

  db.run(
    "INSERT INTO notes (title, content, category, user_id, pinned, archived, created_at, updated_at) VALUES (?, ?, ?, ?, 0, 0, DATETIME('now'), DATETIME('now'))",
    [title, content, category, userId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, title, content, category });
    }
  );
});


// 5. **PUT /notes/:id** – Update a note
app.put("/api/notes/:id", authenticate, (req, res) => {
  const { title, content, category } = req.body;
  const noteId = req.params.id;

  const query = `UPDATE notes SET title = ?, content = ?, category = ?, updated_at = datetime('now') WHERE id = ?`;

  db.run(query, [title, content, category, noteId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: "Note not found" });

    res.json({ message: "Note updated successfully" });
  });
});



// 6. **DELETE /notes/:id** – Delete a note
app.patch("/api/notes/:id/pin", authenticate, (req, res) => {
  const noteId = req.params.id;
  const userId = req.user.userId;

  db.run(
    "UPDATE notes SET pinned = CASE WHEN pinned = 0 THEN 1 ELSE 0 END WHERE id = ? AND user_id = ?",
    [noteId, userId],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to update pin status" });
      if (this.changes === 0) return res.status(404).json({ error: "Note not found or unauthorized" });
      res.json({ message: "Pin status updated successfully" });
    }
  );
});

// 7. **PATCH /notes/:id/pin** – Pin/unpin a note
app.patch("/api/notes/:id/pin", authenticate, (req, res) => {
  const noteId = req.params.id;
  const userId = req.user.id; // Ensure the user is authenticated

  console.log("📌 Updating pin status for Note ID:", noteId);
  console.log("🔑 Authenticated User ID:", userId);

  // Toggle pin status (switch between 0 and 1)
  db.run(
    "UPDATE notes SET pinned = CASE WHEN pinned = 0 THEN 1 ELSE 0 END WHERE id = ? AND user_id = ?",
    [noteId, userId],
    function (err) {
      if (err) {
        console.error("❌ Database Error:", err.message);
        return res.status(500).json({ error: "Failed to update pin status" });
      }
      if (this.changes === 0) {
        console.warn("⚠️ Note not found or not authorized.");
        return res.status(404).json({ message: "Note not found or you're not authorized" });
      }
      console.log("✅ Pin status updated successfully");
      res.json({ message: "Pin status updated successfully" });
    }
  );
});


// 8. **PATCH /notes/:id/archive** – Archive/unarchive a note
app.patch("/api/notes/:id/archive", authenticate, (req, res) => {
  const noteId = req.params.id;
  const userId = req.user.userId;

  db.run(
    "UPDATE notes SET archived = CASE WHEN archived = 0 THEN 1 ELSE 0 END WHERE id = ? AND user_id = ?",
    [noteId, userId],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to update archive status" });
      if (this.changes === 0) return res.status(404).json({ error: "Note not found or unauthorized" });
      res.json({ message: "Archive status updated successfully" });
    }
  );
});


app.delete("/api/notes/:id", authenticate, (req, res) => {
  const noteId = req.params.id;
  
  db.run("DELETE FROM notes WHERE id = ?", [noteId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: "Note not found" });

    res.json({ message: "Note deleted successfully" });
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
