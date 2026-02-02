// server.js
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// ✅ NEW
const path = require("path");
const multer = require("multer");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ NEW: serve uploaded images
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ------------------------
// MySQL Connection
// ------------------------
const db = mysql.createConnection({
  host: "samztitha",
  user: "nodeuser",
  password: "samzi0206",
  database: "bookdb",
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL Connected!");
});

// ------------------------
// JWT Secret
// ------------------------
const JWT_SECRET = "bookmanager_secret_key";

// ------------------------
// Multer Config (Image Upload)
// ------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/books"),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 3 * 1024 * 1024 }, // 3MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed"), false);
    }
    cb(null, true);
  },
});

// ------------------------
// Middleware
// ------------------------
function verifyToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "Token missing" });

  const token = header.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== "ADMIN") return res.status(403).json({ error: "Admin only" });
  next();
}

function isAdminOrAuthor(req, res, next) {
  if (req.user.role === "ADMIN") return next();
  if (req.user.role === "AUTHOR" && req.user.status === "ACTIVE") return next();
  return res.status(403).json({ error: "Not allowed" });
}

// ------------------------
// Auth Routes
// ------------------------

// Login route (all users)
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email & password required" });

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: "User not found" });

    const user = results[0];

    // Authors must be ACTIVE to login
    if (user.role === "AUTHOR" && user.status !== "ACTIVE")
      return res.status(403).json({ error: "Author registration pending approval" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: user.id, role: user.role, status: user.status },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login successful",
      token,
      role: user.role,
      status: user.status,
      name: user.name,
      id: user.id,
    });
  });
});

// ------------------------
// User Registration
// ------------------------
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, 'USER', 'ACTIVE')",
      [name, email, hashed],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "Email already exists" });
          return res.status(500).json({ error: err.message });
        }
        res.json({ message: "User registered successfully! You can now log in." });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------
// Author Registration
// ------------------------
app.post("/register-author", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.query(
      "INSERT INTO users (name, email, password, role, status) VALUES (?, ?, ?, 'AUTHOR', 'PENDING')",
      [name, email, hashed],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ error: "Email already exists" });
          return res.status(500).json({ error: err.message });
        }
        res.json({ message: "Author registered! Waiting for admin approval." });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------
// Admin Approve/Reject Authors
// ------------------------
app.put("/admin/approve-author/:id", verifyToken, isAdmin, (req, res) => {
  const { status } = req.body; // must be 'ACTIVE' or 'REJECTED'
  if (!["ACTIVE", "REJECTED"].includes(status)) return res.status(400).json({ error: "Invalid status" });

  db.query(
    "UPDATE users SET status=? WHERE id=? AND role='AUTHOR'",
    [status, req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (result.affectedRows === 0) return res.status(404).json({ error: "Author not found" });
      res.json({ message: `Author ${status === "ACTIVE" ? "approved" : "rejected"} successfully` });
    }
  );
});

app.get("/admin/pending-authors", verifyToken, isAdmin, (req, res) => {
  db.query(
    "SELECT id, name, email, status FROM users WHERE role='AUTHOR' AND status='PENDING'",
    (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(results);
    }
  );
});

// ✅ Author's own books (and admin can also use it if needed)
app.get("/my-books", verifyToken, (req, res) => {
  // Only AUTHOR (ACTIVE) or ADMIN can access
  if (req.user.role === "AUTHOR" && req.user.status !== "ACTIVE") {
    return res.status(403).json({ error: "Author not allowed" });
  }
  if (req.user.role !== "AUTHOR" && req.user.role !== "ADMIN") {
    return res.status(403).json({ error: "Not allowed" });
  }

  // AUTHOR -> only their books
  if (req.user.role === "AUTHOR") {
    db.query(
      "SELECT * FROM books WHERE created_by = ? ORDER BY id DESC",
      [req.user.id],
      (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
      }
    );
    return;
  }

  // ADMIN -> optionally see all books
  db.query("SELECT * FROM books ORDER BY id DESC", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});


// ------------------------
// Book Routes
// ------------------------

// GET all books (users can see image_url)
app.get("/books", (req, res) => {
  db.query("SELECT * FROM books", (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// ✅ POST book + image (Admin/Active Author)
app.post("/books", verifyToken, isAdminOrAuthor, upload.single("image"), (req, res) => {
  const { title, author, publication_year, genre } = req.body;

  if (!title || !author || !publication_year || !genre) {
    return res.status(400).json({ error: "All fields required" });
  }

  const createdBy = req.user.id;
  const imageUrl = req.file ? `/uploads/books/${req.file.filename}` : null;

  db.query(
    "INSERT INTO books (title, author, genre, publication_year, image_url, created_by) VALUES (?, ?, ?, ?, ?, ?)",
    [title, author, genre, publication_year, imageUrl, createdBy],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Book added", bookId: result.insertId, image_url: imageUrl });
    }
  );
});

// ✅ PUT book update + optional new image
app.put("/books/:id", verifyToken, isAdminOrAuthor, upload.single("image"), (req, res) => {
  const { title, author, publication_year, genre } = req.body;

  if (!title || !author || !publication_year || !genre) {
    return res.status(400).json({ error: "All fields required" });
  }

  db.query("SELECT created_by FROM books WHERE id = ?", [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: "Book not found" });

    if (req.user.role === "AUTHOR" && results[0].created_by !== req.user.id) {
      return res.status(403).json({ error: "You can only edit your own books" });
    }

    const newImageUrl = req.file ? `/uploads/books/${req.file.filename}` : null;

    let sql = "UPDATE books SET title=?, author=?, genre=?, publication_year=?";
    const params = [title, author, genre, publication_year];

    if (newImageUrl) {
      sql += ", image_url=?";
      params.push(newImageUrl);
    }

    sql += " WHERE id=?";
    params.push(req.params.id);

    db.query(sql, params, (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ message: "Book updated", image_url: newImageUrl || undefined });
    });
  });
});

app.delete("/books/:id", verifyToken, isAdminOrAuthor, (req, res) => {
  db.query("SELECT created_by FROM books WHERE id = ?", [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: "Book not found" });

    if (req.user.role === "AUTHOR" && results[0].created_by !== req.user.id)
      return res.status(403).json({ error: "You can only delete your own books" });

    db.query("DELETE FROM books WHERE id=?", [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ message: "Book deleted" });
    });
  });
});

// ------------------------
// Error handler for multer (nice message)
// ------------------------
app.use((err, req, res, next) => {
  if (err) return res.status(400).json({ error: err.message });
  next();
});

// ------------------------
// Start server
// ------------------------
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
