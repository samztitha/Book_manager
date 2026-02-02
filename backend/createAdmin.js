// createAdmin.js
const mysql = require("mysql2");
const bcrypt = require("bcrypt");

// MySQL connection (same as your main app)
const db = mysql.createConnection({
  host: "samztitha",
  user: "nodeuser",
  password: "samzi0206",
  database: "bookdb"
});

// Admin credentials
const adminEmail = "admin@test.com";
const adminPassword = "admin123"; // plain text password

async function createAdmin() {
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    // Insert or update admin user
    const query = `
      INSERT INTO users (name, email, password, role, status)
      VALUES (?, ?, ?, 'ADMIN', 'ACTIVE')
      ON DUPLICATE KEY UPDATE
        password = VALUES(password),
        name = VALUES(name),
        status = 'ACTIVE'
    `;

    db.query(query, ["Super Admin", adminEmail, hashedPassword], (err, result) => {
      if (err) {
        console.error("Error creating/updating admin:", err);
      } else {
        console.log("Admin created/updated successfully!");
        console.log(result);
      }
      db.end();
    });
  } catch (err) {
    console.error("Error hashing password:", err);
    db.end();
  }
}

// Run the function
createAdmin();
