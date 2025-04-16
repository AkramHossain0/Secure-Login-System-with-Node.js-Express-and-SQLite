import sqlite3 from 'sqlite3';

const db = new sqlite3.Database('./secure_login.db', (err) => {
    if (err) {
        console.error('Error connecting to the database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    number TEXT NOT NULL
);
`, (err) => {
    if (err) {
        console.error('Error creating users table:', err.message);
    }
});

export default db;