---

# Secure Login System

A secure login system built with **Node.js**, **Express**, **SQLite**, and other modern libraries. This project implements user registration, email verification, login, password reset, and secure token-based authentication.

---

## 🚀 Features

- **User Registration**: Register with a username, email, password, and phone number.
- **Email Verification**: A verification code is sent to the user's email to complete the registration.
- **Login**: Log in using email or phone number and password.
- **Password Reset**: Request a reset code via email and change your password securely.
- **Secure Authentication**: JWT-based authentication with signed cookies for session management.
- **Password Validation**: Enforces strong password policies.

---

## 🗂 Project Structure

```
.env
app.js
package.json
secure_login.db
api/
  └── auth.js
controllers/
  └── auth.js
lib/
  └── db.js
```

### Key Files

- **`app.js`**: Entry point. Sets up the Express server and routes.
- **`api/auth.js`**: Defines authentication-related API routes.
- **`controllers/auth.js`**: Contains logic for registration, verification, login, password reset, and token decryption.
- **`lib/db.js`**: Handles SQLite connection and schema.
- **`lib/crypto.js`**: Provides AES encryption and decryption utilities.

---

## 🛠 Installation

1. **Clone the repository:**

```bash
git clone <repository-url>
cd Secure-Login-System
```

2. **Install dependencies:**

```bash
npm install
```

3. **Create a `.env` file in the root directory:**

```env
PORT=3000
JWT_SECRET=your_secret_key_here
COOKIE_SECRET=your_cookie_secret_here
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password
```

4. **Start the application:**

```bash
npm start
```

The server will run at: [http://localhost:3000](http://localhost:3000)

---

## 📡 API Endpoints

| Method | Endpoint        | Description                        |
|--------|------------------|------------------------------------|
| POST   | `/api/register`  | Register a new user                |
| POST   | `/api/verify`    | Verify email with a code           |
| POST   | `/api/login`     | Log in a user                      |
| POST   | `/api/forget`    | Request a password reset code      |
| POST   | `/api/reset`     | Reset password with the code       |
| POST   | `/api/update`    | Update user details                |
| POST   | `/api/decrypt`   | Decrypt a secure token             |

---

## 🧩 Database

Uses SQLite with a `users` table. Fields include:

- `id`: Primary key
- `username`: Unique username
- `email`: Unique email address
- `password`: Hashed password
- `number`: Phone number

---

## 📦 Dependencies

- `bcrypt`: Password hashing
- `cookie-parser`: Cookie handling
- `dotenv`: Environment variable management
- `express`: Web framework
- `jsonwebtoken`: JWT token generation and verification
- `nodemailer`: Email sending
- `sqlite3`: Database engine

---

## ⚙️ Development

To run with live reloading during development:

```bash
npm run start
```

---

## 🔒 Security Notes

- Never expose your `.env` file in production.
- Use strong values for `JWT_SECRET` and `COOKIE_SECRET`.
- Use a trusted and secure email provider.
- Ensure HTTPS is used in production for secure communication.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---