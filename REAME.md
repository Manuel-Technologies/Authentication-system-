# 🔐 Mini Auth Backend

Simple authentication API with OTP email verification.

## 🚀 Quick Start

```bash
npm install
npm start
```

## 📧 Environment Setup

Create `.env` file:
```
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
JWT_SECRET=your-secret-key
PORT=3000
```

## 🔗 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/signup` | Send OTP to email |
| POST | `/api/verify-otp` | Verify OTP & create account |
| POST | `/api/login` | User login |
| POST | `/api/resend-otp` | Resend OTP |
| GET | `/api/profile` | Get user profile (protected) |

## 📱 Example Usage

**Signup:**
```json
POST /api/signup
{
  "email": "user@example.com",
  "password": "password123",
  "name": "John Doe"
}
```

**Verify OTP:**
```json
POST /api/verify-otp
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Login:**
```json
POST /api/login
{
  "email": "user@example.com",
  "password": "password123"
}
```

## ⚡ Features

- OTP email verification
- JWT authentication
- Password hashing
- Rate limiting
- Input validation

Built for mobile apps! 📱