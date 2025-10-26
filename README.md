# Secure FinTech App – Authentication & Cybersecurity

This project is a secure FinTech-style authentication system built with **Streamlit** and backed by **MongoDB Atlas**, demonstrating practical implementation of cybersecurity techniques used in modern financial applications.

---

## 🔧 Tech Stack

* **Frontend / App Framework:** Streamlit
* **Backend / Security:** Python (bcrypt, Fernet encryption)
* **Database:** MongoDB Atlas (Cloud)
* **Deployment:** Streamlit Cloud

---

## ✅ Key Security Features

| Feature                | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| Password Hashing       | bcrypt hashing with salt for credential protection         |
| Strong Password Policy | Requires upper, lower, digit and special character         |
| Input Sanitization     | Blocks SQL-style payloads like `' OR 1=1--` and `<script>` |
| Session Timeout        | Auto logout after inactivity (10 minutes)                  |
| Account Lockout        | 5 failed attempts triggers temporary lock                  |
| File Upload Validation | Only allows CSV, TXT and PDF                               |
| Encrypted Data Storage | Sensitive values handled using Fernet encryption           |
| Audit Logging          | All actions logged (login, logout, update etc.)            |

---

## 📂 Project Structure

```
.
├── app.py               # Main Streamlit application
├── requirements.txt     # Python dependencies
├── secret.key           # Encryption key (auto-generated)
└── README.md            # Documentation
```

---

## 🔗 Live Demo & Repository

**Streamlit App:** <DEPLOYMENT LINK HERE>

**GitHub Repository:** <REPO LINK HERE>

---

## 🛡 Manual Cybersecurity Test Cases (Summary)

| No. | Test Performed                     | Result            |
| --- | ---------------------------------- | ----------------- |
| 1   | SQL Injection attempt (`OR 1=1--`) | Blocked ✔️        |
| 2   | Weak password test                 | Enforced ✔️       |
| 3   | Special character/script injection | Prevented ✔️      |
| 4   | Dashboard access without login     | Blocked ✔️        |
| 5   | Inactive session timeout           | Forced logout ✔️  |
| 6   | 5 failed login attempts            | Account locked ✔️ |

(All 20/20 test cases passed successfully)

---

## 🚀 Deployment Notes

1. Create a MongoDB Atlas cluster and user
2. Add Streamlit Cloud IP to network access
3. Set `MONGODB_PASSWORD` in **Streamlit Secrets**
4. Deploy repository to Streamlit Cloud

---

## 🧠 Learning Outcomes

* Practical implementation of secure authentication
* Cloud database security configuration
* Manual security testing aligned with OWASP
* Handling encryption and hashing in production-grade logic

---

## 👨‍🏫 Acknowledgment

Special thanks to **Dr. Usama Arshad** for providing guidance and direction throughout this project.

---

## 📌 Future Enhancements

* Two-Factor Authentication (2FA)
* Role-based access controls (RBAC)
* Transaction module with encryption at field-level



This project is for educational and academic purposes.
