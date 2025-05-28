

# Expense Manager

A modern **Expense Management Application** built with Flask, Tailwind CSS, and MySQL.  
Track your expenses with categories, descriptions, and dates, manage users, and view analytics — all in a responsive, clean UI.

---

## Features

- User registration and login with role-based access (admin/user)
- Add, edit, delete expenses with categories and descriptions
- Expense history displayed in sortable, paginated tables
- Upload profile pictures
- Admin dashboard for user management
- Feedback form for users to submit messages
- Responsive design with Tailwind CSS
- Password visibility toggle

---

## Database Schema & Sample Data

### 1. `user` Table

```sql
CREATE TABLE user (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  phone VARCHAR(15),
  location VARCHAR(50),
  gender VARCHAR(10),
  password VARCHAR(255) NOT NULL,
  role ENUM('user', 'admin') DEFAULT 'user',
  monthly_budget DECIMAL(10,2) DEFAULT 0,
  profile_pic VARCHAR(255)
);


### 2. `expense` Table

```sql
CREATE TABLE expense (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  category VARCHAR(50),
  description TEXT,
  date DATE NOT NULL,
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

### 3. `feedback` Table

```sql
CREATE TABLE feedback (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  subject VARCHAR(100),
  message TEXT,
  date_submitted DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

Install Python dependencies:
pip install -r requirements.txt


Run the Flask app:
python app.py

Visit in your browser:
http://localhost:5000
