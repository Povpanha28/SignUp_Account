# MySQL User Manager - Setup Guide

## 🚀 Quick Start

### 1. Database Setup
First, make sure you have MySQL installed and running on your system.

### 2. Create Environment File
Create a `.env` file in the `backend` folder with your MySQL credentials:

```env
# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password_here
PORT=4000
```

**Replace `your_mysql_password_here` with your actual MySQL root password.**

### 3. Start the Backend Server
Open a terminal in the `backend` folder and run:

```bash
cd backend
npm install
npm start
```

You should see: `Server running on port 4000`

### 4. Start the Frontend
Open another terminal in the `frontend/client` folder and run:

```bash
cd frontend/client
npm install
npm start
```

The React app will open at `http://localhost:3000`

## 🔧 What Each Component Does

### Create User Form
- Creates new MySQL users with different roles
- Automatically assigns appropriate privileges based on role
- Roles: Developer, Analyst, Backup, Database Admin

### User List
- Shows all existing MySQL users (excluding system users)
- Displays user privileges and roles
- Allows deletion of users

### Grant Privilege Form
- Grants additional privileges to existing users
- Works on specific databases

## 🛠️ Troubleshooting

### Common Issues:

1. **"Failed to fetch users" error**
   - Make sure MySQL is running
   - Check your `.env` file credentials
   - Ensure the backend server is running on port 4000

2. **"Access denied" errors**
   - Your MySQL user needs privileges to create/drop users
   - Try running as root or a user with `CREATE USER` privileges

3. **CORS errors**
   - The backend already has CORS configured
   - Make sure both frontend and backend are running

### Testing Database Connection:
You can test if your database connection works by visiting:
`http://localhost:4000/users` in your browser

## 📝 Database Operations

The application performs these MySQL operations:

- `CREATE USER` - Creates new users
- `GRANT` - Assigns privileges
- `DROP USER` - Deletes users
- `SHOW GRANTS` - Lists user privileges
- `FLUSH PRIVILEGES` - Applies privilege changes

## 🔒 Security Notes

- This application requires MySQL root access or equivalent privileges
- Use only in development/testing environments
- Consider implementing proper authentication for production use 