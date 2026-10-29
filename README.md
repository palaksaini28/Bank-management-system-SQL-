# Banking Management System — MySQL Version

This version uses **Flask + MySQL** instead of SQLite.

## 1. Install requirements
```powershell
pip install -r requirements.txt
```

## 2. Create the MySQL database
Open MySQL Workbench and run:
```sql
CREATE DATABASE banking_system;
```

The Flask application automatically creates the four tables and demo users when it starts.

## 3. Configure MySQL password
The default configuration is:
- Host: `localhost`
- Port: `3306`
- User: `root`
- Password: `root`
- Database: `banking_system`

If your MySQL root password is different, set it in PowerShell before running:
```powershell
$env:DB_PASSWORD="YOUR_MYSQL_PASSWORD"
```
Optional variables: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_NAME`.

## 4. Run
```powershell
python app.py
```
Then open `http://localhost:5000`.

## Demo accounts
- `alice` / `password123`
- `bob` / `password123`
- `carol` / `password123`

## MySQL tables
- `users` — customer accounts and balances
- `transactions` — money transfers and transaction history
- `sessions` — login sessions
- `audit_log` — security and activity logs
