# Banking Management System – SQL Database Documentation

## 1. Database Name
`banking_system`

## 2. Database Technology
- MySQL 8.0+
- Storage engine: InnoDB
- Character set: UTF-8 (`utf8mb4`)
- Application: Python + Flask
- Connector: `mysql-connector-python`

## 3. Tables

### `users`
Stores customer login details and bank account information.

| Column | Type | Key | Description |
|---|---|---|---|
| id | INT | PK | Unique customer ID |
| username | VARCHAR(100) | UNIQUE | Login username |
| password_hash | VARCHAR(255) | | Secure password hash |
| salt | VARCHAR(255) | | Password salt |
| full_name | VARCHAR(150) | | Customer name |
| email | VARCHAR(255) | UNIQUE | Customer email |
| phone | VARCHAR(20) | | Contact number |
| account_number | VARCHAR(50) | UNIQUE | Bank account number |
| account_type | ENUM | | Savings or Current |
| balance | DECIMAL(15,2) | | Current account balance |
| created_at | TIMESTAMP | | Account creation time |
| failed_attempts | INT | | Failed login count |
| locked_until | DATETIME | | Temporary account lock |
| last_login | DATETIME | | Last successful login |

### `transactions`
Stores money transfers and transaction history.

| Column | Type | Key | Description |
|---|---|---|---|
| id | INT | PK | Transaction ID |
| from_account | VARCHAR(50) | INDEX | Sender account |
| to_account | VARCHAR(50) | INDEX | Receiver account |
| amount | DECIMAL(15,2) | | Transfer amount |
| type | VARCHAR(50) | | Transaction type |
| description | VARCHAR(255) | | Transaction description |
| status | VARCHAR(30) | | completed/failed/etc. |
| timestamp | TIMESTAMP | | Transaction time |
| reference | VARCHAR(50) | UNIQUE | Transaction reference |

### `sessions`
Stores active login sessions.

### `audit_log`
Stores security and application activity such as successful and failed logins and money transfers.

## 4. Relationships
- One `users` record can have many `sessions` records.
- One `users` record can have many `audit_log` records.
- Transactions use sender/receiver account numbers to identify the two accounts involved.

## 5. ER Diagram
See `database_er_diagram.png`.

## 6. Useful SQL Queries

```sql
USE banking_system;
SHOW TABLES;
```

```sql
SELECT id, username, full_name, email, phone,
       account_number, account_type, balance
FROM users;
```

```sql
SELECT id, from_account, to_account, amount,
       type, description, status, timestamp, reference
FROM transactions
ORDER BY timestamp DESC;
```

```sql
SELECT *
FROM audit_log
ORDER BY timestamp DESC;
```

```sql
SELECT account_type,
       COUNT(*) AS total_accounts,
       SUM(balance) AS total_balance
FROM users
GROUP BY account_type;
```

```sql
SELECT type,
       COUNT(*) AS total_transactions,
       SUM(amount) AS total_amount
FROM transactions
GROUP BY type;
```

## 7. Report Screenshot Recommendation

For the database section of the report, open MySQL Workbench and show:

1. `banking_system` under **SCHEMAS**.
2. The **Tables** section expanded.
3. `users`, `transactions`, `sessions`, and `audit_log` visible.
4. Run `SELECT * FROM users;` and show the result grid.
5. Run `SELECT * FROM transactions;` after making a transfer in the application.
6. Run `SELECT * FROM audit_log;` to demonstrate security/activity logging.

This gives a database view similar to the SQL Database page in the reference report.
