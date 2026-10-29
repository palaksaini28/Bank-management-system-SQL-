-- ============================================================
-- Banking Management System - MySQL Database
-- ============================================================
-- Run this file in MySQL Workbench.
-- The Flask application also creates these tables automatically,
-- but this script gives a clean, report-friendly database design.

CREATE DATABASE IF NOT EXISTS banking_system
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE banking_system;

-- ------------------------------------------------------------
-- 1. USERS / CUSTOMER ACCOUNTS
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20) DEFAULT NULL,
    account_number VARCHAR(50) NOT NULL,
    account_type ENUM('Savings','Current') NOT NULL DEFAULT 'Savings',
    balance DECIMAL(15,2) NOT NULL DEFAULT 10000.00,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME DEFAULT NULL,
    last_login DATETIME DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email),
    UNIQUE KEY uq_users_account_number (account_number),
    KEY idx_users_account_type (account_type)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 2. TRANSACTIONS
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transactions (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_account VARCHAR(50) DEFAULT NULL,
    to_account VARCHAR(50) DEFAULT NULL,
    amount DECIMAL(15,2) NOT NULL,
    type VARCHAR(50) NOT NULL,
    description VARCHAR(255) DEFAULT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'completed',
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reference VARCHAR(50) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_transactions_reference (reference),
    KEY idx_tx_from (from_account),
    KEY idx_tx_to (to_account),
    KEY idx_tx_timestamp (timestamp),
    CONSTRAINT chk_transaction_amount CHECK (amount > 0)
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 3. LOGIN SESSIONS
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    token VARCHAR(128) NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address VARCHAR(45) DEFAULT NULL,
    PRIMARY KEY (token),
    KEY idx_sessions_user (user_id),
    KEY idx_sessions_expiry (expires_at),
    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 4. AUDIT LOG
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT UNSIGNED DEFAULT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45) DEFAULT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success TINYINT(1) NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    KEY idx_audit_user (user_id),
    KEY idx_audit_timestamp (timestamp),
    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- REPORT / DEMONSTRATION QUERIES
-- ------------------------------------------------------------
-- Show all tables:
-- SHOW TABLES;

-- View customer/account records:
-- SELECT id, username, full_name, email, phone, account_number,
--        account_type, balance, created_at FROM users;

-- View transaction history:
-- SELECT id, from_account, to_account, amount, type,
--        description, status, timestamp, reference
-- FROM transactions ORDER BY timestamp DESC;

-- View login/security audit records:
-- SELECT * FROM audit_log ORDER BY timestamp DESC;

-- View active sessions:
-- SELECT * FROM sessions ORDER BY created_at DESC;

-- Example balance summary:
-- SELECT account_type, COUNT(*) AS total_accounts,
--        SUM(balance) AS total_balance
-- FROM users GROUP BY account_type;

-- Example transaction summary:
-- SELECT type, COUNT(*) AS total_transactions,
--        SUM(amount) AS total_amount
-- FROM transactions GROUP BY type;
