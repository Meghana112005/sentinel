-- =====================================================
-- SENTINEL SECURITY SCANNER - DATABASE SETUP
-- =====================================================
-- Complete Database Setup Script
-- Run these commands in order
-- =====================================================

-- Step 1: Drop existing database if you want to start fresh
-- UNCOMMENT THE NEXT LINE ONLY IF YOU WANT TO DELETE ALL EXISTING DATA
-- DROP DATABASE IF EXISTS sentinel_db;

-- Step 2: Create Database
CREATE DATABASE IF NOT EXISTS sentinel_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

-- Step 3: Use the database
USE sentinel_db;

-- Step 4: Drop existing table if you want fresh start
-- UNCOMMENT THE NEXT LINE ONLY IF YOU WANT TO DELETE THE TABLE
-- DROP TABLE IF EXISTS scan_results;

-- Step 5: Create scan_results table
CREATE TABLE IF NOT EXISTS scan_results (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    target_url VARCHAR(2000) NOT NULL,
    vulnerability_type VARCHAR(50) NOT NULL,
    affected_url VARCHAR(2000),
    payload VARCHAR(1000),
    evidence TEXT,
    risk_level VARCHAR(20) NOT NULL,
    scan_date DATETIME NOT NULL,
    scan_id VARCHAR(50) NOT NULL,
    
    INDEX idx_scan_id (scan_id),
    INDEX idx_target_url (target_url(255)),
    INDEX idx_vulnerability_type (vulnerability_type),
    INDEX idx_risk_level (risk_level),
    INDEX idx_scan_date (scan_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Step 6: Verify table creation
SHOW TABLES;
DESCRIBE scan_results;

-- Step 7: Check if table is empty
SELECT COUNT(*) as total_records FROM scan_results;

-- =====================================================
-- REMOVE DUPLICATE VULNERABILITIES
-- Run this after scanning to clean up duplicates
-- =====================================================

-- View duplicates before removing
SELECT 
    scan_id,
    vulnerability_type,
    affected_url,
    COUNT(*) as duplicate_count
FROM scan_results
GROUP BY scan_id, vulnerability_type, affected_url
HAVING COUNT(*) > 1
ORDER BY duplicate_count DESC;

-- Remove duplicates (keeps the first occurrence)
DELETE t1 FROM scan_results t1
INNER JOIN scan_results t2 
WHERE 
    t1.id > t2.id AND
    t1.scan_id = t2.scan_id AND
    t1.vulnerability_type = t2.vulnerability_type AND
    t1.affected_url = t2.affected_url;

-- Verify duplicates removed
SELECT 'Duplicates removed!' as status;
SELECT COUNT(*) as remaining_vulnerabilities FROM scan_results;

-- =====================================================
-- VERIFICATION QUERIES
-- Run these after scanning to check if data is saved
-- =====================================================

-- View all scan results
SELECT * FROM scan_results ORDER BY scan_date DESC LIMIT 10;

-- Count vulnerabilities by type
SELECT vulnerability_type, COUNT(*) as count 
FROM scan_results 
GROUP BY vulnerability_type;

-- Count vulnerabilities by risk level
SELECT risk_level, COUNT(*) as count 
FROM scan_results 
GROUP BY risk_level;

-- View latest scan
SELECT * FROM scan_results 
ORDER BY scan_date DESC 
LIMIT 1;

-- Get all scans with their vulnerability counts
SELECT 
    scan_id,
    target_url,
    COUNT(*) as total_vulnerabilities,
    SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
    SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
    SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk,
    MAX(scan_date) as scan_date
FROM scan_results
GROUP BY scan_id, target_url
ORDER BY scan_date DESC;

-- =====================================================
-- TEST DATA (OPTIONAL - FOR TESTING ONLY)
-- Uncomment to insert test data
-- =====================================================

/*
-- Clear existing data first (OPTIONAL)
-- TRUNCATE TABLE scan_results;

-- Insert test vulnerabilities
INSERT INTO scan_results 
(target_url, vulnerability_type, affected_url, payload, evidence, risk_level, scan_date, scan_id)
VALUES
-- SQL Injection vulnerabilities
('http://localhost/dvwa', 'SQL_INJECTION', 'http://localhost/dvwa/vulnerabilities/sqli/', 
 "1' OR '1'='1", "You have an error in your SQL syntax; check the manual...", 'HIGH', NOW(), 'test-001'),

('http://localhost/dvwa', 'SQL_INJECTION', 'http://localhost/dvwa/vulnerabilities/sqli/?id=1', 
 "1' OR 1=1--", "MySQL error: syntax error near '1' OR 1=1", 'HIGH', NOW(), 'test-001'),

('http://localhost/dvwa', 'SQL_INJECTION', 'http://localhost/dvwa/login.php', 
 "admin'--", "SQL syntax error in login query", 'HIGH', NOW(), 'test-001'),

-- XSS vulnerabilities
('http://localhost/dvwa', 'XSS', 'http://localhost/dvwa/vulnerabilities/xss_r/', 
 '<script>alert(1)</script>', 'XSS payload reflected without encoding', 'MEDIUM', NOW(), 'test-001'),

('http://localhost/dvwa', 'XSS', 'http://localhost/dvwa/vulnerabilities/xss_r/?name=test', 
 '<img src=x onerror=alert(1)>', 'Payload reflected in response', 'MEDIUM', NOW(), 'test-001'),

-- Juice Shop vulnerabilities
('http://localhost:3000', 'SQL_INJECTION', 'http://localhost:3000/rest/products/search?q=test', 
 "' OR 1=1--", "SQLITE_ERROR: near 'OR': syntax error", 'HIGH', NOW(), 'test-002'),

('http://localhost:3000', 'XSS', 'http://localhost:3000/#/search?q=test', 
 '<iframe src=javascript:alert(1)>', 'XSS reflected in search results', 'MEDIUM', NOW(), 'test-002');

-- Verify test data was inserted
SELECT 'Test data inserted successfully!' as message;
SELECT COUNT(*) as test_vulnerabilities FROM scan_results;
*/

-- =====================================================
-- CLEANUP COMMANDS
-- =====================================================

-- Delete old scans (older than 7 days)
-- DELETE FROM scan_results WHERE scan_date < DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Delete specific scan
-- DELETE FROM scan_results WHERE scan_id = 'your-scan-id';

-- Clear all data (DANGEROUS - deletes everything!)
-- TRUNCATE TABLE scan_results;

-- =====================================================
-- DATABASE MAINTENANCE
-- =====================================================

-- Optimize table for better performance
OPTIMIZE TABLE scan_results;

-- Analyze table for query optimization
ANALYZE TABLE scan_results;

-- Check table for errors
CHECK TABLE scan_results;

-- Show table size
SELECT 
    table_name AS 'Table',
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS 'Size (MB)'
FROM information_schema.TABLES
WHERE table_schema = 'sentinel_db'
AND table_name = 'scan_results';

-- =====================================================
-- TROUBLESHOOTING QUERIES
-- =====================================================

-- Check if database exists
SHOW DATABASES LIKE 'sentinel_db';

-- Check if table exists
SHOW TABLES LIKE 'scan_results';

-- Check table structure
SHOW CREATE TABLE scan_results;

-- Check indexes
SHOW INDEX FROM scan_results;

-- Check latest entries
SELECT 
    id,
    vulnerability_type,
    risk_level,
    scan_id,
    scan_date
FROM scan_results
ORDER BY id DESC
LIMIT 5;

-- Test insert (to verify permissions)
-- INSERT INTO scan_results 
-- (target_url, vulnerability_type, affected_url, payload, evidence, risk_level, scan_date, scan_id)
-- VALUES 
-- ('http://test.com', 'TEST', 'http://test.com/test', 'test', 'test evidence', 'LOW', NOW(), 'test-123');

-- Delete test insert
-- DELETE FROM scan_results WHERE scan_id = 'test-123';

-- =====================================================
-- USER PERMISSIONS (OPTIONAL)
-- Create dedicated database user
-- =====================================================

/*
-- Create user (change password!)
CREATE USER IF NOT EXISTS 'sentinel_user'@'localhost' 
IDENTIFIED BY 'SentinelSecure2025!';

-- Grant permissions
GRANT ALL PRIVILEGES ON sentinel_db.* 
TO 'sentinel_user'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify user
SELECT user, host FROM mysql.user WHERE user = 'sentinel_user';

-- Test connection (run in terminal)
-- mysql -u sentinel_user -p sentinel_db
*/

-- =====================================================
-- FINAL VERIFICATION
-- =====================================================

-- Summary of setup
SELECT 
    'Database Setup Complete' as status,
    DATABASE() as current_database,
    (SELECT COUNT(*) FROM scan_results) as total_records,
    (SELECT COUNT(DISTINCT scan_id) FROM scan_results) as total_scans;

-- Show all tables
SHOW TABLES FROM sentinel_db;

-- =====================================================
-- QUICK COMMANDS FOR COPY-PASTE
-- =====================================================

/*
-- To run this entire script:
mysql -u root -p < database.sql

-- Or login and run:
mysql -u root -p
source /path/to/database.sql;

-- Check data after scan:
mysql -u root -p -e "USE sentinel_db; SELECT * FROM scan_results ORDER BY scan_date DESC LIMIT 10;"

-- Count vulnerabilities:
mysql -u root -p -e "USE sentinel_db; SELECT vulnerability_type, COUNT(*) FROM scan_results GROUP BY vulnerability_type;"

-- Delete all data:
mysql -u root -p -e "USE sentinel_db; TRUNCATE TABLE scan_results;"
*/

-- =====================================================
-- END OF SCRIPT
-- =====================================================

SELECT '=' as '', 'DATABASE SETUP COMPLETED SUCCESSFULLY' as '', '=' as '';
SELECT 'Next step: Update application.properties with your MySQL password' as instruction;