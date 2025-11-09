-- Cyber Incident Tracking Database Schema
-- This file creates the necessary tables for the cyber incident tracking system

CREATE DATABASE IF NOT EXISTS project;
USE project;

-- Raw feeds table to store original data from sources
CREATE TABLE IF NOT EXISTS raw_feeds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source VARCHAR(255) NOT NULL,
    data TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source (source),
    INDEX idx_timestamp (timestamp)
);

-- Incidents table to store processed cyber incidents
CREATE TABLE IF NOT EXISTS incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(255) NOT NULL DEFAULT 'Unknown',
    sector VARCHAR(255) NOT NULL DEFAULT 'Unknown',
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    details TEXT NOT NULL,
    category VARCHAR(255) NOT NULL DEFAULT 'Uncategorized',
    analysis TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_severity (severity),
    INDEX idx_sector (sector),
    INDEX idx_category (category),
    INDEX idx_timestamp (timestamp),
    INDEX idx_type (type)
);

-- Alert table to store generated alerts
CREATE TABLE IF NOT EXISTS alert (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id INT NOT NULL,
    alert_type VARCHAR(100) NOT NULL DEFAULT 'Email',
    recipient VARCHAR(255) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pending', 'sent', 'failed') DEFAULT 'pending',
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    INDEX idx_incident_id (incident_id),
    INDEX idx_status (status),
    INDEX idx_timestamp (timestamp)
);

-- Data sources configuration table
CREATE TABLE IF NOT EXISTS data_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    url VARCHAR(500) NOT NULL,
    source_type ENUM('RSS', 'JSON', 'TEXT', 'ZIP') NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    last_fetched DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default data sources
INSERT IGNORE INTO data_sources (name, url, source_type) VALUES
('abuse_ch_malware', 'https://urlhaus.abuse.ch/downloads/json/', 'ZIP'),
('cyber_blog', 'https://krebsonsecurity.com/feed/', 'RSS'),
('cert_in', 'https://www.cert-in.org.in/RSSThreats.xml', 'RSS'),
('spamhaus_drop', 'https://www.spamhaus.org/drop/drop.txt', 'TEXT');

-- System settings table
CREATE TABLE IF NOT EXISTS system_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(255) NOT NULL UNIQUE,
    setting_value TEXT,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default settings
INSERT IGNORE INTO system_settings (setting_key, setting_value, description) VALUES
('auto_refresh_interval', '300', 'Auto refresh interval in seconds'),
('alert_email_enabled', 'true', 'Enable email alerts'),
('alert_sms_enabled', 'false', 'Enable SMS alerts'),
('max_incidents_per_page', '50', 'Maximum incidents to display per page'),
('data_retention_days', '90', 'Number of days to retain incident data');

-- Create views for easier querying
CREATE OR REPLACE VIEW incident_summary AS
SELECT 
    i.id,
    i.type,
    i.sector,
    i.severity,
    i.category,
    i.timestamp,
    COUNT(a.id) as alert_count
FROM incidents i
LEFT JOIN alert a ON i.id = a.incident_id
GROUP BY i.id, i.type, i.sector, i.severity, i.category, i.timestamp;

-- Create view for recent activity
CREATE OR REPLACE VIEW recent_activity AS
SELECT 
    'incident' as activity_type,
    id,
    type as title,
    severity,
    timestamp
FROM incidents
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
UNION ALL
SELECT 
    'alert' as activity_type,
    id,
    CONCAT('Alert for incident #', incident_id) as title,
    'high' as severity,
    timestamp
FROM alert
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;

-- Create indexes for better performance
CREATE INDEX idx_incidents_severity_sector ON incidents(severity, sector);
CREATE INDEX idx_incidents_category_timestamp ON incidents(category, timestamp);
CREATE INDEX idx_alerts_incident_status ON alert(incident_id, status);

-- Grant permissions (adjust as needed for your setup)
-- GRANT ALL PRIVILEGES ON project.* TO 'root'@'localhost';
-- FLUSH PRIVILEGES;

