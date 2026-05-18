-- 1. Create Master CVE Table
CREATE TABLE cve_records (
    cve_id VARCHAR(50) PRIMARY KEY,
    published_date TIMESTAMP,
    last_modified TIMESTAMP,
    description TEXT,
    cvss_v3_score DOUBLE PRECISION,
    cvss_v3_severity VARCHAR(20),
    vector_string TEXT,
    affected_software TEXT,
    source_url TEXT,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    spike_flag INT DEFAULT 0
);

-- 2. Create News Articles Table
CREATE TABLE news_articles (
    article_id SERIAL PRIMARY KEY,
    title TEXT,
    source_name VARCHAR(100),
    source_type VARCHAR(20),
    url TEXT UNIQUE,
    published_at TIMESTAMP,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    content_snippet TEXT,
    matched_cve VARCHAR(50),
    matched_keyword VARCHAR(100),
    sentiment_score DOUBLE PRECISION
);

-- 3. Create Alert Spikes Table
CREATE TABLE alert_spikes (
    spike_id SERIAL PRIMARY KEY,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    spike_type VARCHAR(50),
    target_identifier VARCHAR(100),
    article_count_window INT,
    z_score DOUBLE PRECISION,
    severity_level VARCHAR(20),
    triggered_by_cvss DOUBLE PRECISION,
    alert_message TEXT,
    resolved INT DEFAULT 0
);

-- 4. Create Monitored Keywords Table
CREATE TABLE monitored_keywords (
    keyword_id SERIAL PRIMARY KEY,
    keyword VARCHAR(100) UNIQUE,
    category VARCHAR(50),
    alert_threshold INT DEFAULT 5,
    active INT DEFAULT 1,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Create Pipeline Execution Log Table
CREATE TABLE pipeline_log (
    log_id SERIAL PRIMARY KEY,
    run_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(50),
    records_fetched INT,
    records_inserted INT,
    records_skipped INT,
    duration_seconds DOUBLE PRECISION,
    status VARCHAR(20),
    error_message TEXT
);